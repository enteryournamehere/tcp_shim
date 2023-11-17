/*!
	A program to transparently translate RakNet 3.25 traffic to TCP and UDP.

	RakNet's protocol is designed to support sending packets with one of multiple reliability modes. To achieve this, the RakNet protocol is layered on top of UDP, and implements the necessary protocol structures and behaviors for ensuring the various reliability modes.

	RakNet offers the modes `Unreliable`, `UnreliableSequenced`, `Reliable`, `ReliableOrdered`, and `ReliableSequenced`. However, in practice (at least for LU specifically), only `UnreliableSequenced` and `ReliableOrdered` are widely used. Unfortunately, the structures and behaviors necessary for the other modes, the complexity required for implementing reliability comparable with TCP on top of UDP, as well as various bugs/artifacts in RakNet's implementation, make the protocol much more complex than necessary.

	RakNet's protocol also rolls its own custom combination of cryptography techniques for encryption. RakNet 3.25 is so niche that it's very unlikely that the protocol has been properly audited for cryptographic correctness, and along with the fact that the protocol is now over 10 years old (version 3.25 is from 2008), it can't be reliably said to be secure.

	Further issues arise if RakNet is used in a closed-source context (as in LU). In this situation the version of RakNet used can't be updated, even if it turns out there are bugs in its implementation. This is especially problematic when the potential security vulnerabilities mentioned above are taken into account.

	To address these issues, this program replaces the RakNet 3.25 protocol with a new protocol, designed to add as little additional complexity as possible. Support for the reliability modes `Reliable` and `ReliableSequenced` are dropped, with `Reliable` converted to `ReliableOrdered`. Instead of basing the protocol on UDP for all reliability modes, UDP is used as a base for `Unreliable` and `UnreliableSequenced` packets, and TCP is used for `ReliableOrdered` packets. This means that the underlying protocols' mechanisms can be fully utilized and the resulting protocol is kept extremely simple.

	For encryption, the TCP connection can be configured to use TLS. As TLS needs a reliable base protocol, and LU only uses unreliable packets for player position updates and not for confidential data, the choice was made not to support encrypted UDP.

	As the LU client is closed-source, its use of the RakNet protocol cannot be replaced directly, and the translation into TCP/UDP needs to be transparent to the client. To accomplish this, this program hosts a RakNet 3.25 server which the client connects to. Traffic is translated on the fly and relayed to a server using the new protocol. LU Redirect packets are intercepted and new relays are spun up to facilitate dynamic connections to multiple servers.

	More information about the new protocol can be found in the documentation for the TcpUdp connection implementation, and info about the translation and interception process can be found in the `Bridge` documentation.
*/
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Result as Res;
use std::net::TcpListener;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::Duration;

mod bridge;
mod raknet;
mod string;
mod tcpudp;
use tcpudp::Connection;

use crate::bridge::{Bridge, ShimCommand};
const SLEEP_TIME: Duration = Duration::from_millis(1000 / 30);

/// A RakNet server translating and relaying incoming connections to a TcpUdp server.
pub struct Shim {
	/// The remote address to relay connections to.
	connect_addr: SocketAddr,
	/// The RakNet socket. As UDP is a connectionless protocol, there is only one socket no matter how many clients connect to the server.
	tcp_listener: TcpListener,
	/// The map from an incoming RakNet address to the bridge responsible for handling the specific connection.
	bridges: HashMap<SocketAddr, Bridge>,
	config: AppConfig,
}

impl Shim {
	/// Creates a new Shim with the specified local address to listen on and the remote address to relay connections to.
	fn new(listen_addr: SocketAddr, connect_addr: SocketAddr, config: AppConfig) -> Res<Shim> {
		let real_listen_addr = (config.bind_to, listen_addr.port())
			.to_socket_addrs()?
			.next()
			.unwrap();
		let tcp_server = TcpListener::bind(real_listen_addr.to_string().as_str())?;
		tcp_server.set_nonblocking(true)?;

		println!("Starting new shim. Listening on {listen_addr}, connecting to RakNet at {connect_addr}.");

		Ok(Shim {
			connect_addr,
			tcp_listener: tcp_server,
			bridges: HashMap::new(),
			config,
		})
	}

	/// Returns the local address of the RakNet socket. This may not be the same as the `listen_address` passed to `new` if the passed address had 0 as port.
	pub fn local_addr(&self) -> Res<SocketAddr> {
		self.tcp_listener.local_addr()
	}

	/**
		Checks all sockets for incoming packets and handles them if there are any.

		The RakNet socket is checked by the `raknet_step` method, while the TCP/UDP sockets are checked by the bridge's `tcpudp_receive` method.
	*/
	fn step(
		&mut self,
		cmds: &mut Vec<ShimCommand>,
		addrs: &HashMap<SocketAddr, SocketAddr>,
	) -> Res<()> {
		self.client_receive()?;
		self.bridges
			.retain(|_addr, bridge| match bridge.server_receive(addrs) {
				Ok(cmd) => {
					cmds.extend(cmd);
					true
				}
				Err(err) => {
					if err.kind() == io::ErrorKind::ConnectionReset {
						println!("Connection was reset unexpectedly");
					} else if err.kind() != io::ErrorKind::ConnectionAborted {
						println!("Error in `step`: {err:?}");
					}
					false
				}
			});
		Ok(())
	}

	fn client_receive(&mut self) -> Res<()> {
		while let Ok((stream, addr)) = self.tcp_listener.accept() {
			let conn = Connection::from(stream)?;

			let new_bridge = self.create_bridge(conn)?;
			self.bridges.insert(addr, new_bridge);
		}

		self.bridges
			.retain(|_addr, bridge| match bridge.client_receive() {
				Ok(msg) => {
					bridge.forward_to_server(&msg).unwrap_or_else(|err| {
						println!("Error in `client_receive`: {err:?}");
					});
					true
				}
				Err(err) => {
					if err.kind() == io::ErrorKind::ConnectionReset {
						return false;
					}
					if err.kind() != io::ErrorKind::WouldBlock {
						dbg!(&err);
					}
					true
				}
			});

		Ok(())
	}

	fn create_bridge(&self, source: Connection) -> Res<Bridge> {
		let raknet_to_server_socket = UdpSocket::bind("0.0.0.0:0")?;
		raknet_to_server_socket.connect(self.connect_addr)?;
		raknet_to_server_socket.set_nonblocking(true)?;
		raknet_to_server_socket.send_to(&[9, 121], self.connect_addr)?;
		Ok(Bridge::new(
			source,
			raknet_to_server_socket,
			self.config.clone(),
		))
	}
}

impl Drop for Shim {
	fn drop(&mut self) {
		println!("Closing shim {}", self.connect_addr.port());
	}
}

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
	external_ip: String,
	external_auth_port: u16,
	raknet_ip: String,
	raknet_auth_port: u16,
	bind_to: String,
}

fn load_config() -> Result<AppConfig, io::Error> {
	let config_str = fs::read_to_string("config.toml").map_err(|err| {
		io::Error::new(
			io::ErrorKind::NotFound,
			format!("Could not read config file `config.toml`: {err}"),
		)
	})?;
	toml::from_str(&config_str).map_err(|err| {
		io::Error::new(
			io::ErrorKind::InvalidData,
			format!("Error in formatting config file `config.toml`: {err}"),
		)
	})
}

fn main() -> Res<()> {
	let config: AppConfig = load_config().unwrap_or_else(|err| {
		eprintln!("{err}");
		std::process::exit(1);
	});

	let listen_addr = ("0.0.0.0", config.external_auth_port)
		.to_socket_addrs()
		.unwrap()
		.next()
		.unwrap();
	let connect_addr = (config.raknet_ip.clone(), config.raknet_auth_port)
		.to_socket_addrs()
		.unwrap()
		.next()
		.unwrap();

	let mut addrs = HashMap::new();
	let mut shims = vec![];
	addrs.insert(connect_addr, listen_addr);
	shims.push(Shim::new(listen_addr, connect_addr, config.clone())?);

	loop {
		let mut cmds = vec![];

		for shim in shims.iter_mut() {
			shim.step(&mut cmds, &addrs)?;
		}
		for cmd in cmds {
			match cmd {
				ShimCommand::NewShim(connect_addr, shim) => {
					addrs.insert(connect_addr, shim.local_addr()?);
					shims.push(shim);
				}
			}
		}
		thread::sleep(SLEEP_TIME);
	}
}
