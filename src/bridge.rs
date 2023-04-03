use std::collections::HashMap;
use std::io::Result as Res;
use std::net::{SocketAddr, ToSocketAddrs};

use endio::{LERead, LEWrite};

use crate::raknet::Connection as RakConn;
use crate::raknet::MAX_PACKET_SIZE;
use crate::string::WriteStr;
use crate::tcpudp::Connection as TcpConn;
use crate::{AppConfig, Shim};
use std::net::UdpSocket;

// Control messages of the RakNet data-level protocol. Only those that need to be handled by this program are listed.
#[allow(dead_code)]
pub enum MessageType {
	/// First message ever received: The client requests to open a connection.
	OpenConnectionRequest = 9,
	/// We accept the client's request to open a connection.
	OpenConnectionReply = 10,
	/// We refuse the client's request to open a connection.
	NoFreeIncomingConnections = 18,
	/// The client has disconnected voluntarily.
	DisconnectNotification = 19,
}

/// Reliablity types supported by RakNet. `ReliableSequenced` is also one of them but is never used in practice, so it's omitted from this program entirely.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Reliability {
	/// Neither guaranteed to be received nor to be received in the same order as the packets were sent.
	Unreliable,
	/// Not guaranteed to be received. If packets are received out of order, the most recent one is used and older packets are ignored.
	UnreliableSequenced,
	/// Guaranteed to be received at some point. No guarantees about ordering are made.
	Reliable,
	/// Guaranteed to be received, and in the same order as the packets were sent.
	ReliableOrdered,
}

/// Packet data and reliability: The abstract data that connections return from receiving and accept for sending.
#[derive(Debug)]
pub struct Packet {
	pub reliability: Reliability,
	pub data: Box<[u8]>,
}

/// Shims are managed by the main function, so if they need to be modified the command has to be relayed back through this.
pub enum ShimCommand {
	/// Instructs the main function to add a shim to the list of shims, and a remote address to the lookup of remote addresses to local addresses.
	NewShim(SocketAddr, Shim),
}

/// A Bridge connects a RakNet connection with a TcpUdp connection.
pub struct Bridge {
	conn_to_client: TcpConn,
	conn_to_server: RakConn,
	raknet_socket: UdpSocket,
	raknet_buffer: [u8; MAX_PACKET_SIZE * 5],
	config: AppConfig,
}

impl Bridge {
	pub fn new(tcp_conn: TcpConn, raknet_to_server_socket: UdpSocket, config: AppConfig) -> Self {
		let raknet_to_server = RakConn::new(
			raknet_to_server_socket.try_clone().unwrap(),
			raknet_to_server_socket.peer_addr().unwrap(),
		);

		Bridge {
			conn_to_client: tcp_conn,
			conn_to_server: raknet_to_server,
			raknet_socket: raknet_to_server_socket,
			raknet_buffer: [0; MAX_PACKET_SIZE * 5],
			config,
		}
	}

	pub fn client_receive(&mut self) -> Res<Box<[u8]>> {
		self.conn_to_client.receive_raw()
	}

	pub fn server_receive(
		&mut self,
		addrs: &HashMap<SocketAddr, SocketAddr>,
	) -> Res<Vec<ShimCommand>> {
		let mut return_vec = Vec::new();
		loop {
			let (length, _) = match self.raknet_socket.recv_from(&mut self.raknet_buffer) {
				Ok(x) => x,
				Err(err) => {
					if err.kind() == std::io::ErrorKind::WouldBlock
						|| err.kind() == std::io::ErrorKind::ConnectionReset
					{
						return Ok(return_vec);
					}
					return Err(err);
				}
			};

			let mut packets = self
				.conn_to_server
				.handle_datagram(&self.raknet_buffer[..length])?;

			let mut cmds = self.scan_packets(&mut packets, addrs)?;
			return_vec.append(&mut cmds);
			self.conn_to_client.send_packets(packets)?;
		}
	}

	/// Receives any incoming packets on the RakNet end and sends them on the TcpUdp end.
	pub fn forward_to_server(&mut self, data: &[u8]) -> Res<()> {
		let packets = vec![Packet {
			reliability: Reliability::Reliable,
			data: data.to_vec().into_boxed_slice(),
		}];
		self.conn_to_server.send(packets)?;
		Ok(())
	}

	/**
		Scans packets for certain messages and replaces data if necessary.

		LU servers send IPs in login response and redirection packets. If these packets were passed on unmodified, the client would directly connect to the LU server instead, making this program pointless. Therefore these IPs need to be replaced with those of a relay server, starting one if it doesn't already exist.
	*/
	fn scan_packets(
		&mut self,
		packets: &mut Vec<Packet>,
		addrs: &HashMap<SocketAddr, SocketAddr>,
	) -> Res<Vec<ShimCommand>> {
		let mut cmds = vec![];
		for packet in packets {
			if packet.data.len() > 8 && packet.data[0] == 83 && packet.data[1] == 5 {
				let packet_is_login_response =
					packet.data[3] == 0 && packet.data[8] == 1 && packet.data.len() > 413;
				let packet_is_transfer_to_world = packet.data[3] == 14;

				if !((packet_is_login_response) || packet_is_transfer_to_world) {
					continue;
				}

				let raknet_host = self.raknet_socket.peer_addr().unwrap().ip();
				let port_location = if packet_is_login_response {
					411
				} else {
					8 + 33
				};
				let port: u16 = (&packet.data[port_location..]).read()?;
				let connect_addr = (raknet_host, port)
					.to_socket_addrs()
					.unwrap()
					.next()
					.unwrap();
				if addrs.get(&connect_addr).is_none() {
					let listen_addr = ("0.0.0.0", port).to_socket_addrs().unwrap().next().unwrap();
					let shim = Shim::new(listen_addr, connect_addr, self.config.clone())?;
					cmds.push(ShimCommand::NewShim(connect_addr, shim));
				}
				let ip_location = if packet_is_login_response { 345 } else { 8 };
				let mut writer = &mut packet.data[ip_location..];
				writer.write_fix(&self.config.external_ip)?;
				let mut writer = &mut packet.data[port_location..];
				writer.write(port)?;
			}
		}
		Ok(cmds)
	}
}

impl Drop for Bridge {
	fn drop(&mut self) {
		println!(
			"Closing bridge to port {}",
			self.raknet_socket.peer_addr().unwrap().port()
		);
	}
}
