/*!
	The TCP- and UDP-based Raknet replacement protocol.

	The protocol is designed to make full use of the mechanisms of the underlying protocols and be as simple as possible itself.

	Reliable packets are sent over TCP, which provides all necessary mechanisms for reliability and ordering. The only additional mechanism needed is message framing, as TCP is a stream-oriented protocol and doesn't have a concept of distinct messages. To implement this, each message is prefixed with a 32-bit length field (in bytes).

	Unreliable packets are sent over UDP, prefixed with an 8-bit ID for distinguishing between `Unreliable` (ID 0) and `UnreliableSequenced` (ID 1). In the case of `UnreliableSequenced`, a 32-bit sequence number is prefixed as well. To keep the protocol simple, no support for packet splitting is included, unreliable packets must be shorter than the MTU.
*/
use std::io::Error;
use std::io::ErrorKind::WouldBlock;
use std::io::Result as Res;

use endio::LEWrite;

use crate::bridge::Packet;
use std::net::{SocketAddr, TcpStream as ReliableTransport};

#[derive(Debug)]
/// Buffer for keeping packets that were only read in part.
struct BufferOffset {
	reading_length: bool,
	offset: usize,
	length: [u8; 4],
	buffer: Box<[u8]>,
}

/**
	Supports sending and receiving messages in the TCP/UDP protocol.

	By substituting the I and O parameters with types representing the messages you intend to receive (I) and send (O), you can construct an API that only allows sending and receiving of correctly formatted messages, with (de-)serialization done automatically.

	Note: UDP support is not present in this variant as the auth server doesn't need it.
*/
#[derive(Debug)]
pub struct Connection {
	tcp: ReliableTransport,
	packet: BufferOffset,
}

impl Connection {
	/// Constructs a connection from a previously established TCP or TLS connection.
	pub fn from(tcp: ReliableTransport) -> Res<Self> {
		tcp.set_nonblocking(true)?;
		Ok(Self {
			tcp,
			packet: BufferOffset {
				reading_length: true,
				offset: 0,
				length: [0; 4],
				buffer: Box::new([]),
			},
		})
	}

	#[allow(dead_code)]
	pub fn local_addr(&self) -> Res<SocketAddr> {
		self.tcp.local_addr()
	}

	/// Sends bytes over TCP.
	pub fn send_raw(&mut self, data: &[u8]) -> Res<()> {
		self.tcp.write(data.len() as u32)?;
		std::io::Write::write(&mut self.tcp, data)?;
		Ok(())
	}

	pub fn send_packets(&mut self, datas: Vec<Packet>) -> Res<()> {
		for data in datas {
			self.send_raw(&data.data)?;
		}
		Ok(())
	}

	/// Receives bytes over TCP.
	pub fn receive_raw(&mut self) -> Res<Box<[u8]>> {
		use std::io::Read;

		if self.packet.reading_length {
			while self.packet.offset < self.packet.length.len() {
				let n = self
					.tcp
					.read(&mut self.packet.length[self.packet.offset..])?;
				if n == 0 {
					return Err(Error::new(WouldBlock, ""));
				}
				self.packet.offset += n;
			}
			self.packet.reading_length = false;
			self.packet.offset = 0;
			self.packet.buffer =
				vec![0; u32::from_le_bytes(self.packet.length) as usize].into_boxed_slice();
		}
		while self.packet.offset < self.packet.buffer.len() {
			let n = self
				.tcp
				.read(&mut self.packet.buffer[self.packet.offset..])?;
			if n == 0 {
				return Err(Error::new(WouldBlock, ""));
			}
			self.packet.offset += n;
		}
		self.packet.reading_length = true;
		self.packet.offset = 0;
		let mut b = Box::from(&[][..]);
		std::mem::swap(&mut self.packet.buffer, &mut b);
		Ok(b)
	}
}
