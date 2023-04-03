// designed to be run on localhost only!
// a bunch of things will break if this is run on a backend where packet drop and congestion occur
use std::io;
use std::io::Result as Res;
use std::net::{SocketAddr, UdpSocket};

use endio::LERead;
use endio_bit::BEBitReader;

use super::rangelist::RangeList;
use super::recv::ReceivePart;
use super::send::SendPart;
use crate::bridge::{MessageType::DisconnectNotification, Packet, Reliability::Unreliable};

pub use super::send::MAX_PACKET_SIZE;

pub struct Connection {
	closed: bool,
	remote_system_time: u32,
	acks: RangeList,
	recv: ReceivePart,
	send: SendPart,
}

impl Connection {
	pub fn new(socket: UdpSocket, address: SocketAddr) -> Connection {
		Connection {
			closed: false,
			remote_system_time: 0,
			acks: RangeList::new(),
			recv: ReceivePart::default(),
			send: SendPart::new(socket, address),
		}
	}

	pub fn handle_datagram(&mut self, data: &[u8]) -> Res<Vec<Packet>> {
		let mut r = data;
		let mut reader = BEBitReader::new(&mut r);
		match self.handle_header(&mut reader) {
			Ok(_) => (),
			Err(err) => {
				// Server sends / once sent a packet with a bad header and no content
				if err.kind() != io::ErrorKind::UnexpectedEof {
					return Err(err);
				}
			}
		}
		let rak_packets = ReceivePart::parse_packets(&mut reader);
		Ok(self
			.recv
			.process_incoming_packets(rak_packets, &mut self.acks, &mut self.closed))
	}

	fn handle_header(&mut self, reader: &mut BEBitReader<&mut &[u8]>) -> Res<()> {
		let has_acks = reader.read_bit()?;
		if has_acks {
			let _old_time: u32 = reader.read()?;
			let _acks: RangeList = reader.read()?;
		}
		let has_remote_system_time = reader.read_bit()?;
		if has_remote_system_time {
			self.remote_system_time = reader.read()?;
		}
		Ok(())
	}

	pub fn send(&mut self, packets: Vec<Packet>) -> Res<()> {
		if self.closed {
			return Err(io::Error::new(
				io::ErrorKind::ConnectionAborted,
				"disconnect notification received",
			));
		}
		self.send
			.send_packets(packets, &mut self.acks, self.remote_system_time)
	}
}

impl Drop for Connection {
	fn drop(&mut self) {
		let _ = self.send(vec![Packet {
			reliability: Unreliable,
			data: Box::from([DisconnectNotification as u8]),
		}]);
	}
}
