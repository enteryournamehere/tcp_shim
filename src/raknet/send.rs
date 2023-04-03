use std::io::Result as Res;
use std::net::{SocketAddr, UdpSocket};

use endio::LEWrite;
use endio_bit::BEBitWriter;

use super::packet::{RaknetPacket, ReliabilityData, SplitPacketInfo};
use super::rangelist::RangeList;
use crate::bridge::{Packet, Reliability};

const MTU_SIZE: usize = 1228; // set by LU
const UDP_HEADER_SIZE: usize = 28;
pub const MAX_PACKET_SIZE: usize = MTU_SIZE - UDP_HEADER_SIZE;

pub struct SendPart {
	socket: UdpSocket,
	address: SocketAddr,
	message_number: u32,
	split_packet_index: u16,
	unrel_seq_index: u32,
	rel_ord_index: u32,
}

impl SendPart {
	pub fn new(socket: UdpSocket, address: SocketAddr) -> Self {
		Self {
			socket,
			address,
			message_number: 0,
			split_packet_index: 0,
			unrel_seq_index: 0,
			rel_ord_index: 0,
		}
	}

	pub fn send_packets(
		&mut self,
		packets: Vec<Packet>,
		acks: &mut RangeList,
		remote_system_time: u32,
	) -> Res<()> {
		let rak_packets = self.process_outgoing_packets(packets);

		if rak_packets.is_empty() {
			self.send_acks(acks, remote_system_time)?;
		}

		for rak_packet in rak_packets {
			self.send_packet(rak_packet, acks, remote_system_time)?;
		}
		Ok(())
	}

	fn send(&self, data: &[u8]) -> Res<usize> {
		self.socket.send_to(data, self.address)
	}

	fn message_number(&mut self) -> u32 {
		let msgn = self.message_number;
		self.message_number = self.message_number.wrapping_add(1);
		msgn
	}

	fn split_packet_index(&mut self) -> u16 {
		let id = self.split_packet_index;
		self.split_packet_index = self.split_packet_index.wrapping_add(1);
		id
	}

	fn rel_data(&mut self, rel: &Reliability) -> ReliabilityData {
		match rel {
			Reliability::Unreliable => ReliabilityData::Unreliable,
			Reliability::UnreliableSequenced => {
				let ord = self.unrel_seq_index;
				self.unrel_seq_index = self.unrel_seq_index.wrapping_add(1);
				ReliabilityData::UnreliableSequenced(ord)
			}
			Reliability::Reliable => ReliabilityData::Reliable,
			Reliability::ReliableOrdered => {
				let ord = self.rel_ord_index;
				self.rel_ord_index = self.rel_ord_index.wrapping_add(1);
				ReliabilityData::ReliableOrdered(ord)
			}
		}
	}

	pub fn process_outgoing_packets(&mut self, packets: Vec<Packet>) -> Vec<RaknetPacket> {
		let mut rak_packets = Vec::with_capacity(packets.len()); // either the same amount or more
		for packet in packets {
			let rel_data = self.rel_data(&packet.reliability);
			if Self::header_len(&packet.reliability, false) + packet.data.len() > MAX_PACKET_SIZE {
				let split_packet_id = self.split_packet_index();
				let chunk_size = MAX_PACKET_SIZE - Self::header_len(&packet.reliability, true);
				let chunks = packet.data.chunks(chunk_size);
				let count = chunks.len() as u32;
				for (i, chunk) in chunks.enumerate() {
					let message_number = self.message_number();
					let info = Some(SplitPacketInfo {
						id: split_packet_id,
						index: i as u32,
						count,
					});
					rak_packets.push(RaknetPacket {
						message_number,
						rel_data: rel_data.clone(),
						split_packet_info: info,
						data: Box::from(chunk),
					});
				}
			} else {
				let message_number = self.message_number();
				rak_packets.push(RaknetPacket {
					message_number,
					rel_data,
					split_packet_info: None,
					data: packet.data,
				});
			}
		}
		rak_packets
	}

	fn header_len(rel: &Reliability, is_split_packet: bool) -> usize {
		let mut len = 32; // message number
		len += 3; // reliability
		if rel == &Reliability::UnreliableSequenced || rel == &Reliability::ReliableOrdered {
			len += 5; // ordering channel
			len += 32; // ordering index
		}
		len += 1; // is split packet
		if is_split_packet {
			len += 16; // split packet id
			len += 32; // split packet index (actually a compressed write so assume the maximum)
			len += 32; // split packet count (actually a compressed write so assume the maximum)
			len += 16; // data length (actually a compressed write so assume the maximum)
		}
		len / 8 + 1
	}

	fn send_packet(
		&mut self,
		packet: RaknetPacket,
		acks: &mut RangeList,
		remote_system_time: u32,
	) -> Res<()> {
		let mut vec = vec![];
		{
			let mut writer = BEBitWriter::new(&mut vec);
			Self::write_acks(&mut writer, acks, remote_system_time)?;
			let has_remote_system_time = false;
			writer.write_bit(has_remote_system_time)?;
			writer.write(&packet)?;
		}
		self.send(&vec)?;
		Ok(())
	}

	fn send_acks(&mut self, acks: &mut RangeList, remote_system_time: u32) -> Res<()> {
		let has_acks = !acks.is_empty();
		if !has_acks {
			return Ok(());
		}
		let mut vec = vec![];
		{
			let mut writer = BEBitWriter::new(&mut vec);
			Self::write_acks(&mut writer, acks, remote_system_time)?;
		}
		self.send(&vec)?;
		Ok(())
	}

	fn write_acks(
		writer: &mut BEBitWriter<&mut Vec<u8>>,
		acks: &mut RangeList,
		remote_system_time: u32,
	) -> Res<()> {
		let has_acks = !acks.is_empty();
		writer.write_bit(has_acks)?;
		if has_acks {
			writer.write(remote_system_time)?;
			writer.write(&*acks)?;
		}
		acks.clear();
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use std::net::{ToSocketAddrs, UdpSocket};

	use super::Packet;
	use super::Reliability as R;
	use super::ReliabilityData as RD;
	use super::SendPart;

	fn send() -> SendPart {
		SendPart::new(
			UdpSocket::bind("127.0.0.1:0").unwrap(),
			"127.0.0.1:0".to_socket_addrs().unwrap().next().unwrap(),
		)
	}

	#[test]
	fn message_number() {
		let mut send = send();
		let packets = vec![
			Packet {
				data: Box::new([]),
				reliability: R::Unreliable,
			},
			Packet {
				data: Box::new([]),
				reliability: R::Unreliable,
			},
		];
		let rak_packets = send.process_outgoing_packets(packets);
		assert_eq!(rak_packets[0].message_number, 0);
		assert_eq!(rak_packets[1].message_number, 1);
	}

	#[test]
	fn unrel_seq_index() {
		let mut send = send();
		let packets = vec![
			Packet {
				data: Box::new([]),
				reliability: R::UnreliableSequenced,
			},
			Packet {
				data: Box::new([]),
				reliability: R::UnreliableSequenced,
			},
		];
		let rak_packets = send.process_outgoing_packets(packets);
		if let RD::UnreliableSequenced(i) = rak_packets[0].rel_data {
			assert_eq!(i, 0);
		} else {
			panic!();
		}
		if let RD::UnreliableSequenced(i) = rak_packets[1].rel_data {
			assert_eq!(i, 1);
		} else {
			panic!();
		}
	}

	#[test]
	fn rel_ord_index() {
		let mut send = send();
		let packets = vec![
			Packet {
				data: Box::new([]),
				reliability: R::ReliableOrdered,
			},
			Packet {
				data: Box::new([]),
				reliability: R::ReliableOrdered,
			},
		];
		let rak_packets = send.process_outgoing_packets(packets);
		if let RD::ReliableOrdered(i) = rak_packets[0].rel_data {
			assert_eq!(i, 0);
		} else {
			panic!();
		}
		if let RD::ReliableOrdered(i) = rak_packets[1].rel_data {
			assert_eq!(i, 1);
		} else {
			panic!();
		}
	}

	#[test]
	fn split_packet() {
		let mut send = send();
		let packets = vec![Packet {
			data: Box::new([0; super::MAX_PACKET_SIZE * 3]),
			reliability: R::ReliableOrdered,
		}];
		let rak_packets = send.process_outgoing_packets(packets);
		assert_eq!(rak_packets.len(), 4);
		for (i, rak_packet) in rak_packets.into_iter().enumerate() {
			assert_eq!(rak_packet.message_number, i as u32);
			if let RD::ReliableOrdered(i) = rak_packet.rel_data {
				assert_eq!(i, 0);
			} else {
				panic!();
			}
			let info = rak_packet.split_packet_info.unwrap();
			assert_eq!(info.id, 0);
			assert_eq!(info.count, 4);
			assert_eq!(info.index, i as u32);
		}
	}

	#[test]
	fn overflow() {
		let mut send = SendPart {
			socket: UdpSocket::bind("127.0.0.1:0").unwrap(),
			address: "127.0.0.1:0".to_socket_addrs().unwrap().next().unwrap(),
			message_number: u32::max_value(),
			split_packet_index: u16::max_value(),
			unrel_seq_index: u32::max_value(),
			rel_ord_index: u32::max_value(),
		};

		assert_eq!(send.message_number(), u32::max_value());
		assert_eq!(send.message_number(), u32::min_value());
		assert_eq!(send.split_packet_index(), u16::max_value());
		assert_eq!(send.split_packet_index(), u16::min_value());
		if let RD::UnreliableSequenced(i) = send.rel_data(&R::UnreliableSequenced) {
			assert_eq!(i, u32::max_value());
		} else {
			panic!()
		}
		if let RD::UnreliableSequenced(i) = send.rel_data(&R::UnreliableSequenced) {
			assert_eq!(i, u32::min_value());
		} else {
			panic!()
		}
		if let RD::ReliableOrdered(i) = send.rel_data(&R::ReliableOrdered) {
			assert_eq!(i, u32::max_value());
		} else {
			panic!()
		}
		if let RD::ReliableOrdered(i) = send.rel_data(&R::ReliableOrdered) {
			assert_eq!(i, u32::min_value());
		} else {
			panic!()
		}
	}
}
