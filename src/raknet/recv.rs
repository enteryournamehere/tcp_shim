use std::collections::hash_map::Entry;
use std::collections::HashMap;

use endio::LERead;
use endio_bit::BEBitReader;

use super::packet::{RaknetPacket, ReliabilityData};
use super::rangelist::RangeList;
use crate::bridge::{MessageType, Packet};

#[derive(Default)]
pub struct ReceivePart {
	unrel_seq_index: u32,
	rel_ord_index: u32,
	out_of_order_packets: HashMap<u32, Packet>,
	split_packet_queue: HashMap<u16, Vec<Option<Box<[u8]>>>>,
}

impl ReceivePart {
	pub fn parse_packets(reader: &mut BEBitReader<&mut &[u8]>) -> Vec<RaknetPacket> {
		let mut rak_packets = vec![];
		while let Ok(packet) = reader.read() {
			rak_packets.push(packet);
		}
		rak_packets
	}

	pub fn process_incoming_packets(
		&mut self,
		rak_packets: Vec<RaknetPacket>,
		acks: &mut RangeList,
		closed: &mut bool,
	) -> Vec<Packet> {
		let mut packets = Vec::with_capacity(rak_packets.len()); // around this number, fewer with skips, more with queue drains
		for mut rak_packet in rak_packets {
			match rak_packet.rel_data {
				ReliabilityData::Reliable | ReliabilityData::ReliableOrdered(_) => {
					acks.insert(rak_packet.message_number);
				}
				_ => {}
			}

			if let Some(split) = &rak_packet.split_packet_info {
				assert!(split.count > 1);
				println!("got split packet {} out of {}", split.index, split.count);
				match self.split_packet_queue.entry(split.id) {
					Entry::Vacant(v) => {
						let mut parts = vec![None; split.count as usize];
						parts[split.index as usize] = Some(rak_packet.data);
						v.insert(parts);
						continue;
					}
					Entry::Occupied(mut o) => {
						let parts = o.get_mut();
						parts[split.index as usize] = Some(rak_packet.data);
						let mut ready = true;
						for part in parts.iter() {
							if part.is_none() {
								ready = false;
								break;
							}
						}
						if ready {
							let mut assembled: Vec<u8> = vec![];
							for part in parts.iter() {
								if let Some(x) = part {
									assembled.extend_from_slice(x);
								}
							}
							rak_packet.data = assembled.into_boxed_slice();
							o.remove_entry();
						} else {
							continue;
						}
					}
				}
			}

			if rak_packet.data.len() >= 1
				&& rak_packet.data[0] == MessageType::DisconnectNotification as u8
			{
				*closed = true;
				continue;
			}

			match rak_packet.rel_data {
				ReliabilityData::UnreliableSequenced(ord) => {
					if ord.wrapping_sub(self.unrel_seq_index) < u32::max_value() / 2 {
						self.unrel_seq_index = ord.wrapping_add(1);
					} else {
						// old unreliable packets get dropped
						continue;
					}
				}
				ReliabilityData::ReliableOrdered(ord) => {
					if ord == self.rel_ord_index {
						self.rel_ord_index = self.rel_ord_index.wrapping_add(1);
						packets.push(Packet::from(rak_packet));
						// release any queued up packets directly after this one
						while let Some(x) = self.out_of_order_packets.remove(&self.rel_ord_index) {
							packets.push(x);
							self.rel_ord_index = self.rel_ord_index.wrapping_add(1);
						}
						// don't push the packet twice
						continue;
					} else if ord.wrapping_sub(self.rel_ord_index) < u32::max_value() / 2 {
						// packet too early
						println!("relord packet too early {} > {}", ord, self.rel_ord_index);
						// add to queue
						self.out_of_order_packets
							.insert(ord, Packet::from(rak_packet));
						continue;
					} else {
						// duplicate
						println!("relord dup {} < {}", ord, self.rel_ord_index);
						continue;
					}
				}
				_ => {}
			}

			packets.push(Packet::from(rak_packet));
		}
		packets
	}
}

#[cfg(test)]
mod tests {
	use super::super::packet::SplitPacketInfo;
	use super::{MessageType, RaknetPacket, RangeList, ReceivePart, ReliabilityData::*};

	fn unrel_seq(index: u32) -> RaknetPacket {
		RaknetPacket {
			message_number: index,
			rel_data: UnreliableSequenced(index),
			split_packet_info: None,
			data: Box::new([index as u8]),
		}
	}

	fn rel_ord(index: u32) -> RaknetPacket {
		RaknetPacket {
			message_number: index,
			rel_data: ReliableOrdered(index),
			split_packet_info: None,
			data: Box::new([index as u8]),
		}
	}

	#[test]
	fn unrel() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![RaknetPacket {
			message_number: 0,
			rel_data: Unreliable,
			split_packet_info: None,
			data: Box::new([]),
		}];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(acks.len(), 0);
		assert_eq!(packets.len(), 1);
	}

	#[test]
	fn unrel_seq_duplicate() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![unrel_seq(1), unrel_seq(1)];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(acks.len(), 0);
		assert_eq!(packets.len(), 1);
	}
	#[test]
	fn unrel_seq_too_early() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![unrel_seq(1)];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(packets.len(), 1);
	}

	#[test]
	fn unrel_seq_caught_up() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![unrel_seq(1), unrel_seq(0)];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(packets.len(), 1);
	}

	#[test]
	fn unrel_seq_gap_too_large() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![unrel_seq(u32::max_value())];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(packets.len(), 0);
	}

	#[test]
	fn unrel_seq_overflow() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		recv.unrel_seq_index = u32::max_value();
		let rak_packets = vec![unrel_seq(u32::max_value()), unrel_seq(u32::min_value())];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(packets.len(), 2);
	}

	#[test]
	fn unrel_seq_overflow_gap() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		recv.unrel_seq_index = u32::max_value() - 1;
		let rak_packets = vec![unrel_seq(u32::max_value() - 1), unrel_seq(u32::min_value())];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(packets.len(), 2);
	}

	#[test]
	fn rel_ord_duplicate() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![rel_ord(0), rel_ord(0)];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(acks.len(), 1);
		assert_eq!(packets.len(), 1);
	}

	#[test]
	fn rel_ord_too_early() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![rel_ord(1)];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(acks.len(), 1);
		assert_eq!(packets.len(), 0);
	}

	#[test]
	fn rel_ord_caught_up() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![rel_ord(1), rel_ord(0)];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(acks.len(), 2);
		assert_eq!(packets.len(), 2);
		assert_eq!(packets[0].data[0], 0);
		assert_eq!(packets[1].data[0], 1);
	}

	#[test]
	fn rel_ord_gap() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![rel_ord(5), rel_ord(1), rel_ord(0)];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(acks.len(), 3);
		assert_eq!(packets.len(), 2);
		assert_eq!(packets[0].data[0], 0);
		assert_eq!(packets[1].data[0], 1);
	}

	#[test]
	fn rel_ord_overflow_duplicate() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![rel_ord(u32::max_value())];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(packets.len(), 0);
		assert_eq!(recv.out_of_order_packets.len(), 0);
	}

	#[test]
	fn rel_ord_overflow_index() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		recv.rel_ord_index = u32::max_value();
		let rak_packets = vec![rel_ord(u32::max_value()), rel_ord(u32::min_value())];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(packets.len(), 2);
		assert_eq!(packets[0].data[0], u8::max_value());
		assert_eq!(packets[1].data[0], u8::min_value());
	}

	#[test]
	fn rel_ord_overflow_index_out_of_order() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		recv.rel_ord_index = u32::max_value();
		let rak_packets = vec![rel_ord(u32::min_value()), rel_ord(u32::max_value())];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(packets.len(), 2);
		assert_eq!(packets[0].data[0], u8::max_value());
		assert_eq!(packets[1].data[0], u8::min_value());
	}

	#[test]
	fn rel_ord_overflow_queue_drain() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		recv.rel_ord_index = u32::max_value() - 1;
		let rak_packets = vec![rel_ord(u32::max_value()), rel_ord(u32::max_value() - 1)];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(packets.len(), 2);
		assert_eq!(packets[0].data[0], u8::max_value() - 1);
		assert_eq!(packets[1].data[0], u8::max_value());
	}

	#[test]
	fn single_split_packet() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![RaknetPacket {
			message_number: 0,
			rel_data: ReliableOrdered(0),
			split_packet_info: Some(SplitPacketInfo {
				id: 0,
				index: 0,
				count: 2,
			}),
			data: Box::new([]),
		}];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(acks.len(), 1);
		assert_eq!(packets.len(), 0);
	}

	#[test]
	fn all_split_packets() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let rak_packets = vec![
			RaknetPacket {
				message_number: 0,
				rel_data: ReliableOrdered(0),
				split_packet_info: Some(SplitPacketInfo {
					id: 0,
					index: 1,
					count: 2,
				}),
				data: Box::new([3, 4, 5]),
			},
			RaknetPacket {
				message_number: 1,
				rel_data: ReliableOrdered(0),
				split_packet_info: Some(SplitPacketInfo {
					id: 0,
					index: 0,
					count: 2,
				}),
				data: Box::new([0, 1, 2]),
			},
		];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut false);
		assert_eq!(acks.len(), 2);
		assert_eq!(packets.len(), 1);
		assert_eq!(&*packets[0].data, [0, 1, 2, 3, 4, 5]);
	}

	#[test]
	fn disconnect_close() {
		let mut recv = ReceivePart::default();
		let mut acks = RangeList::new();
		let mut closed = false;
		let rak_packets = vec![RaknetPacket {
			message_number: 0,
			rel_data: ReliableOrdered(0),
			split_packet_info: None,
			data: Box::new([MessageType::DisconnectNotification as u8]),
		}];
		let packets = recv.process_incoming_packets(rak_packets, &mut acks, &mut closed);
		assert!(closed);
		assert_eq!(packets.len(), 0);
	}
}
