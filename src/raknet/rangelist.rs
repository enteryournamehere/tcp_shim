use std::io::Result as Res;

use endio::{Deserialize, LERead, LEWrite, LittleEndian, Serialize};
use endio_bit::{BEBitReader, BEBitWriter};

use super::comp::Compressed;

#[derive(Debug)]
struct Range {
	min: u32,
	max: u32,
}
#[derive(Debug)]
pub struct RangeList {
	ranges: Vec<Range>,
}

impl RangeList {
	pub fn new() -> RangeList {
		RangeList { ranges: vec![] }
	}

	pub fn len(&self) -> usize {
		let mut len = 0;
		for range in self.ranges.iter() {
			len += (range.max - range.min + 1) as usize;
		}
		len
	}

	pub fn is_empty(&self) -> bool {
		self.ranges.is_empty()
	}

	pub fn clear(&mut self) {
		self.ranges.clear()
	}

	pub fn insert(&mut self, item: u32) {
		let ranges_len = self.ranges.len();
		let mut try_remove = None;
		let mut insert = None;
		for (i, range) in self.ranges.iter_mut().enumerate() {
			if range.min <= item {
				if range.max >= item {
					// The item is within the range, we don't even need to update it
					return;
				}
				if range.max == item - 1 {
					range.max = item;
					if i == ranges_len - 1 {
						return;
					}
					try_remove = Some(i + 1);
					break;
				}
			} else {
				if range.min - item == 1 {
					range.min = item;
					return;
				}
				// If we got here, the range starts at a higher position than the item, so we should insert it now (the list is auto-sorted so there can't be any other position)
				insert = Some(i);
				break;
			}
		}
		if let Some(i) = try_remove {
			if self.ranges[i].min == item - 1 {
				self.ranges.remove(i);
			}
			return;
		}
		if let Some(i) = insert {
			self.ranges.insert(
				i,
				Range {
					min: item,
					max: item,
				},
			);
			return;
		}
		// We ran through the whole list and couldn't find a good existing range
		self.ranges.push(Range {
			min: item,
			max: item,
		});
	}
}

pub struct Items {
	range_iter: std::vec::IntoIter<Range>,
	range: Option<std::ops::RangeInclusive<u32>>,
}

impl Iterator for Items {
	type Item = u32;

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			if self.range.is_none() {
				let range = self.range_iter.next()?;
				self.range = Some(range.min..=range.max);
			}
			if let Some(range) = &mut self.range {
				match range.next() {
					None => self.range = None,
					Some(x) => {
						return Some(x);
					}
				}
			}
		}
	}
}

impl IntoIterator for RangeList {
	type Item = u32;
	type IntoIter = Items;

	fn into_iter(self) -> Self::IntoIter {
		Items {
			range_iter: self.ranges.into_iter(),
			range: None,
		}
	}
}

impl<W: std::io::Write> Serialize<LittleEndian, BEBitWriter<W>> for &RangeList {
	fn serialize(self, writer: &mut BEBitWriter<W>) -> Res<()> {
		writer.write(Compressed::<u16>(self.ranges.len() as u16))?;
		for range in &self.ranges {
			writer.write_bit(range.min == range.max)?;
			writer.write(range.min)?;
			if range.min != range.max {
				writer.write(range.max)?;
			}
		}
		Ok(())
	}
}

impl<R: std::io::Read> Deserialize<LittleEndian, BEBitReader<R>> for RangeList {
	fn deserialize(reader: &mut BEBitReader<R>) -> Res<Self> {
		let ranges_count: Compressed<u16> = reader.read()?;
		let ranges_count = u16::from(ranges_count);
		let mut ranges = vec![];
		for _ in 0..ranges_count {
			let same = reader.read_bit()?;
			let min = reader.read()?;
			let max;
			if same {
				max = min;
			} else {
				max = reader.read()?;
			}
			ranges.push(Range { min, max });
		}
		Ok(RangeList { ranges })
	}
}

#[cfg(test)]
mod tests {
	use std::io::Result as Res;

	use super::RangeList;
	use endio::{LERead, LEWrite};
	use endio_bit::{BEBitReader, BEBitWriter};

	const DATA: &[u8] = b"\xd0\x02\x00\x00\x00\x06\x00\x00\x00\x05\x00\x00\x00\x06\x00\x00\x00\x84\x00\x00\x00\x03\x80\x00\x00\x04@\x00\x00\x00";

	#[test]
	fn insert() {
		let values = [1, 2, 3, 4];
		let mut list = RangeList::new();
		for value in &values {
			list.insert(*value);
		}
		assert_eq!(list.ranges.len(), 1);
		assert_eq!(list.ranges[0].min, 1);
		assert_eq!(list.ranges[0].max, 4);
	}

	#[test]
	fn underflow() {
		let mut list = RangeList::new();
		list.insert(u32::min_value());
		list.insert(u32::min_value());
		assert_eq!(list.ranges.len(), 1);
		assert_eq!(list.ranges[0].min, u32::min_value());
		assert_eq!(list.ranges[0].max, u32::min_value());
	}

	#[test]
	fn overflow() {
		let mut list = RangeList::new();
		list.insert(u32::max_value());
		list.insert(u32::max_value());
		assert_eq!(list.ranges.len(), 1);
		assert_eq!(list.ranges[0].min, u32::max_value());
		assert_eq!(list.ranges[0].max, u32::max_value());
	}

	fn create_multiple_ranges() -> RangeList {
		let values = [1, 2, 3, 5, 6, 8, 14, 15, 16, 17];
		let mut list = RangeList::new();
		for value in &values {
			list.insert(*value);
		}
		list
	}

	fn assert_multiple_ranges(list: &RangeList) {
		assert_eq!(list.ranges.len(), 4);
		assert_eq!(list.len(), 10);
		assert_eq!(list.ranges[0].min, 1);
		assert_eq!(list.ranges[0].max, 3);
		assert_eq!(list.ranges[1].min, 5);
		assert_eq!(list.ranges[1].max, 6);
		assert_eq!(list.ranges[2].min, 8);
		assert_eq!(list.ranges[2].max, 8);
		assert_eq!(list.ranges[3].min, 14);
		assert_eq!(list.ranges[3].max, 17);
	}

	#[test]
	fn multiple_ranges() {
		let list = create_multiple_ranges();
		assert_multiple_ranges(&list);
	}

	#[test]
	fn clear() {
		let mut list = create_multiple_ranges();
		list.clear();
		assert_eq!(list.ranges.len(), 0);
	}

	#[test]
	fn serialize() -> Res<()> {
		let list = create_multiple_ranges();
		let mut vec = vec![];
		{
			let mut writer = BEBitWriter::new(&mut vec);
			writer.write(&list)?;
		}
		assert_eq!(vec, DATA);
		Ok(())
	}

	#[test]
	fn deserialize() -> Res<()> {
		let slice = &mut &DATA[..];
		let mut reader = BEBitReader::new(slice);
		let list: RangeList = reader.read()?;
		assert_multiple_ranges(&list);
		Ok(())
	}
}
