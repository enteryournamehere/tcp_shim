use std::io::Result as Res;
use std::mem::size_of;
use std::ops::{BitOrAssign, Shl};

use endio::{Deserialize, LERead, LEWrite, LittleEndian, Serialize};
use endio_bit::{BEBitReader, BEBitWriter};

/// A "compressed" integer. This struct only wraps the inner type, the actual functionality is in the Serialize and Deserialize impls.
pub struct Compressed<T>(pub T);

/// Serializes the value, see the `Deserialize` impl for details.
impl<W: std::io::Write> Serialize<LittleEndian, BEBitWriter<W>> for Compressed<u16> {
	fn serialize(self, writer: &mut BEBitWriter<W>) -> Res<()> {
		let size = size_of::<Self>();
		for i in 0..size - 1 {
			let zero = (self.0 >> (8 * (size - 1 - i))) & 0xff == 0;
			writer.write_bit(zero)?;
			if !zero {
				for j in 0..(size - i) {
					writer.write((self.0 >> (8 * j)) as u8)?;
				}
				return Ok(());
			}
		}

		let zero = self.0 & 0xf0 == 0;
		writer.write_bit(zero)?;
		if zero {
			writer.write_bits((self.0 & 0x0f) as u8, 4)?;
		} else {
			writer.write(self.0 as u8)?;
		}
		Ok(())
	}
}

/// Serializes the value, see the `Deserialize` impl for details.
impl<W: std::io::Write> Serialize<LittleEndian, BEBitWriter<W>> for Compressed<u32> {
	fn serialize(self, writer: &mut BEBitWriter<W>) -> Res<()> {
		let size = size_of::<Self>();
		for i in 0..size - 1 {
			let zero = (self.0 >> (8 * (size - 1 - i))) & 0xff == 0;
			writer.write_bit(zero)?;
			if !zero {
				for j in 0..(size - i) {
					writer.write((self.0 >> (8 * j)) as u8)?;
				}
				return Ok(());
			}
		}

		let zero = self.0 & 0xf0 == 0;
		writer.write_bit(zero)?;
		if zero {
			writer.write_bits((self.0 & 0x0f) as u8, 4)?;
		} else {
			writer.write(self.0 as u8)?;
		}
		Ok(())
	}
}
/**
	Deserializes the value.

	The compression works based on the fact that most of the time the values are small enough not to need all the bytes of the binary representation. Each byte from high to the second lowest is encoded as a bit, 1 if the entire byte is 0, and 0 if not. If the bit is 0, the remaining bytes are read from low to high (!). The lowest byte also has a bit, but it encodes whether the upper half byte is 0 or not. If it is 0, the lowest 8 bits are read, if not, the lower 4 bits are read.
*/
impl<T, R: std::io::Read> Deserialize<LittleEndian, BEBitReader<R>> for Compressed<T>
where
	T: From<u8> + BitOrAssign<<T as Shl>::Output> + Shl + Default,
{
	fn deserialize(reader: &mut BEBitReader<R>) -> Res<Self> {
		let size = size_of::<Self>() as u8;
		for i in 0..size - 1 {
			if reader.read_bit()? {
				continue;
			}
			let mut res = T::default();
			for j in i..size {
				res |= T::from(reader.read::<u8>()?) << T::from(8 * j);
			}
			return Ok(Compressed(res));
		}

		Ok(Compressed::<T>(T::from(if reader.read_bit()? {
			reader.read_bits(4)?
		} else {
			reader.read::<u8>()?
		})))
	}
}

impl From<Compressed<u16>> for u16 {
	fn from(com: Compressed<u16>) -> Self {
		com.0
	}
}

impl From<Compressed<u32>> for u32 {
	fn from(com: Compressed<u32>) -> Self {
		com.0
	}
}

#[cfg(test)]
mod tests {
	use super::Compressed;
	use endio::{LERead, LEWrite};
	use endio_bit::{BEBitReader, BEBitWriter};

	#[test]
	fn read_comp_u16_small() {
		let b = &mut &b"\xf8"[..];
		let mut reader = BEBitReader::new(b);
		let v: Compressed<u16> = reader.read().unwrap();
		assert_eq!(u16::from(v), 14);
	}

	#[test]
	fn read_comp_u16_large() {
		let b = &mut &b"\x33\xdd\x80"[..];
		let mut reader = BEBitReader::new(b);
		let v: Compressed<u16> = reader.read().unwrap();
		assert_eq!(u16::from(v), 47975);
	}

	#[test]
	fn write_comp_u16_small() {
		let mut vec = vec![];
		{
			let mut writer = BEBitWriter::new(&mut vec);
			writer.write(Compressed::<u16>(14)).unwrap();
		}
		assert_eq!(vec, b"\xf8");
	}

	#[test]
	fn write_comp_u16_large() {
		let mut vec = vec![];
		{
			let mut writer = BEBitWriter::new(&mut vec);
			writer.write(Compressed::<u16>(47975u16)).unwrap();
		}
		assert_eq!(vec, b"\x33\xdd\x80");
	}

	#[test]
	fn read_comp_u32_small() {
		let b = &mut &b"\xfe"[..];
		let mut reader = BEBitReader::new(b);
		let v: Compressed<u32> = reader.read().unwrap();
		assert_eq!(u32::from(v), 14);
	}

	#[test]
	fn read_comp_u32_large() {
		let b = &mut &b"\x29\x43\x7f\xf4\x80"[..];
		let mut reader = BEBitReader::new(b);
		let v: Compressed<u32> = reader.read().unwrap();
		assert_eq!(u32::from(v), 3925837394);
	}

	#[test]
	fn write_comp_u32_small() {
		let mut vec = vec![];
		{
			let mut writer = BEBitWriter::new(&mut vec);
			writer.write(Compressed::<u32>(14)).unwrap();
		}
		assert_eq!(vec, b"\xfe");
	}

	#[test]
	fn write_comp_u32_large() {
		let mut vec = vec![];
		{
			let mut writer = BEBitWriter::new(&mut vec);
			writer.write(Compressed::<u32>(3925837394)).unwrap();
		}
		assert_eq!(vec, b"\x29\x43\x7f\xf4\x80");
	}
}
