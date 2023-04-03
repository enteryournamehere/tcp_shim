/*!
	Traits for working with LU's fixed string format.

	LU's fixed string format is exactly 33 bytes, consisting of string data, followed by a null terminator, with anything afterwards ignored.

	The encoding of the string is not completely clear, only ascii-range has been observed so far. To keep things simple Rust's standard utf8 methods are used.
*/
use std::io;
use std::io::ErrorKind::InvalidData;
use std::io::Result as Res;
use std::io::Write;

/// A trait to be implemented to allow reading.
pub trait ReadStr {
	/// Reads a LU fixed string.
	fn read_fix(&mut self) -> Res<&str>;
}

/// A trait to be implemented to allow writing.
pub trait WriteStr {
	/// Writes a LU fixed string.
	fn write_fix(&mut self, s: &str) -> Res<()>;
}

impl ReadStr for &[u8] {
	fn read_fix(&mut self) -> Res<&str> {
		let (a, b) = self.split_at(33);
		let terminator = match a.iter().position(|&x| x == 0) {
			Some(i) => i,
			None => return Err(io::Error::new(InvalidData, "no null terminator")),
		};
		match std::str::from_utf8(&a[..terminator]) {
			Ok(x) => {
				*self = b;
				Ok(x)
			}
			Err(_) => Err(io::Error::new(InvalidData, "not valid utf8")),
		}
	}
}

impl<W: Write> WriteStr for W {
	fn write_fix(&mut self, s: &str) -> Res<()> {
		let bytes = s.as_bytes();
		let len = bytes.len();
		if len > 32 {
			return Err(io::Error::new(InvalidData, "str too long"));
		}
		self.write(bytes)?;
		self.write(&vec![0; 33 - len])?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::{ReadStr, WriteStr};
	use std::io::ErrorKind::InvalidData;

	#[test]
	fn read_long() {
		let bytes = b"a thirty-two bytes long str test\0";
		let mut reader = &bytes[..];
		let read = reader.read_fix().unwrap();
		assert_eq!(read, "a thirty-two bytes long str test");
		assert_eq!(reader, b"");
	}

	#[test]
	fn read_short() {
		let bytes = b"short\0garbage garbage garbage \xff\xff\xff";
		let mut reader = &bytes[..];
		let read = reader.read_fix().unwrap();
		assert_eq!(read, "short");
		assert_eq!(reader, b"");
	}

	#[test]
	#[should_panic]
	fn read_eof() {
		let bytes = b"content\0garbage";
		let mut reader = &bytes[..];
		let _ = reader.read_fix();
	}

	#[test]
	fn read_no_null() {
		let bytes = b" a string without null terminator";
		let mut reader = &bytes[..];
		let err = reader.read_fix().unwrap_err();
		assert_eq!(err.kind(), InvalidData);
	}

	#[test]
	fn read_invalid_utf8() {
		let bytes = b"\xff\xff\xff\xff\xff\0garbage garbage garbage gar";
		let mut reader = &bytes[..];
		let err = reader.read_fix().unwrap_err();
		assert_eq!(err.kind(), InvalidData);
	}

	#[test]
	fn write_long() {
		let mut vec = vec![];
		vec.write_fix("a thirty-two bytes long str test").unwrap();
		assert_eq!(vec, &b"a thirty-two bytes long str test\0"[..]);
	}

	#[test]
	fn write_short() {
		let mut vec = vec![];
		vec.write_fix("short").unwrap();
		assert_eq!(
			vec,
			&b"short\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..]
		);
	}

	#[test]
	fn write_too_long() {
		let mut vec = vec![];
		let err = vec.write_fix("😂😂😂😂😂😂😂😂😂").unwrap_err();
		assert!(vec.is_empty());
		assert_eq!(err.kind(), InvalidData);
	}
}
