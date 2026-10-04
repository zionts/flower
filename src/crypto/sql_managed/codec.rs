//! Fixed-slice canonical unpadded base64url and finite compact-JWT framing.
use super::{Control, Error, MAX_TOKEN_BYTES};
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
fn sextet(byte: u8) -> Result<u8, Error> {
    Ok(match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return Err(Error::Invalid),
    })
}
/// Validate canonical spelling without decoding/copying a ciphertext buffer.
pub(super) fn validated_len(input: &[u8], control: &Control<'_>) -> Result<usize, Error> {
    control.check()?;
    if input.len() > MAX_TOKEN_BYTES || input.len() % 4 == 1 {
        return Err(Error::Invalid);
    }
    for chunk in input.chunks(1024) {
        control.debit(chunk.len())?;
        for byte in chunk {
            sextet(*byte)?;
        }
    }
    match input.len() % 4 {
        2 if sextet(input[input.len() - 1])? & 15 != 0 => return Err(Error::Invalid),
        3 if sextet(input[input.len() - 1])? & 3 != 0 => return Err(Error::Invalid),
        _ => (),
    }
    control.check()?;
    Ok(input.len() / 4 * 3
        + match input.len() % 4 {
            2 => 1,
            3 => 2,
            _ => 0,
        })
}
pub(super) fn decode(
    input: &[u8],
    output: &mut [u8],
    control: &Control<'_>,
) -> Result<usize, Error> {
    control.check()?;
    if input.len() > MAX_TOKEN_BYTES || input.len() % 4 == 1 {
        return Err(Error::Invalid);
    }
    let len = input.len() / 4 * 3
        + match input.len() % 4 {
            2 => 1,
            3 => 2,
            _ => 0,
        };
    if len > output.len() {
        return Err(Error::Capacity);
    }
    let mut read = 0;
    let mut written = 0;
    while read + 4 <= input.len() {
        if read.is_multiple_of(1024) {
            control.debit((input.len() - read).min(1024))?;
        }
        let a = sextet(input[read])?;
        let b = sextet(input[read + 1])?;
        let c = sextet(input[read + 2])?;
        let d = sextet(input[read + 3])?;
        output[written] = a << 2 | b >> 4;
        output[written + 1] = b << 4 | c >> 2;
        output[written + 2] = c << 6 | d;
        read += 4;
        written += 3;
    }
    let tail = input.len() - read;
    if tail > 0 {
        if read.is_multiple_of(1024) {
            control.debit(tail)?;
        }
        let a = sextet(input[read])?;
        let b = sextet(input[read + 1])?;
        output[written] = a << 2 | b >> 4;
        written += 1;
        if tail == 2 {
            if b & 15 != 0 {
                return Err(Error::Invalid);
            }
        } else {
            let c = sextet(input[read + 2])?;
            if c & 3 != 0 {
                return Err(Error::Invalid);
            }
            output[written] = b << 4 | c >> 2;
            written += 1;
        }
    }
    control.check()?;
    Ok(written)
}
pub(super) fn encode(
    input: &[u8],
    output: &mut [u8],
    control: &Control<'_>,
) -> Result<usize, Error> {
    control.check()?;
    if input.len() > MAX_TOKEN_BYTES {
        return Err(Error::Capacity);
    }
    let len = input.len() / 3 * 4
        + match input.len() % 3 {
            1 => 2,
            2 => 3,
            _ => 0,
        };
    if len > output.len() {
        return Err(Error::Capacity);
    }
    let mut read = 0;
    let mut written = 0;
    while read + 3 <= input.len() {
        // 768 input bytes -> 1024 output bytes; bounded cancellation interval.
        if read.is_multiple_of(768) {
            control.debit((input.len() - read).min(768))?;
        }
        let a = input[read];
        let b = input[read + 1];
        let c = input[read + 2];
        output[written] = ALPHABET[(a >> 2) as usize];
        output[written + 1] = ALPHABET[((a & 3) << 4 | b >> 4) as usize];
        output[written + 2] = ALPHABET[((b & 15) << 2 | c >> 6) as usize];
        output[written + 3] = ALPHABET[(c & 63) as usize];
        read += 3;
        written += 4;
    }
    if read < input.len() {
        if read.is_multiple_of(768) {
            control.debit(input.len() - read)?;
        }
        let a = input[read];
        output[written] = ALPHABET[(a >> 2) as usize];
        output[written + 1] = ALPHABET[((a & 3) << 4) as usize];
        written += 2;
        if read + 1 < input.len() {
            let b = input[read + 1];
            output[written - 1] = ALPHABET[((a & 3) << 4 | b >> 4) as usize];
            output[written] = ALPHABET[((b & 15) << 2) as usize];
            written += 1;
        }
    }
    control.check()?;
    Ok(written)
}
pub(super) struct Parts<'a> {
    pub header: &'a [u8],
    pub claims: &'a [u8],
    pub signature: &'a [u8],
    pub message: &'a [u8],
}
pub(super) fn parts<'a>(token: &'a [u8], control: &Control<'_>) -> Result<Parts<'a>, Error> {
    control.check()?;
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Error::Capacity);
    }
    let mut first = None;
    let mut second = None;
    for (i, byte) in token.iter().enumerate() {
        if i.is_multiple_of(1024) {
            control.debit((token.len() - i).min(1024))?;
        }
        if *byte == b'.' {
            if first.is_none() {
                first = Some(i);
            } else if second.is_none() {
                second = Some(i);
            } else {
                return Err(Error::Invalid);
            }
        }
    }
    let first = first.ok_or(Error::Invalid)?;
    let second = second.ok_or(Error::Invalid)?;
    if first == 0 || second <= first + 1 || second + 1 >= token.len() {
        return Err(Error::Invalid);
    }
    Ok(Parts {
        header: &token[..first],
        claims: &token[first + 1..second],
        signature: &token[second + 1..],
        message: &token[..second],
    })
}
pub(super) struct Writer<'a, 'c> {
    output: &'a mut [u8],
    len: usize,
    control: &'c Control<'c>,
}
impl<'a, 'c> Writer<'a, 'c> {
    pub(super) fn new(output: &'a mut [u8], control: &'c Control<'c>) -> Self {
        Self {
            output,
            len: 0,
            control,
        }
    }
    pub(super) fn len(&self) -> usize {
        self.len
    }
    pub(super) fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.len.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        if end > self.output.len() {
            return Err(Error::Capacity);
        }
        for chunk in bytes.chunks(1024) {
            self.control.debit(chunk.len())?;
            self.output[self.len..self.len + chunk.len()].copy_from_slice(chunk);
            self.len += chunk.len();
        }
        Ok(())
    }
    pub(super) fn integer(&mut self, mut number: u64) -> Result<(), Error> {
        let mut digits = [0; 20];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (number % 10) as u8;
            number /= 10;
            if number == 0 {
                break;
            }
        }
        self.bytes(&digits[at..])
    }
    pub(super) fn quoted(&mut self, text: &str) -> Result<(), Error> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.bytes(b"\"")?;
        for byte in text.bytes() {
            match byte {
                b'"' => self.bytes(b"\\\"")?,
                b'\\' => self.bytes(b"\\\\")?,
                0..=31 => self.bytes(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[(byte >> 4) as usize],
                    HEX[(byte & 15) as usize],
                ])?,
                _ => self.bytes(&[byte])?,
            }
        }
        self.bytes(b"\"")
    }
}
