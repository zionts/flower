//! Fixed-error JSON output. No serde/io error boxes or temporary heap strings.
use super::*;
use serde_json::Value;
use std::fmt::Write as _;

pub(super) struct FixedJsonWriter<'a> {
    pub bytes: &'a mut [u8],
    pub used: &'a mut usize,
}
impl FixedJsonWriter<'_> {
    fn append(&mut self, value: &[u8]) -> Result<(), SqlCaptureError> {
        let end = self
            .used
            .checked_add(value.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or(SqlCaptureError::Oversized)?;
        self.bytes[*self.used..end].copy_from_slice(value);
        *self.used = end;
        Ok(())
    }
    pub(super) fn string(&mut self, value: &str) -> Result<(), SqlCaptureError> {
        self.append(b"\"")?;
        // Same CompactFormatter escaping as the locked serde_json serializer:
        // UTF8 passes through; ASCII controls, quote and slash-backslash escape.
        let bytes = value.as_bytes();
        let mut start = 0;
        for (i, &byte) in bytes.iter().enumerate() {
            let escaped: Option<&[u8]> = match byte {
                b'"' => Some(b"\\\""),
                b'\\' => Some(b"\\\\"),
                b'\x08' => Some(b"\\b"),
                b'\x0c' => Some(b"\\f"),
                b'\n' => Some(b"\\n"),
                b'\r' => Some(b"\\r"),
                b'\t' => Some(b"\\t"),
                0..=0x1f => Some(b""),
                _ => None,
            };
            if let Some(escaped) = escaped {
                self.append(&bytes[start..i])?;
                if escaped.is_empty() {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.append(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[(byte >> 4) as usize],
                        HEX[(byte & 15) as usize],
                    ])?;
                } else {
                    self.append(escaped)?;
                }
                start = i + 1;
            }
        }
        self.append(&bytes[start..])?;
        self.append(b"\"")
    }
    pub(super) fn value(
        &mut self,
        value: &Value,
        work: &mut usize,
        depth: usize,
    ) -> Result<(), SqlCaptureError> {
        *work += 1;
        if *work > SQL_CAPTURE_MAX_JSON_NODES || depth > 128 {
            return Err(SqlCaptureError::WorkLimit);
        }
        match value {
            Value::Null => self.append(b"null"),
            Value::Bool(value) => self.append(if *value { b"true" } else { b"false" }),
            Value::Number(value) => {
                // Number::Display in the locked serde_json uses the SAME
                // stack itoa/zmij tokens as Serialize, preserving 1.0/-0.0,
                // signed/u64 extrema and exact native token spelling. Arbitrary
                // precision feature unification cannot widen this 32B bound.
                let mut token = NumberText {
                    bytes: [0; 32],
                    used: 0,
                };
                write!(&mut token, "{value}").map_err(|_| SqlCaptureError::Oversized)?;
                self.append(&token.bytes[..token.used])
            }
            Value::String(value) => self.string(value),
            Value::Array(values) => {
                self.append(b"[")?;
                for (n, value) in values.iter().enumerate() {
                    if n != 0 {
                        self.append(b",")?;
                    }
                    self.value(value, work, depth + 1)?;
                }
                self.append(b"]")
            }
            Value::Object(values) => {
                self.append(b"{")?;
                for (n, (key, value)) in values.iter().enumerate() {
                    if n != 0 {
                        self.append(b",")?;
                    }
                    self.string(key)?;
                    self.append(b":")?;
                    self.value(value, work, depth + 1)?;
                }
                self.append(b"}")
            }
        }
    }
}
struct NumberText {
    bytes: [u8; 32],
    used: usize,
}
impl std::fmt::Write for NumberText {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self
            .used
            .checked_add(value.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or(std::fmt::Error)?;
        self.bytes[self.used..end].copy_from_slice(value.as_bytes());
        self.used = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_capture_json_matches_locked_serde_for_escapes_numbers_nested_and_errors() {
        for text in [
            "null",
            "true",
            "false",
            "0",
            "1.0",
            "-0.0",
            "-9223372036854775808",
            "18446744073709551615",
            "5e-324",
            "1.7976931348623157e308",
            "[null,true,{\"n\":1.0,\"u\":18446744073709551615}]",
        ] {
            let value: Value = serde_json::from_str(text).unwrap();
            let expected = serde_json::to_vec(&value).unwrap();
            let mut bytes = [0u8; 1024];
            let mut used = 0;
            FixedJsonWriter {
                bytes: &mut bytes,
                used: &mut used,
            }
            .value(&value, &mut 0, 0)
            .unwrap();
            assert_eq!(&bytes[..used], expected.as_slice(), "{text}");
        }
        let controls: String = (0..=0x7f)
            .map(char::from)
            .chain("東京🌸\u{80}\u{9f}".chars())
            .collect();
        let expected = serde_json::to_vec(&controls).unwrap();
        let mut bytes = [0u8; 1024];
        let mut used = 0;
        FixedJsonWriter {
            bytes: &mut bytes,
            used: &mut used,
        }
        .string(&controls)
        .unwrap();
        assert_eq!(&bytes[..used], expected.as_slice());
        let mut tiny = [0u8; 1];
        let mut used = 0;
        assert_eq!(
            FixedJsonWriter {
                bytes: &mut tiny,
                used: &mut used
            }
            .string("x"),
            Err(SqlCaptureError::Oversized)
        );
    }
}
