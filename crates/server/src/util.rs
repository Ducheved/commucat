use blake3::Hasher;
use std::time::{SystemTime, UNIX_EPOCH};

/// Decodes a hexadecimal string into raw bytes.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, &'static str> {
    if input.len() % 2 != 0 {
        return Err("invalid hex length");
    }
    let mut output = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for chunk in bytes.chunks(2) {
        let high = decode_hex_digit(chunk[0])?;
        let low = decode_hex_digit(chunk[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

/// Decodes a hexadecimal string into a 32-byte array.
pub fn decode_hex32(input: &str) -> Result<[u8; 32], &'static str> {
    let bytes = decode_hex(input)?;
    if bytes.len() != 32 {
        return Err("invalid hex length");
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Encodes raw bytes into hexadecimal representation.
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter() {
        output.push(nibble(byte >> 4));
        output.push(nibble(byte & 0x0f));
    }
    output
}

/// Generates an opaque identifier from entropy and context.
pub fn generate_id(context: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(context.as_bytes());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    hasher.update(&now);
    encode_hex(hasher.finalize().as_bytes())
}

fn decode_hex_digit(digit: u8) -> Result<u8, &'static str> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(10 + digit - b'a'),
        b'A'..=b'F' => Ok(10 + digit - b'A'),
        _ => Err("invalid hex digit"),
    }
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + (value - 10)),
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [1u8, 2, 3, 254];
        let hex = encode_hex(&data);
        let decoded = decode_hex(&hex).unwrap();
        assert_eq!(&decoded, &data);
    }

    #[test]
    fn id_generation_differs() {
        let first = generate_id("context");
        let second = generate_id("context");
        assert_ne!(first, second);
    }
}
