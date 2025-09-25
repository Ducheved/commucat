use std::fmt::Write;

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{:02x}", byte);
    }
    output
}

pub fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let expected_len = N * 2;
    if value.len() != expected_len {
        return Err(format!(
            "invalid hex length {}; expected {}",
            value.len(),
            expected_len
        ));
    }
    let mut output = [0u8; N];
    let bytes = value.as_bytes();
    for idx in 0..N {
        let hi = parse_nibble(bytes[idx * 2])?;
        let lo = parse_nibble(bytes[idx * 2 + 1])?;
        output[idx] = (hi << 4) | lo;
    }
    Ok(output)
}

fn parse_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", value as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let data = [0u8, 1, 2, 254, 255];
        let encoded = encode_hex(&data);
        assert_eq!(encoded, "000102feff");
        let decoded: [u8; 5] = decode_hex_array(&encoded).expect("decode");
        assert_eq!(decoded, data);
    }
}
