use thiserror::Error;
use winnow::{
    binary::bits::{Bits, take},
    token::rest,
};

const MAP: [u8; 64] = [
    b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P',
    b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', //
    b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p',
    b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z', //
    b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'-', b'_',
];

#[derive(Debug, Error, PartialEq)]
pub enum DecodeError {
    #[error("unexpected char '{0}'")]
    UnexpectedChar(char),
    #[error("not ascii")]
    NotAscii,
}

#[allow(dead_code)]
pub fn encode(input: &[u8]) -> String {
    use winnow::Parser as _;

    let mut res = String::with_capacity(input.len() * 2);

    let mut input = Bits(input, 0);
    while let Ok((bits, rest)) = (take::<_, u8, _, ()>(6usize), rest).parse(input) {
        input = Bits(rest.0, rest.1);
        res.push(MAP[bits as usize] as char);
    }
    if input.1 == 4 {
        let mut r: u8 = take::<_, _, _, ()>(4usize).parse(input).unwrap();
        r <<= 2;
        res.push(MAP[r as usize] as char);
        res.push('=');
    } else if input.1 == 6 {
        let mut r: u8 = take::<_, _, _, ()>(2usize).parse(input).unwrap();
        r <<= 4;
        res.push(MAP[r as usize] as char);
        res.push_str("==");
    } else {
        debug_assert!(input.1 == 0);
    }

    res
}

pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
    let mut res = Vec::with_capacity(input.len());

    if !input.is_ascii() {
        return Err(DecodeError::NotAscii);
    }
    let input = input.trim_end_matches('=');
    let input = input.as_bytes();

    let input = input
        .iter()
        .map(|i| {
            Ok(u8::try_from(
                MAP.iter()
                    .position(|m| i == m)
                    .ok_or(DecodeError::UnexpectedChar(*i as char))?,
            )
            .unwrap())
        })
        .collect::<Result<Vec<u8>, DecodeError>>()?;

    for chunk in input.chunks(4) {
        if chunk.len() >= 2 {
            res.push(chunk[0] << 2 | chunk[1] >> 4);
        }
        if chunk.len() >= 3 {
            res.push(chunk[1] << 4 | chunk[2] >> 2);
        }
        if chunk.len() >= 4 {
            res.push(chunk[2] << 6 | chunk[3]);
        }
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(encode(b"Man"), "TWFu");
        assert_eq!(encode(b"Ma"), "TWE=");
        assert_eq!(encode(b"M"), "TQ==");
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode("bGlnaHQgd29y"), Ok("light wor".as_bytes().to_vec()));
        assert_eq!(decode("bGlnaHQgd28="), Ok("light wo".as_bytes().to_vec()));
        assert_eq!(decode("bGlnaHQgdw=="), Ok("light w".as_bytes().to_vec()));
    }
}
