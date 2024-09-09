//! bech32k: KeyURI-specific bech32 encoding/decoding support

/// Minimum length of a bech32k string
pub const MIN_LENGTH: usize = 8;

/// Maximum length of a bech32k string
pub const MAX_LENGTH: usize = 90;

/// bech32k encoding character set (same as bech32)
const CHARSET: [char; 32] = [
    'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0', 's', '3', 'j',
    'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
];

/// Inverse mapping from character codes to CHARSET indexes
const CHARSET_INVERSE: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
    -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1,
    -1, -1, -1, -1,
];

/// bech32k generator coefficients (same as bech32)
const GENERATOR_COEFFICIENTS: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// bech32k-specific separator between URI prefix and encoded data
const SEPARATOR: char = ';';

/// Encode a Bech32k string from a string prefix and binary data
pub fn encode(prefix: &str, data: &[u8]) -> String {
    let base32_data = Base32Converter::Encode.convert(data).unwrap();
    let checksum = Checksum::new(prefix.as_bytes(), &base32_data);
    let data_with_checksum: String = base32_data
        .iter()
        .chain(checksum.as_ref().iter())
        .map(|byte| CHARSET[*byte as usize])
        .collect();

    format!("{}{}{}", prefix, SEPARATOR, data_with_checksum)
}

/// Decode a Bech32k string to a prefix string and binary data
pub fn decode(encoded: &str) -> Result<(String, Vec<u8>), Error> {
    let len: usize = encoded.len();

    if encoded.find(SEPARATOR).is_none() {
        return Err(Error::SeparatorMissing);
    }

    match len {
        MIN_LENGTH..=MAX_LENGTH => (),
        _ => return Err(Error::LengthInvalid),
    }

    let parts: Vec<&str> = encoded.splitn(2, SEPARATOR).collect();

    let prefix = parts[0];
    if prefix.is_empty() {
        return Err(Error::LengthInvalid);
    }

    let data = parts[1];
    if data.len() < 6 {
        return Err(Error::LengthInvalid);
    }

    let mut has_lower: bool = false;
    let mut has_upper: bool = false;
    let mut prefix_bytes = vec![];

    for mut byte in prefix.bytes() {
        match byte {
            33..=126 => (),
            _ => return Err(Error::CharInvalid { byte }),
        }

        match byte {
            b'A'..=b'Z' => {
                has_upper = true;
                byte += b'a' - b'A'
            }
            b'a'..=b'z' => {
                has_lower = true;
            }
            _ => (),
        }

        prefix_bytes.push(byte);
    }

    let mut data_bytes = vec![];

    for mut byte in data.bytes() {
        // Check character validity
        match byte {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => match byte {
                // These characters are not valid
                b'1' | b'B' | b'I' | b'O' | b'b' | b'i' | b'o' => {
                    return Err(Error::CharInvalid { byte })
                }
                _ => (),
            },
            _ => return Err(Error::CharInvalid { byte }),
        }

        // Check for mixed case (otherwise converting upper case to lower case)
        match byte {
            b'A'..=b'Z' => {
                has_upper = true;
                byte += b'a' - b'A';
            }
            b'a'..=b'z' => {
                has_lower = true;
            }
            _ => (),
        }

        data_bytes.push(CHARSET_INVERSE[byte as usize] as u8);
    }

    if has_lower && has_upper {
        return Err(Error::CaseInvalid);
    }

    Checksum::verify(&prefix_bytes, &data_bytes)?;

    let data_bytes_len = data_bytes.len();
    data_bytes.truncate(data_bytes_len - 6);

    Ok((
        String::from_utf8(prefix_bytes).unwrap(),
        Base32Converter::Decode.convert(&data_bytes)?,
    ))
}

/// Checksum value used to verify data integrity
struct Checksum(Vec<u8>);

impl Checksum {
    pub fn new(prefix: &[u8], data: &[u8]) -> Self {
        let mut payload = Self::expand_prefix(prefix);
        payload.extend_from_slice(data);
        payload.extend_from_slice(&[0u8; 6]);

        let pm = Self::polymod(&payload) ^ 1;
        let mut checksum = vec![];

        for p in 0..6 {
            checksum.push(((pm >> (5 * (5 - p))) & 0x1f) as u8);
        }

        Checksum(checksum)
    }

    pub fn verify(prefix: &[u8], data: &[u8]) -> Result<(), Error> {
        let mut exp = Self::expand_prefix(prefix);
        exp.extend_from_slice(data);

        if Self::polymod(&exp) == 1 {
            Ok(())
        } else {
            Err(Error::ChecksumInvalid)
        }
    }

    fn expand_prefix(prefix: &[u8]) -> Vec<u8> {
        let mut v = vec![];

        for b in prefix {
            v.push(*b >> 5);
        }

        v.push(0);

        for b in prefix {
            v.push(*b & 0x1f);
        }

        v
    }

    fn polymod(values: &[u8]) -> u32 {
        let mut result = 1u32;
        let mut b: u8;

        for v in values {
            b = (result >> 25) as u8;
            result = (result & 0x1ff_ffff) << 5 ^ u32::from(*v);

            for (i, coeff) in GENERATOR_COEFFICIENTS.iter().enumerate() {
                if (b >> i) & 1 == 1 {
                    result ^= *coeff
                }
            }
        }

        result
    }
}

impl AsRef<[u8]> for Checksum {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Convert between base32 and "base256"
enum Base32Converter {
    /// Encode into base32
    Encode,

    /// Decode from base32
    Decode,
}

impl Base32Converter {
    fn convert(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let (src, dst) = match *self {
            Base32Converter::Encode => (8, 5),
            Base32Converter::Decode => (5, 8),
        };

        let mut acc = 0u32;
        let mut bits = 0u32;
        let mut result = vec![];
        let max = (1u32 << dst) - 1;

        for value in data {
            let v = u32::from(*value);

            if (v >> src) != 0 {
                return Err(Error::DataInvalid { byte: v as u8 });
            }

            acc = (acc << src) | v;
            bits += src;

            while bits >= dst {
                bits -= dst;
                result.push(((acc >> bits) & max) as u8);
            }
        }

        match *self {
            Base32Converter::Encode => {
                if bits > 0 {
                    result.push(((acc << (dst - bits)) & max) as u8);
                }
            }
            Base32Converter::Decode => {
                if bits >= src || ((acc << (dst - bits)) & max) != 0 {
                    return Err(Error::PaddingInvalid);
                }
            }
        }

        Ok(result)
    }
}

/// Error types for Bech32 encoding / decoding
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    /// KeyURI is missing the ';' character
    #[fail(display = "missing separator character: \";\"")]
    SeparatorMissing,

    /// Checksum for the Bech32 string does not match expected value
    #[fail(display = "checksum mismatch")]
    ChecksumInvalid,

    /// String is too short or long
    #[fail(display = "invalid KeyURI length (min 8, max 90)")]
    LengthInvalid,

    /// Character is not valid
    #[fail(display = "character invalid ({})'", byte)]
    CharInvalid {
        /// Invalid byte
        byte: u8,
    },

    /// Data is not valid
    #[fail(display = "data invalid ({})", byte)]
    DataInvalid {
        /// Invalid byte
        byte: u8,
    },

    /// Padding missing/invalid
    #[fail(display = "padding invalid")]
    PaddingInvalid,

    /// Mixed-case string
    #[fail(display = "string contains mixed-case")]
    CaseInvalid,
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    const EXAMPLE_PREFIX: &str = "example.prefix";
    const EXAMPLE_DATA: &[u8] = &[0, 255, 1, 2, 3, 42, 101];
    const EXAMPLE_ENCODED: &str = "example.prefix;qrlszqsr9fjsjhjw53";

    #[test]
    fn test_beck32k_roundtrip() {
        let encoded = encode(EXAMPLE_PREFIX, EXAMPLE_DATA);
        assert_eq!(encoded, EXAMPLE_ENCODED);

        let (prefix, data) = decode(&encoded).unwrap();
        assert_eq!(prefix, EXAMPLE_PREFIX);
        assert_eq!(data, EXAMPLE_DATA);
    }
}
