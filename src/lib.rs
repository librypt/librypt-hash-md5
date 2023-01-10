use librypt_hash::{Hash, HashFn};

/// MD5 hash function.
///
/// WARNING: MD5 is [cryptographically broken and should be avoided](https://www.kb.cert.org/vuls/id/836068).
#[deprecated(note = "For legacy purposes only. See documentation for more information.")]
pub struct Md5 {
    // MD5 hasher state
    a0: u32,
    b0: u32,
    c0: u32,
    d0: u32,
}

impl Md5 {
    pub const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    pub const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    pub const A0: u32 = 0x67452301;
    pub const B0: u32 = 0xefcdab89;
    pub const C0: u32 = 0x98badcfe;
    pub const D0: u32 = 0x10325476;
}

impl Md5 {
    /// Expects a chunk of exactly 512-bits (64 bytes).
    fn compute(&mut self, chunk: &[u8; 64]) {
        let mut A = self.a0;
        let mut B = self.b0;
        let mut C = self.c0;
        let mut D = self.d0;

        let mut words = [0u32; 16];

        for (i, word) in chunk.chunks(4).enumerate() {
            words[i] = u32::from_le_bytes(word.try_into().unwrap());
        }

        for i in 0..64 {
            let mut f = 0u32;
            let mut g = 0u32;

            if 0 <= i && i <= 15 {
                f = (B & C) | ((!B) & D);
                g = i;
            } else if 16 <= i && i <= 31 {
                f = (D & B) | ((!D) & C);
                g = (5 * i + 1) % 16;
            } else if 32 <= i && i <= 47 {
                f = B ^ C ^ D;
                g = (3 * i + 5) % 16;
            } else if 48 <= i && i <= 63 {
                f = C ^ (B | (!D));
                g = (7 * i) % 16;
            }

            f = f.wrapping_add(A.wrapping_add(Self::K[i as usize].wrapping_add(words[g as usize])));
            A = D;
            D = C;
            C = B;
            B = B.wrapping_add(f.rotate_left(Self::S[i as usize]));
        }

        self.a0 = self.a0.wrapping_add(A);
        self.b0 = self.b0.wrapping_add(B);
        self.c0 = self.c0.wrapping_add(C);
        self.d0 = self.d0.wrapping_add(D);
    }
}

impl HashFn<64, 16> for Md5 {
    fn new() -> Self {
        Self {
            a0: Self::A0,
            b0: Self::B0,
            c0: Self::C0,
            d0: Self::D0,
        }
    }

    /// TODO: Finish this function.
    fn update(&mut self, data: &[u8]) {
        let data_len = data.len();
        let mut blocks = 0;

        // process complete 512-bit blocks
        for chunk in data.windows(64) {
            self.compute(chunk.try_into().unwrap());
            blocks += 1;
        }

        println!("Blocks: {blocks}");

        // determine remaining data
        let data = &data[blocks * 64..];

        if data.len() > 56 {
            let mut block = [0u8; 64];

            block[0..data.len()].copy_from_slice(data);
            block[data.len()] = 0x80;

            self.compute(&block);

            // compute padding block
            let mut block = [0u8; 64];

            block[56..64].copy_from_slice(&data_len.to_le_bytes());

            self.compute(&block);
        } else {
            let mut block = [0u8; 64];

            println!("Remaining: {}", data.len());

            block[0..data.len()].copy_from_slice(data);
            block[data.len()] = 0x80;

            block[56..64].copy_from_slice(&data_len.to_le_bytes());

            println!("{block:?}");

            self.compute(&block);
        }
    }

    fn finalize(self) -> Hash<16> {
        let mut hash = [0u8; 16];

        hash[0..4].copy_from_slice(&self.a0.to_le_bytes());
        hash[4..8].copy_from_slice(&self.b0.to_le_bytes());
        hash[8..12].copy_from_slice(&self.c0.to_le_bytes());
        hash[12..16].copy_from_slice(&self.d0.to_le_bytes());

        hash
    }

    fn finalize_reset(&mut self) -> Hash<16> {
        let mut hash = [0u8; 16];

        hash[0..4].copy_from_slice(&self.a0.to_le_bytes());
        hash[4..8].copy_from_slice(&self.b0.to_le_bytes());
        hash[8..12].copy_from_slice(&self.c0.to_le_bytes());
        hash[12..16].copy_from_slice(&self.d0.to_le_bytes());

        // reset state
        self.a0 = Self::A0;
        self.b0 = Self::B0;
        self.c0 = Self::C0;
        self.d0 = Self::D0;

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_hash() {
        let input = String::from("Hello, world!").into_bytes();
        let hash = Md5::hash(&input);

        println!("Hash: {}", hash.encode_hex::<String>());
    }
}
