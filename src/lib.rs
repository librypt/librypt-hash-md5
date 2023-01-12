use librypt_hash::{Hash, HashFn};

/// MD5 hash function.
///
/// WARNING: MD5 is [cryptographically broken and unsuitable for further use](https://www.kb.cert.org/vuls/id/836068).
pub struct Md5 {
    total: u64,
    state: [u32; 4],
    buffer: (usize, [u8; 64]),
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

    pub const STATE: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
}

impl Md5 {
    fn compute(&mut self) {
        let chunk = &self.buffer.1;

        let mut state = self.state;
        let mut words = [0u32; 16];

        for (i, word) in chunk.chunks(4).enumerate() {
            words[i] = u32::from_le_bytes(word.try_into().unwrap());
        }

        for i in 0..64 {
            let mut f;
            let g;

            if i < 16 {
                f = (state[1] & state[2]) | ((!state[1]) & state[3]);
                g = i;
            } else if i < 32 {
                f = (state[3] & state[1]) | ((!state[3]) & state[2]);
                g = (5 * i + 1) % 16;
            } else if i < 48 {
                f = state[1] ^ state[2] ^ state[3];
                g = (3 * i + 5) % 16;
            } else {
                f = state[2] ^ (state[1] | (!state[3]));
                g = (7 * i) % 16;
            }

            f = f
                .wrapping_add(state[0])
                .wrapping_add(Self::K[i as usize])
                .wrapping_add(words[g as usize])
                .rotate_left(Self::S[i as usize]);

            state[0] = state[3];
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[1].wrapping_add(f);
        }

        for i in 0..4 {
            self.state[i] = self.state[i].wrapping_add(state[i]);
        }
    }

    fn compute_padded(&mut self) {
        self.buffer.1[self.buffer.0] = 0x80;

        if self.buffer.0 > 55 {
            for i in self.buffer.0 + 1..64 {
                self.buffer.1[i] = 0;
            }

            self.compute();

            self.buffer.0 = 0;
        }

        for i in self.buffer.0 + 1..56 {
            self.buffer.1[i] = 0;
        }

        self.buffer.1[56..64].copy_from_slice(&(self.total * 8).to_le_bytes());

        self.compute();
    }
}

impl HashFn<64, 16> for Md5 {
    fn new() -> Self {
        Self {
            total: 0,
            state: Self::STATE,
            buffer: (0, [0u8; 64]),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total += data.len() as u64;

        for i in 0..data.len() {
            self.buffer.1[self.buffer.0] = data[i];
            self.buffer.0 += 1;

            if self.buffer.0 == 64 {
                self.compute();
                self.buffer.0 = 0;
            }
        }
    }

    fn finalize(mut self) -> Hash<16> {
        self.compute_padded();

        let mut hash = [0u8; 16];

        for i in 0..4 {
            hash[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_le_bytes());
        }

        hash
    }

    fn finalize_reset(&mut self) -> Hash<16> {
        self.compute_padded();

        let mut hash = [0u8; 16];

        for i in 0..4 {
            hash[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_le_bytes());
        }

        // reset state
        self.total = 0;
        self.state = Self::STATE;
        self.buffer = (0, [0u8; 64]);

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_hash() {
        let hash = Md5::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "6cd3556deb0da54bca060b4c39479839"
        );
    }
}
