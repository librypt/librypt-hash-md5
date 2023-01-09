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
        // process complete 512-bit blocks
        for chunk in data.windows(64) {
            let mut A = self.a0;
            let mut B = self.b0;
            let mut C = self.c0;
            let mut D = self.d0;
        }

        // process any leftover data
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
