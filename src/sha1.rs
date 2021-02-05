const BLOCK_SIZE: usize = 64;
const STATE_SIZE: usize = 5;

const INIT_STATE: [u32; STATE_SIZE] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

macro_rules! W {
    ($w:expr, $i:expr) => {{
        $w[$i] = ($w[$i - 3] ^ $w[$i - 8] ^ $w[$i - 14] ^ $w[$i - 16]).rotate_left(1);
        $w[$i]
    }}
}

macro_rules! R1 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr, $block:expr, $i:expr) => {
        let idx = $i * 4;
        $w[$i] = u32::from_be_bytes([$block[idx], $block[idx + 1], $block[idx + 2], $block[idx + 3]]);

        let f = ($b & $c) | (!$b & $d);

        $e = $e.wrapping_add($a.rotate_left(5).wrapping_add(f).wrapping_add(0x5A827999).wrapping_add($w[$i]));
        $b = $b.rotate_left(30);
    }
}

macro_rules! R2 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr, $i:expr) => {
        let f = ($b & $c) | (!$b & $d);

        $e = $e.wrapping_add($a.rotate_left(5).wrapping_add(f).wrapping_add(0x5A827999).wrapping_add(W!($w, $i)));
        $b = $b.rotate_left(30);
    }
}

macro_rules! R3 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr, $i:expr) => {
        let f = $b ^ $c ^ $d;

        $e = $e.wrapping_add($a.rotate_left(5).wrapping_add(f).wrapping_add(0x6ED9EBA1).wrapping_add(W!($w, $i)));
        $b = $b.rotate_left(30);
    }
}

macro_rules! R4 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr, $i:expr) => {
        let f = ($b & $c) | ($b & $d) | ($c & $d);

        $e = $e.wrapping_add($a.rotate_left(5).wrapping_add(f).wrapping_add(0x8F1BBCDC).wrapping_add(W!($w, $i)));
        $b = $b.rotate_left(30);
    }
}

macro_rules! R5 {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr, $i:expr) => {
        let f = $b ^ $c ^ $d;

        $e = $e.wrapping_add($a.rotate_left(5).wrapping_add(f).wrapping_add(0xCA62C1D6).wrapping_add(W!($w, $i)));
        $b = $b.rotate_left(30);
    }
}

///`SHA-1` algorithm implementation
pub struct Sha1 {
    state: [u32; STATE_SIZE],
    len: u64,
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
}

impl Sha1 {
    const RESULT_SIZE: usize = 20;
    const BLOCK_SIZE: usize = BLOCK_SIZE;

    ///New default instance.
    pub const fn new() -> Self {
        Self {
            state: INIT_STATE,
            len: 0,
            buffer: [0; BLOCK_SIZE],
            buffer_len: 0
        }
    }

    fn transform(&mut self, block: [u8; BLOCK_SIZE]) {
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        let mut w = [0u32; 80];

        R1!(a, b, c, d, e, w, block,  0);
        R1!(e, a, b, c, d, w, block,  1);
        R1!(d, e, a, b, c, w, block,  2);
        R1!(c, d, e, a, b, w, block,  3);
        R1!(b, c, d, e, a, w, block,  4);
        R1!(a, b, c, d, e, w, block,  5);
        R1!(e, a, b, c, d, w, block,  6);
        R1!(d, e, a, b, c, w, block,  7);
        R1!(c, d, e, a, b, w, block,  8);
        R1!(b, c, d, e, a, w, block,  9);
        R1!(a, b, c, d, e, w, block, 10);
        R1!(e, a, b, c, d, w, block, 11);
        R1!(d, e, a, b, c, w, block, 12);
        R1!(c, d, e, a, b, w, block, 13);
        R1!(b, c, d, e, a, w, block, 14);
        R1!(a, b, c, d, e, w, block, 15);

        R2!(e, a, b, c, d, w, 16);
        R2!(d, e, a, b, c, w, 17);
        R2!(c, d, e, a, b, w, 18);
        R2!(b, c, d, e, a, w, 19);

        R3!(a, b, c, d, e, w, 20);
        R3!(e, a, b, c, d, w, 21);
        R3!(d, e, a, b, c, w, 22);
        R3!(c, d, e, a, b, w, 23);
        R3!(b, c, d, e, a, w, 24);
        R3!(a, b, c, d, e, w, 25);
        R3!(e, a, b, c, d, w, 26);
        R3!(d, e, a, b, c, w, 27);
        R3!(c, d, e, a, b, w, 28);
        R3!(b, c, d, e, a, w, 29);
        R3!(a, b, c, d, e, w, 30);
        R3!(e, a, b, c, d, w, 31);
        R3!(d, e, a, b, c, w, 32);
        R3!(c, d, e, a, b, w, 33);
        R3!(b, c, d, e, a, w, 34);
        R3!(a, b, c, d, e, w, 35);
        R3!(e, a, b, c, d, w, 36);
        R3!(d, e, a, b, c, w, 37);
        R3!(c, d, e, a, b, w, 38);
        R3!(b, c, d, e, a, w, 39);

        R4!(a, b, c, d, e, w, 40);
        R4!(e, a, b, c, d, w, 41);
        R4!(d, e, a, b, c, w, 42);
        R4!(c, d, e, a, b, w, 43);
        R4!(b, c, d, e, a, w, 44);
        R4!(a, b, c, d, e, w, 45);
        R4!(e, a, b, c, d, w, 46);
        R4!(d, e, a, b, c, w, 47);
        R4!(c, d, e, a, b, w, 48);
        R4!(b, c, d, e, a, w, 49);
        R4!(a, b, c, d, e, w, 50);
        R4!(e, a, b, c, d, w, 51);
        R4!(d, e, a, b, c, w, 52);
        R4!(c, d, e, a, b, w, 53);
        R4!(b, c, d, e, a, w, 54);
        R4!(a, b, c, d, e, w, 55);
        R4!(e, a, b, c, d, w, 56);
        R4!(d, e, a, b, c, w, 57);
        R4!(c, d, e, a, b, w, 58);
        R4!(b, c, d, e, a, w, 59);

        R5!(a, b, c, d, e, w, 60);
        R5!(e, a, b, c, d, w, 61);
        R5!(d, e, a, b, c, w, 62);
        R5!(c, d, e, a, b, w, 63);
        R5!(b, c, d, e, a, w, 64);
        R5!(a, b, c, d, e, w, 65);
        R5!(e, a, b, c, d, w, 66);
        R5!(d, e, a, b, c, w, 67);
        R5!(c, d, e, a, b, w, 68);
        R5!(b, c, d, e, a, w, 69);
        R5!(a, b, c, d, e, w, 70);
        R5!(e, a, b, c, d, w, 71);
        R5!(d, e, a, b, c, w, 72);
        R5!(c, d, e, a, b, w, 73);
        R5!(b, c, d, e, a, w, 74);
        R5!(a, b, c, d, e, w, 75);
        R5!(e, a, b, c, d, w, 76);
        R5!(d, e, a, b, c, w, 77);
        R5!(c, d, e, a, b, w, 78);
        R5!(b, c, d, e, a, w, 79);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    ///Resets algorithm's state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    ///Hashes input
    pub fn update(&mut self, mut input: &[u8]) {
        if input.len() == 0 {
            return;
        }

        self.len += input.len() as u64;

        if self.buffer_len > 0 {
            let mut k = BLOCK_SIZE - self.buffer_len;

            if input.len() < k {
                k = input.len();
            }

            let (to_copy, remain) = input.split_at(k);
            input = remain;
            self.buffer[self.buffer_len..][..k].copy_from_slice(to_copy);
            self.buffer_len += k;

            if self.buffer_len < BLOCK_SIZE {
                return;
            }

            self.transform(self.buffer);
            self.buffer_len = 0;
        }

        while input.len() > BLOCK_SIZE {
            self.transform(unsafe {
                *(input.as_ptr() as *const [u8; BLOCK_SIZE])
            });
            input = &input[BLOCK_SIZE..];
        }

        if input.len() > 0 {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    ///Finalizes algorithm and returns output.
    pub fn result(&mut self) -> [u8; Self::RESULT_SIZE] {
        const PADDING: [u8; BLOCK_SIZE] = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let bits = (self.len * 8).to_be_bytes();
        let k = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };

        self.update(&PADDING[..k]);
        self.update(&bits);

        debug_assert_eq!(self.buffer_len, 0);

        let a = self.state[0].to_be_bytes();
        let b = self.state[1].to_be_bytes();
        let c = self.state[2].to_be_bytes();
        let d = self.state[3].to_be_bytes();
        let e = self.state[4].to_be_bytes();
        [
            a[0], a[1], a[2], a[3],
            b[0], b[1], b[2], b[3],
            c[0], c[1], c[2], c[3],
            d[0], d[1], d[2], d[3],
            e[0], e[1], e[2], e[3],
        ]
    }
}

define_hmac!(HmacSha1, Sha1);

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::string::String;

    use super::*;

    fn sha_to_hex(input: [u8; 20]) -> String {
        use core::fmt::Write;

        let mut result = String::new();
        for byt in input.iter() {
            let _ = write!(result, "{:02x}", byt);
        }
        result
    }

    #[test]
    fn test_simple() {
        let tests = [
            ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            ("The quick brown fox jumps over the lazy dog",
             "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
            ("The quick brown fox jumps over the lazy cog",
             "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
            ("testing\n", "9801739daae44ec5293d4e1f53d3f4d2d426d91c"),
            ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "025ecbd5d70f8fb3c5457cd96bab13fda305dc59"),
            ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "4300320394f7ee239bcdce7d3b8bcee173a0cd5c"),
            ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "cef734ba81a024479e09eb5a75b6ddae62e6abf1"),
        ];

        let mut sha = Sha1::new();
        for (data, ref expected) in tests.iter() {
            let data = data.as_bytes();

            sha.update(data);
            let hash = sha_to_hex(sha.result());

            assert_eq!(hash.len(), hash.len());
            assert_eq!(hash, *expected);

            sha.reset();
        }
    }

    #[cfg(feature = "hmac")]
    #[test]
    fn test_hmac() {
        let tests: [(&'static [u8], &'static [u8], &'static str); 8] = [
            (b"", b"", "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"),
            (b"key", b"The quick brown fox jumps over the lazy dog", "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"),
            (b"Jefe", b"what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
            (&[0xAA; 20], &[0xDD; 50], "125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
            (&[0x0B; 20], b"Hi There", "b617318655057264e28bc0b6fb378c8ef146be00"),
            (&[0x0C; 20], b"Test With Truncation", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"),
            (&[0xAA; 80], b"Test Using Larger Than Block-Size Key - Hash Key First", "aa4ae5e15272d00e95705637ce8a3b55ed402112"),
            (&[0xAA; 80], b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"),
        ];

        for (key, data, ref expected) in tests.iter() {
            let mut hmac = HmacSha1::new(key);
            hmac.update(data);
            let hash = sha_to_hex(hmac.result());

            assert_eq!(hash.len(), hash.len());
            assert_eq!(hash, *expected);
        }
    }
}
