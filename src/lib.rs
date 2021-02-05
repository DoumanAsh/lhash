//! Minimal hashing library

#![no_std]
#![warn(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

#[cfg(feature = "hmac")]
#[allow(unused)]
///Creates HMAC algorithm based on provided hashing `algorithm` from the crate.
macro_rules! define_hmac {
    ($name:ident, $algo:path) => {
        ///HMAC algorithm
        pub struct $name {
            outer: $algo,
            inner: $algo,
        }

        impl $name {
            ///Creates new instance with provided `secret`, used to create key.
            pub fn new(secret: &[u8]) -> Self {
                let mut key = [0u8; <$algo>::BLOCK_SIZE];

                if secret.len() <= <$algo>::BLOCK_SIZE {
                    key[..secret.len()].copy_from_slice(secret);
                } else {
                    let mut hash = <$algo>::new();
                    hash.update(secret);
                    let hash = hash.result();
                    key[..hash.len()].copy_from_slice(&hash);
                }

                let mut result = Self {
                    outer: <$algo>::new(),
                    inner: <$algo>::new(),
                };

                for idx in 0..key.len() {
                    key[idx] = key[idx] ^ 0x36;
                }

                result.inner.update(&key);

                for idx in 0..key.len() {
                    key[idx] = key[idx] ^ 0x36 ^ 0x5C;
                }

                result.outer.update(&key);

                result
            }

            #[inline]
            ///Resets algorithm's state.
            pub fn reset(&mut self) {
                self.inner.reset();
                self.outer.reset();
            }

            #[inline]
            ///Hashes input
            pub fn update(&mut self, input: &[u8]) {
                self.inner.update(input);
            }

            ///Finalizes algorithm and returns output.
            pub fn result(&mut self) -> [u8; <$algo>::RESULT_SIZE] {
                self.outer.update(&self.inner.result());
                self.outer.result()
            }
        }
    }
}

#[cfg(not(feature = "hmac"))]
#[allow(unused)]
macro_rules! define_hmac {
    ($name:ident, $algo:path) => {
    }
}

#[cfg(feature = "sha1")]
mod sha1;
#[cfg(feature = "sha1")]
pub use sha1::{Sha1};
#[cfg(all(feature = "sha1", feature = "hmac"))]
pub use sha1::{HmacSha1};

#[cfg(feature = "md5")]
mod md5;
#[cfg(feature = "md5")]
pub use md5::{Md5};
#[cfg(all(feature = "md5", feature = "hmac"))]
pub use md5::{HmacMd5};
