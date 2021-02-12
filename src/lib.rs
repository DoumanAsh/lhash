//!Minimal `no_std` hashing library
//!
//!## Provided Algorithms
//!
//!These are also names of features to be used to include algorithm code.
//!
//!- `sha1`
//!- `md5`
//!
//!It also includes generic hmac implementation

#![no_std]
#![warn(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

///Hashing algorithm interface
pub trait Digest {
    ///Output type
    type OutputType: AsRef<[u8]> + AsMut<[u8]> + Copy;
    ///Block type
    type BlockType: AsRef<[u8]> + AsMut<[u8]> + Copy;

    ///Creates new instance.
    fn new() -> Self;
    ///Resets algorithm's state.
    fn reset(&mut self);
    ///Hashes input
    fn update(&mut self, input: &[u8]);
    ///Finalizes algorithm and returns output.
    fn result(&mut self) -> Self::OutputType;
}

///Creates HMAC using provided `Digest` algorithm.
///
///- `input` - Data to hash.
///- `secret` - Data to derive HMAC's key.
pub fn hmac<D: Digest>(input: &[u8], secret: &[u8]) -> D::OutputType {
    let mut key: D::BlockType = unsafe {
        core::mem::MaybeUninit::zeroed().assume_init()
    };
    let key = key.as_mut();

    if secret.len() <= key.len() {
        key[..secret.len()].copy_from_slice(secret);
    } else {
        let mut hash = D::new();
        hash.update(secret);
        let hash = hash.result();
        let hash = hash.as_ref();
        key[..hash.len()].copy_from_slice(hash);
    }

    let mut inner = D::new();
    let mut outer = D::new();

    for byte in key.iter_mut() {
        *byte ^= 0x36;
    }
    inner.update(key);

    for byte in key.iter_mut() {
        *byte ^= 0x36 ^ 0x5C;
    }
    outer.update(key);

    inner.update(input);
    outer.update(inner.result().as_ref());
    outer.result()
}

///Wrapper to hex format digest
///
///```
///use lhash::sha1;
///
///let hash = format!("{}", lhash::DigestFmt(sha1(b"lolka")));
///assert_eq!(hash, "96b83283e86b889f6dc07d52d1f1806fe70f5488");
///```
pub struct DigestFmt<T>(pub T);

impl<T: AsRef<[u8]>> core::fmt::Display for DigestFmt<T> {
    #[inline(always)]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byt in self.0.as_ref() {
            f.write_fmt(format_args!("{:02x}", byt))?;
        }
        Ok(())
    }
}

#[cfg(feature = "sha1")]
mod sha1;
#[cfg(feature = "sha1")]
pub use sha1::{sha1, Sha1};
#[cfg(feature = "md5")]
mod md5;
#[cfg(feature = "md5")]
pub use md5::{md5, Md5};
