//! Minimal hashing library

#![no_std]
#![warn(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

#[cfg(feature = "sha1")]
mod sha1;
#[cfg(feature = "sha1")]
pub use sha1::Sha1;
