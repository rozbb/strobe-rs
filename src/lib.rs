#![no_std]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[macro_use] extern crate bitflags;
extern crate byteorder;
extern crate subtle;
extern crate tiny_keccak;

mod keccak;
mod prelude;
mod strobe;

pub use strobe::*;
