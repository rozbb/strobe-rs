//-------- no_std stuff --------//
#![no_std]
#![cfg_attr(not(feature="std"), feature(alloc))]

#[cfg(feature="std")]
#[macro_use] extern crate std;

#[cfg(not(feature="std"))]
#[macro_use] extern crate alloc;

//-------- Testing stuff --------//

// kat_tests requires std. These are its deps
#[cfg(all(test, feature="std"))]
extern crate hex;
#[cfg(all(test, feature="std"))]
extern crate serde;
#[cfg(all(test, feature="std"))]
extern crate serde_json;
#[cfg(all(test, feature="std"))]
#[macro_use] extern crate serde_derive;

#[cfg(test)]
mod basic_tests;

// kat_tests requires std
#[cfg(all(test, feature="std"))]
mod kat_tests;

//-------- Normal deps --------//

#[macro_use] extern crate bitflags;
extern crate byteorder;
extern crate subtle;
extern crate tiny_keccak;

//-------- Modules and exports--------//

mod keccak;
mod prelude;
mod strobe;

pub use strobe::*;
