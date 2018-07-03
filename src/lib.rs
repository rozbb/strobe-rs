//-------- no_std stuff --------//
#![no_std]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(feature = "std")]
#[macro_use] extern crate std;

#[cfg(not(feature = "std"))]
#[macro_use] extern crate alloc;

//-------- Testing stuff --------//

#[cfg(test)]
extern crate hex;
#[cfg(test)]
extern crate serde;
#[cfg(test)]
extern crate serde_json;
#[cfg(test)]
#[macro_use] extern crate serde_derive;

#[cfg(test)]
mod basic_tests;

#[cfg(test)]
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
