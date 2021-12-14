//-------- no_std stuff --------//
#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

//-------- Testing stuff --------//

#[cfg(test)]
mod basic_tests;

// kat_tests requires std and also serde. This is a proc macro so we still need extern crate
#[cfg(all(test, feature = "std"))]
#[macro_use]
extern crate serde_derive;

// kat_tests requires std
#[cfg(all(test, feature = "std"))]
mod kat_tests;

// serde_tests requires serde
#[cfg(all(test, feature = "serde"))]
mod serde_tests;

//-------- Modules and exports--------//

mod keccak;
mod prelude;
mod strobe;

pub use crate::strobe::*;
