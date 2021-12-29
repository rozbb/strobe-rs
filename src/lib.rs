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

//-------- Modules and exports--------//

mod keccak;
mod prelude;
mod strobe;

pub use crate::strobe::*;
