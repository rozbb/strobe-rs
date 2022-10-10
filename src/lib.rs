//-------- no_std stuff --------//
#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

// An Error type is just something that's Debug and Display
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl std::error::Error for AuthError {}

//-------- Testing stuff --------//
#[cfg(test)]
mod basic_tests;

// kat_tests requires std
#[cfg(all(test, feature = "std"))]
mod kat_tests;

//-------- Modules and exports--------//

mod keccak;
mod strobe;

pub use crate::strobe::*;
