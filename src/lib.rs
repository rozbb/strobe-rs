#![allow(clippy::needless_doctest_main)]
#![doc = include_str!("../README.md")]
// The doc_auto_cfg feature is only available in nightly. It auto-marks items in documentation as
// dependent on specific features.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
//-------- no_std stuff --------//
#![no_std]

#[cfg(all(test, feature = "std"))]
#[macro_use]
extern crate std;

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

// An Error type is just something that's Debug and Display
impl core::error::Error for AuthError {}
