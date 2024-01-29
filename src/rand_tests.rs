//! tests for the `rand` feature

use crate::{SecParam, Strobe, StrobeRng};
use rand::{Rng, rngs::OsRng};

#[derive(Debug, Default)]
struct Key([u8; 32]);

fn random_key<R: Rng>(rng: &mut R) -> Key {
    let mut key: Key = Default::default();
    rng.fill(key.0.as_mut_slice());
    key
}

#[test]
fn from_strobe() {
    let mut t = Strobe::new(b"StrobeRng test", SecParam::B128);
    let key = random_key(&mut OsRng);
    t.key(&key.0, false);
    let zero = [0u8; 128];
    let mut rng: StrobeRng = t.into();
    let mut output = zero.clone();
    rng.fill(&mut output);
    assert!(output != zero);
}
