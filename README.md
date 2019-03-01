strobe-rs
=========

[![Build Status](https://travis-ci.org/rozbb/strobe-rs.svg?branch=master)](https://travis-ci.org/rozbb/strobe-rs)
[![Version](https://img.shields.io/crates/v/strobe-rs.svg)](https://crates.io/crates/strobe-rs)
[![Docs](https://docs.rs/strobe-rs/badge.svg)](https://docs.rs/strobe-rs)

This is a relatively barebones implementation of the [Strobe protocol framework][strobe] in pure
Rust. It is intended to be used as a library to build other protocols and frameworks. This
implementation currently only supports Keccak-f\[1600\] as the internal permutation function, which
is the largest possible block size, so big deal.

[strobe]: https://strobe.sourceforge.io/

Example
-------

A simple [program](examples/basic.rs) that encrypts and decrypts a message:

```rust
use strobe_rs::{SecParam, Strobe};

fn main() {
    let mut rx = Strobe::new(b"correctnesstest", SecParam::B256);
    let mut tx = Strobe::new(b"correctnesstest", SecParam::B256);

    rx.key(b"the-combination-on-my-luggage", false);
    tx.key(b"the-combination-on-my-luggage", false);

    let mut msg = b"Attack at dawn".to_vec();
    rx.send_enc(msg.as_mut_slice(), false);

    // Rename for clarity. `msg` has been encrypted in-place.
    let mut ciphertext = msg;

    tx.recv_enc(ciphertext.as_mut_slice(), false);

    // And back again.
    let round_trip_msg = ciphertext;

    assert_eq!(&round_trip_msg, b"Attack at dawn");
}
```

TODO
----

* Add benchmarks
* Contribute an asm impelmentation of Keccak-f\[1600\] to tiny-keccak and expose a feature flag that
  lets `strobe-rs` users choose which implementation they prefer.
* Put more asserts in the code like the Python implementation does. Not sure if this is a great idea
  though

License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Warning
-------

This code has not been audited in any sense of the word. Use at your own discretion.
