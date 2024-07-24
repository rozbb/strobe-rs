strobe-rs
=========

[![CI](https://github.com/rozbb/strobe-rs/workflows/CI/badge.svg)](https://github.com/rozbb/strobe-rs/actions)
[![Coverage](https://codecov.io/gh/rozbb/strobe-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/rozbb/strobe-rs)
[![Version](https://img.shields.io/crates/v/strobe-rs.svg)](https://crates.io/crates/strobe-rs)
[![Docs](https://docs.rs/strobe-rs/badge.svg)](https://docs.rs/strobe-rs)

This is a pure Rust, `no_std` implementation of the [Strobe protocol framework][strobe]. It is intended to be used as a library to build other protocols and frameworks. This implementation currently only supports Keccak-f\[1600\] as the internal permutation function, which is the largest possible block size, so big deal.

[strobe]: https://strobe.sourceforge.io/

Example
-------

A simple [program](examples/basic.rs) that does authenticated encryption and decryption:

```rust
use strobe_rs::{SecParam, Strobe};

use rand::RngCore;

// NOTE: This is just a simple authenticated encryption scheme. For a robust AEAD construction,
// see the example at https://strobe.sourceforge.io/examples/aead/

fn main() {
    let mut rng = rand::thread_rng();

    // Sender and receiver
    let mut tx = Strobe::new(b"correctnesstest", SecParam::B256);
    let mut rx = Strobe::new(b"correctnesstest", SecParam::B256);

    // Key both sides with a predetermined key
    let k = b"the-combination-on-my-luggage";
    tx.key(k, false);
    rx.key(k, false);

    // Have the transmitter sample and send a nonce (192 bits) in the clear
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    rx.recv_clr(&nonce, false);
    tx.send_clr(&nonce, false);

    // Have the transmitter send an authenticated ciphertext (with a 256 bit MAC)
    let orig_msg = b"groceries: kaymac, ajvar, cream, diced onion, red pepper, grilled meat";
    let mut msg_buf = *orig_msg;
    tx.send_enc(&mut msg_buf, false);
    let mut mac = [0u8; 32];
    tx.send_mac(&mut mac, false);

    // Rename for clarity. `msg_buf` has been encrypted in-place.
    let mut ciphertext = msg_buf;

    // Have the receiver receive the ciphertext and MAC
    rx.recv_enc(ciphertext.as_mut_slice(), false);
    let res = rx.recv_mac(&mac);

    // Check that the MAC verifies
    assert!(res.is_ok());
    // Check that the decrypted ciphertext equals the original plaintext
    let round_trip_msg = ciphertext;
    assert_eq!(&round_trip_msg, orig_msg);
}
```

Features
--------

Default features flags: [none]

Feature flag list:

* `std` - Implements `std::error::Error` for `AuthError`.
* `serialize_secret_state` - Implements `serde`'s `Serialize` and `Deserialize` traits for the `Strobe` struct. **SECURITY NOTE**: Serializing Strobe state outputs security sensitive data that MUST be kept private. Treat the data as you would a private encryption/decryption key.

For info on how to omit or include feature flags, see the [cargo docs on features](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#choosing-features).

MSRV
----

The current minimum supported Rust version (MSRV) is 1.60.0 (2022-04-04).

Tests
-----

To run tests, execute

    cargo test --all-features

This includes known-answer tests, which test against JSON-encoded test vectors in the [kat/](kat/) directory. To verify these test vectors against the reference Python implementation, `cd` into `kat/`, run `python2 verify_test_vector.py` and follow the included instructions.

Benchmarks
----------

To benchmark, run

    cargo bench

This will produce a summary with plots in `target/crieteron/report/index.html`. These won't be very interesting, since almost every function in  STROBE has the same runtime.

TODO
----

* Contribute an asm impelmentation of Keccak-f\[1600\] to tiny-keccak and expose a feature flag that lets `strobe-rs` users choose which implementation they prefer.

License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Warning
-------

This code has not been audited in any sense of the word. Use at your own discretion.
