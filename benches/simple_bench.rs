#![feature(test)]

extern crate strobe_rs;
extern crate test;

use test::Bencher;

use strobe_rs::{SecParam, Strobe};

#[bench]
fn simple_bench(b: &mut Bencher) {
    let mut s = Strobe::new(b"simplebench".to_vec(), SecParam::B256);
    b.iter(|| {
        let mut v = vec![0u8; 256];
        v = s.send_enc(v, None, false);
        s.recv_enc(v, None, false)
    });
}
