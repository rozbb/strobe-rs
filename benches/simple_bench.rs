#![feature(test)]

extern crate strobe_rs;
extern crate test;

use test::Bencher;

use strobe_rs::{SecParam, Strobe};

#[bench]
fn simple_bench(b: &mut Bencher) {
    let mut s = Strobe::new(b"simplebench", SecParam::B256);
    b.iter(|| {
        let mut v = [0u8; 256];
        s.send_enc(&mut v, false);
        s.recv_enc(&mut v, false);
    });
}
