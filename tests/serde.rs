#![cfg(feature = "serialize_secret_state")]

use serde_json;
use strobe_rs::{SecParam, Strobe};

// Serializes and immediately deserializes a Strobe state. Should be equivalent to the identity
// function. The tests below make sure of that.
fn do_round_trip(s: &Strobe) -> Strobe {
    // Serialize the Strobe state to bytes
    let b = serde_json::to_vec(&s).unwrap();
    println!("{}", serde_json::to_string(&s).unwrap());

    // Deserialize the Strobe state from bytes
    let s: Strobe = serde_json::from_slice(&b).unwrap();

    s
}

// An arbitrary sequence of STROBE operations
fn do_seq() -> Strobe {
    let mut s = Strobe::new(b"seqtest", SecParam::B256);

    let mut buf = [0u8; 10];
    s.prf(&mut buf[..], false);

    s.ad(b"Hello", false);

    let mut buf = b"World".to_vec();
    s.send_enc(buf.as_mut_slice(), false);

    s.send_clr(b"foo", false);
    s.ratchet(32, false);
    s.recv_clr(b"bar", false);

    let mut buf = b"baz".to_vec();
    s.recv_enc(buf.as_mut_slice(), false);

    for i in 0..100 {
        let mut buf = vec![b'X'; i];
        s.send_enc(buf.as_mut_slice(), false);
    }

    let mut buf = [0u8; 123];
    s.prf(&mut buf[..], false);

    let mut buf = [0u8; 16];
    s.send_mac(&mut buf[..], false);

    s
}

fn do_seq_rt() -> Strobe {
    let mut s = Strobe::new(b"seqtest", SecParam::B256);

    let mut buf = [0u8; 10];
    s.prf(&mut buf[..], false);

    s.ad(b"Hello", false);

    let mut buf = b"World".to_vec();
    s.send_enc(buf.as_mut_slice(), false);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    s.send_clr(b"foo", false);
    s.ratchet(32, false);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    s.recv_clr(b"bar", false);

    // continue...
    let mut buf = b"baz".to_vec();
    s.recv_enc(buf.as_mut_slice(), false);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    for i in 0..100 {
        let mut buf = vec![b'X'; i];
        s.send_enc(buf.as_mut_slice(), false);
    }

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    let mut buf = [0u8; 123];
    s.prf(&mut buf[..], false);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    let mut buf = [0u8; 16];
    s.send_mac(&mut buf[..], false);

    s
}

#[test]
fn test_seq() {
    let seq = serde_json::to_vec(&do_seq()).unwrap();
    let seq_rt = serde_json::to_vec(&do_seq_rt()).unwrap();
    assert_eq!(&seq[..], &seq_rt[..]);
}

fn do_metadata() -> (Vec<u8>, Strobe) {
    // We will accumulate output over 3 operations and 3 meta-operations
    let mut s = Strobe::new(b"metadatatest", SecParam::B256);
    let mut output = Vec::new();

    let buf = b"meta1";
    s.meta_send_clr(buf, false);
    output.extend_from_slice(buf);

    // This does not output anything
    s.key(b"key", false);

    let mut buf = [0u8; 10];
    s.meta_prf(&mut buf, false);
    output.extend_from_slice(&buf[..]);

    // We don't have to re-zero the buffer. Our internal special-casing for PRF does this for us
    s.prf(&mut buf, false);
    output.extend_from_slice(&buf[..]);

    let buf = b"meta3";
    s.meta_send_clr(buf, false);
    output.extend(buf);

    let mut buf = b"pt".to_vec();
    s.send_enc(buf.as_mut_slice(), false);
    output.extend(buf);

    (output, s)
}

fn do_metadata_rt() -> (Vec<u8>, Strobe) {
    // We will accumulate output over 3 operations and 3 meta-operations
    let mut s = Strobe::new(b"metadatatest", SecParam::B256);
    let mut output = Vec::new();

    let buf = b"meta1";
    s.meta_send_clr(buf, false);
    output.extend_from_slice(buf);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    // This does not output anything
    s.key(b"key", false);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    let mut buf = [0u8; 10];
    s.meta_prf(&mut buf, false);
    output.extend_from_slice(&buf[..]);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    // We don't have to re-zero the buffer. Our internal special-casing for PRF does this for us
    s.prf(&mut buf, false);
    output.extend_from_slice(&buf[..]);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    let buf = b"meta3";
    s.meta_send_clr(buf, false);
    output.extend(buf);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    let mut buf = b"pt".to_vec();
    s.send_enc(buf.as_mut_slice(), false);
    output.extend(buf);

    (output, s)
}

#[test]
fn test_metadata() {
    let (output, meta) = do_metadata();
    let (output_rt, meta_rt) = do_metadata_rt();

    let m = serde_json::to_vec(&meta).unwrap();
    let m_rt = serde_json::to_vec(&meta_rt).unwrap();

    assert_eq!(&output[..], &output_rt[..]);
    assert_eq!(&m[..], &m_rt[..]);
}

fn do_long_inputs() -> Strobe {
    let mut s = Strobe::new(b"bigtest", SecParam::B256);
    const BIG_N: usize = 9823;
    let big_data = [0x34; BIG_N];

    s.meta_ad(&big_data[..], false);
    s.ad(&big_data[..], false);
    s.meta_key(&big_data[..], false);
    s.key(&big_data[..], false);
    s.meta_send_clr(&big_data[..], false);
    s.send_clr(&big_data[..], false);
    s.meta_recv_clr(&big_data[..], false);
    s.recv_clr(&big_data[..], false);

    s.meta_send_enc(big_data.to_vec().as_mut_slice(), false);
    s.send_enc(big_data.to_vec().as_mut_slice(), false);
    s.meta_recv_enc(big_data.to_vec().as_mut_slice(), false);
    s.recv_enc(big_data.to_vec().as_mut_slice(), false);
    let _ = s.meta_recv_mac(big_data.to_vec().as_mut_slice());
    let _ = s.recv_mac(big_data.to_vec().as_mut_slice());

    let mut big_buf = [0u8; BIG_N];

    s.meta_ratchet(BIG_N, false);
    s.ratchet(BIG_N, false);
    s.meta_prf(&mut big_buf, false);
    s.prf(&mut big_buf, false);
    s.meta_send_mac(&mut big_buf, false);
    s.send_mac(&mut big_buf, false);

    s
}

fn do_long_inputs_rt() -> Strobe {
    let mut s = Strobe::new(b"bigtest", SecParam::B256);
    const BIG_N: usize = 9823;
    let big_data = [0x34; BIG_N];

    s.meta_ad(&big_data[..], false);
    s.ad(&big_data[..], false);
    s.meta_key(&big_data[..], false);
    s.key(&big_data[..], false);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    s.meta_send_clr(&big_data[..], false);
    s.send_clr(&big_data[..], false);
    s.meta_recv_clr(&big_data[..], false);
    s.recv_clr(&big_data[..], false);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    s.meta_send_enc(big_data.to_vec().as_mut_slice(), false);
    s.send_enc(big_data.to_vec().as_mut_slice(), false);
    s.meta_recv_enc(big_data.to_vec().as_mut_slice(), false);
    s.recv_enc(big_data.to_vec().as_mut_slice(), false);
    let _ = s.meta_recv_mac(big_data.to_vec().as_mut_slice());
    let _ = s.recv_mac(big_data.to_vec().as_mut_slice());

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    let mut big_buf = [0u8; BIG_N];

    s.meta_ratchet(BIG_N, false);
    s.ratchet(BIG_N, false);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    s.meta_prf(&mut big_buf, false);
    s.prf(&mut big_buf, false);
    s.meta_send_mac(&mut big_buf, false);

    // SERDE ROUND TRIP
    let mut s = do_round_trip(&s);

    s.send_mac(&mut big_buf, false);

    s
}

#[test]
fn test_long_inputs() {
    let li = serde_json::to_vec(&do_long_inputs()).unwrap();
    let li_rt = serde_json::to_vec(&do_long_inputs_rt()).unwrap();
    assert_eq!(&li[..], &li_rt[..]);
}

fn do_streaming() -> (Strobe, Strobe) {
    // Compute a few things without breaking up their inputs
    let one_shot = {
        let mut s = Strobe::new(b"streamingtest", SecParam::B256);

        s.ad(b"mynonce", false);

        let mut buf = b"hello there".to_vec();
        s.recv_enc(buf.as_mut_slice(), false);

        let mut mac = [0u8; 16];
        s.send_mac(&mut mac[..], false);

        s.ratchet(13, false);

        s
    };
    // Now do the same thing but stream the inputs
    let streamed = {
        let mut s = Strobe::new(b"streamingtest", SecParam::B256);

        s.ad(b"my", false);
        s.ad(b"nonce", true);

        let mut buf = b"hello".to_vec();
        s.recv_enc(buf.as_mut_slice(), false);

        let mut buf = b" there".to_vec();
        s.recv_enc(buf.as_mut_slice(), true);

        let mut mac = [0u8; 16];
        s.send_mac(&mut mac[..10], false);
        s.send_mac(&mut mac[10..], true);

        s.ratchet(10, false);
        s.ratchet(3, true);

        s
    };

    (one_shot, streamed)
}

fn do_streaming_rt() -> (Strobe, Strobe) {
    // Compute a few things without breaking up their inputs
    let one_shot = {
        let mut s = Strobe::new(b"streamingtest", SecParam::B256);

        s.ad(b"mynonce", false);

        // SERDE ROUND TRIP
        let mut s = do_round_trip(&s);

        let mut buf = b"hello there".to_vec();
        s.recv_enc(buf.as_mut_slice(), false);

        // SERDE ROUND TRIP
        let mut s = do_round_trip(&s);

        let mut mac = [0u8; 16];
        s.send_mac(&mut mac[..], false);

        // SERDE ROUND TRIP
        let mut s = do_round_trip(&s);

        s.ratchet(13, false);

        // SERDE ROUND TRIP
        do_round_trip(&s)
    };
    // Now do the same thing but stream the inputs
    let streamed = {
        let mut s = Strobe::new(b"streamingtest", SecParam::B256);

        s.ad(b"my", false);

        // SERDE ROUND TRIP
        let mut s = do_round_trip(&s);

        s.ad(b"nonce", true);

        let mut buf = b"hello".to_vec();
        s.recv_enc(buf.as_mut_slice(), false);

        // SERDE ROUND TRIP
        let mut s = do_round_trip(&s);

        let mut buf = b" there".to_vec();
        s.recv_enc(buf.as_mut_slice(), true);

        // SERDE ROUND TRIP
        let mut s = do_round_trip(&s);

        let mut mac = [0u8; 16];
        s.send_mac(&mut mac[..10], false);

        // SERDE ROUND TRIP
        let mut s = do_round_trip(&s);

        s.send_mac(&mut mac[10..], true);

        s.ratchet(10, false);

        // SERDE ROUND TRIP
        let mut s = do_round_trip(&s);

        s.ratchet(3, true);

        // SERDE ROUND TRIP
        do_round_trip(&s)
    };

    (one_shot, streamed)
}

// Test that streaming in data using the `more` flag works as expected
#[test]
fn test_streaming_correctness() {
    let (one_shot, streamed) = do_streaming();
    let (one_shot_rt, streamed_rt) = do_streaming_rt();

    let os = serde_json::to_vec(&one_shot).unwrap();
    let os_rt = serde_json::to_vec(&one_shot_rt).unwrap();

    let s = serde_json::to_vec(&streamed).unwrap();
    let s_rt = serde_json::to_vec(&streamed_rt).unwrap();

    assert_eq!(&os[..], &os_rt[..]);
    assert_eq!(&s[..], &s_rt[..]);
}

fn do_enc_correctness(msg: &[u8]) -> Vec<u8> {
    let mut tx = Strobe::new(b"enccorrectnesstest", SecParam::B256);
    let mut rx = Strobe::new(b"enccorrectnesstest", SecParam::B256);

    tx.key(b"the-combination-on-my-luggage", false);
    rx.key(b"the-combination-on-my-luggage", false);

    // Encrypt and decrypt the original message
    let mut buf = msg.to_vec();
    tx.send_enc(buf.as_mut_slice(), false);
    rx.recv_enc(buf.as_mut_slice(), false);

    buf
}

fn do_enc_correctness_rt(msg: &[u8]) -> Vec<u8> {
    let mut tx = Strobe::new(b"enccorrectnesstest", SecParam::B256);
    let mut rx = Strobe::new(b"enccorrectnesstest", SecParam::B256);

    tx.key(b"the-combination-on-my-luggage", false);

    // SERDE ROUND TRIP
    let mut tx = do_round_trip(&tx);

    rx.key(b"the-combination-on-my-luggage", false);

    // SERDE ROUND TRIP
    let mut rx = do_round_trip(&rx);

    // Encrypt and decrypt the original message
    let mut buf = msg.to_vec();
    tx.send_enc(buf.as_mut_slice(), false);
    rx.recv_enc(buf.as_mut_slice(), false);

    buf
}

// Test that decrypt(encrypt(msg)) == msg
#[test]
fn test_enc_correctness_round_trip() {
    let orig_msg = b"Hello there";
    let msg = do_enc_correctness(orig_msg);
    let msg_rt = do_enc_correctness_rt(orig_msg);

    assert_eq!(orig_msg, msg.as_slice());
    assert_eq!(orig_msg, msg_rt.as_slice());
}

// Test that recv_mac(send_mac()) doesn't error, and recv_mac(otherstuff) does error
#[test]
fn test_mac_correctness_and_soundness() {
    let mut tx = Strobe::new(b"mactest", SecParam::B256);
    let mut rx = Strobe::new(b"mactest", SecParam::B256);

    // Just do some stuff with the state

    tx.key(b"secretsauce", false);
    let mut msg = b"attack at dawn".to_vec();
    tx.send_enc(msg.as_mut_slice(), false);

    let mut mac = [0u8; 16];
    tx.send_mac(&mut mac[..], false);

    // Deserialize the rx side upon receiving an encrypted message and decrypt...
    rx.key(b"secretsauce", false);
    rx.recv_enc(&mut msg[..], false);

    // Test that valid MACs are accepted
    let mut rx_copy = rx.clone();
    let good_res = rx_copy.recv_mac(&mut mac[..]);
    assert!(good_res.is_ok());

    // Test that invalid MACs are rejected
    let mut bad_mac = {
        let mut tmp = mac.to_vec();
        tmp.push(0);
        tmp
    };
    let bad_res = rx.recv_mac(&mut bad_mac[..]);
    assert!(bad_res.is_err());
}

// Test that recv_mac(send_mac()) doesn't error, and recv_mac(otherstuff) does error
// with round trips
#[test]
fn test_mac_correctness_and_soundness_rt() {
    let mut tx = Strobe::new(b"mactest", SecParam::B256);
    let rx = Strobe::new(b"mactest", SecParam::B256);

    // Serialize the rx side...
    let rx_sleep = serde_json::to_vec(&rx).unwrap();

    // Just do some stuff with the state

    tx.key(b"secretsauce", false);
    let mut msg = b"attack at dawn".to_vec();
    tx.send_enc(msg.as_mut_slice(), false);

    let mut mac = [0u8; 16];
    tx.send_mac(&mut mac[..], false);

    // Deserialize the rx side upon receiving an encrypted message and decrypt...
    let mut rx: Strobe = serde_json::from_slice(&rx_sleep).unwrap();
    rx.key(b"secretsauce", false);
    rx.recv_enc(&mut msg[..], false);

    // Serialize the rx side again
    let rx_sleep = serde_json::to_vec(&rx).unwrap();

    // Create two identical strobe states from one serialized Strobe state
    let mut rx1: Strobe = serde_json::from_slice(&rx_sleep).unwrap();
    let mut rx2: Strobe = serde_json::from_slice(&rx_sleep).unwrap();

    // Test that valid MACs are accepted
    let good_res = rx1.recv_mac(&mut mac[..]);
    assert!(good_res.is_ok());

    // Test that invalid MACs are rejected
    let mut bad_mac = {
        let mut tmp = mac.to_vec();
        tmp.push(0);
        tmp
    };
    let bad_res = rx2.recv_mac(&mut bad_mac[..]);
    assert!(bad_res.is_err());
}
