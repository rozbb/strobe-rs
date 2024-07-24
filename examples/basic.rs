use strobe_rs::{SecParam, Strobe};

use rand::RngCore;

fn main() {
    let mut rng = rand::thread_rng();

    // Sender and receiver
    let mut tx = Strobe::new(b"correctnesstest", SecParam::B256);
    let mut rx = Strobe::new(b"correctnesstest", SecParam::B256);

    // Key both sides with a predetermined key
    let k = b"the-combination-on-my-luggage";
    tx.key(k, false);
    rx.key(k, false);

    // Have the transmitter sample and send a nonce in the clear
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    rx.recv_clr(&nonce, false);
    tx.send_clr(&nonce, false);

    // Have the transmitter send an authenticated ciphertext
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
