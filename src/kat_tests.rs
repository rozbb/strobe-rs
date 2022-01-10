use crate::{
    prelude::*,
    strobe::{SecParam, Strobe},
};

use std::{boxed::Box, fs::File, path::Path};

use hex;
use serde::{de::Error as SError, Deserialize, Deserializer};
use serde_json;

// This is the top-level structure of the JSON we find in the test vectors
#[derive(Deserialize)]
struct TestHead {
    proto_string: String,
    #[serde(deserialize_with = "sec_param_from_bits")]
    security: SecParam,
    operations: Vec<TestOp>,
}

// Each individual test case looks like this
#[derive(Deserialize)]
struct TestOp {
    name: String,
    meta: bool,
    #[serde(default, deserialize_with = "bytes_from_hex_opt")]
    input_data: Option<Vec<u8>>,
    #[serde(default)]
    input_length: Option<usize>,
    stream: bool,
    #[serde(default, rename = "output", deserialize_with = "bytes_from_hex_opt")]
    expected_output: Option<Vec<u8>>,
    #[serde(default, rename = "state_after", deserialize_with = "bytes_from_hex")]
    expected_state_after: Vec<u8>,
}

// Tells serde how to deserialize a `SecParam`
fn sec_param_from_bits<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SecParam, D::Error>
where
    D: Deserializer<'de>,
{
    let b = u64::deserialize(deserializer)?;
    match b {
        128 => Ok(SecParam::B128),
        256 => Ok(SecParam::B256),
        n => Err(SError::custom(format!("Invalid security parameter: {}", n))),
    }
}

// Tells serde how to deserialize bytes from hex
fn bytes_from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut hex_str = String::deserialize(deserializer)?;
    // Prepend a 0 if it's not even length
    if hex_str.len() % 2 == 1 {
        hex_str.insert(0, '0');
    }
    hex::decode(hex_str).map_err(|e| SError::custom(format!("{:?}", e)))
}

// This function is a formality. Some fields are not present, so they're wrapped in Option in the
// above structs. Hence, the deserialization function must return an Option. The `default` pragma
// on the members ensures, however, that the value is None when the field is missing.
fn bytes_from_hex_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    bytes_from_hex(deserializer).map(Some)
}

// Recall that `ratchet` can take a length argument, so this is the most general type that
// represents the input to a STROBE operation
enum DataOrLength {
    Data(Vec<u8>),
    Length(usize),
}

impl DataOrLength {
    fn get_data(&self) -> &[u8] {
        match self {
            DataOrLength::Data(d) => d.as_slice(),
            _ => panic!("cannot get data from a length field"),
        }
    }
}

// Given the name of the operation and meta flag, returns a closure that performs this operation.
// The types are kind of a mess, because the input and output types of the closure have to fit all
// possible STROBE operations.
fn get_op(op_name: String, meta: bool) -> Box<dyn Fn(&mut Strobe, &mut DataOrLength, bool)> {
    let f = move |s: &mut Strobe, dol: &mut DataOrLength, more: bool| {
        let data = match dol {
            DataOrLength::Length(len) => {
                match (meta, op_name.as_str()) {
                    (false, "RATCHET") => s.ratchet(*len, more),
                    (true, "RATCHET") => s.meta_ratchet(*len, more),
                    (_, o) => panic!("Got length input without RATCHET op: {}", o),
                }
                return;
            }
            DataOrLength::Data(ref mut data) => data,
        };

        // Note: we don't expect recv_MAC to work on random inputs. We test recv_MAC's
        // correctness in strobe.rs
        if !meta {
            match op_name.as_str() {
                "AD" => s.ad(data, more),
                "KEY" => s.key(data, more),
                "PRF" => s.prf(data, more),
                "send_CLR" => s.send_clr(data, more),
                "recv_CLR" => s.recv_clr(data, more),
                "send_ENC" => s.send_enc(data, more),
                "recv_ENC" => s.recv_enc(data, more),
                "send_MAC" => s.send_mac(data, more),
                "recv_MAC" => s.recv_mac(data).unwrap_or(()),
                "RATCHET" => panic!("Got RATCHET op without length input"),
                _ => panic!("Unexpected op name: {}", op_name),
            }
        } else {
            match op_name.as_str() {
                "AD" => s.meta_ad(data, more),
                "KEY" => s.meta_key(data, more),
                "PRF" => s.meta_prf(data, more),
                "send_CLR" => s.meta_send_clr(data, more),
                "recv_CLR" => s.meta_recv_clr(data, more),
                "send_ENC" => s.meta_send_enc(data, more),
                "recv_ENC" => s.meta_recv_enc(data, more),
                "send_MAC" => s.meta_send_mac(data, more),
                "recv_MAC" => s.meta_recv_mac(data).unwrap_or(()),
                "RATCHET" => panic!("Got RATCHET op without length input"),
                _ => panic!("Unexpected op name: {}", op_name),
            }
        }
    };
    Box::new(f)
}

// If Strobe state serialization is defined, then this function does a
// JSON serialization/deserialization round trip on the input state. This is for testing
// correctness of our serde impl.
#[cfg(feature = "serialize_secret_state")]
fn serde_round_trip(s: Strobe) -> Strobe {
    let b = serde_json::to_vec(&s).unwrap();
    let s: Strobe = serde_json::from_slice(&b).unwrap();
    s
}
// If the this feature isn't present, then this is the identity function
#[cfg(not(feature = "serialize_secret_state"))]
fn serde_round_trip(s: Strobe) -> Strobe {
    s
}

// Runs the test vector and compares to the expected output at each step of the way
fn test_against_vector<P: AsRef<Path>>(filename: P) {
    let file = File::open(filename).unwrap();
    let TestHead {
        proto_string,
        security,
        operations,
    } = serde_json::from_reader(file).unwrap();
    let mut s = Strobe::new(proto_string.as_bytes(), security);

    for test_op in operations.into_iter() {
        // Test the serde functionality while we're at it. Do a JSON serialization/deserialization
        // round trip on the state. If not defined, this is the identity function.
        s = serde_round_trip(s);

        // Destructure the operation
        let TestOp {
            name,
            meta,
            input_data,
            input_length,
            stream,
            expected_output,
            expected_state_after,
        } = test_op;

        // Ignore the init part. That was already done in the header
        if name == "init" {
            continue;
        }

        // Input data is either a bytestring, an output MAC size, or a number of zeros
        let mut mac_buf = Vec::new();
        let mut input = match (input_data, name.as_str()) {
            (Some(data), _) => DataOrLength::Data(data),
            (None, "send_MAC" | "PRF") => {
                // If we have to get a MAC or PRF, make a buffer of zeros to write to
                mac_buf.extend(core::iter::repeat(0).take(input_length.unwrap()));
                DataOrLength::Data(mac_buf)
            }
            (None, _) => DataOrLength::Length(input_length.unwrap()),
        };

        // Do the operation and check the resulting state
        let op = get_op(name.clone(), meta);
        op(&mut s, &mut input, stream);
        assert_eq!(&s.st.0[..], expected_state_after.as_slice());

        // Test expected output if the test vector has output to test against. The output of
        // recv_MAC is True or False, which we don't count as output here
        if name == "recv_MAC" {
            continue;
        }
        if let Some(eo) = expected_output {
            // Rename for clarity. The input is mutated in place, so it's the output now
            let computed_output = input.get_data();
            assert_eq!(computed_output, eo.as_slice());
        }
    }
}

#[test]
fn simple_test() {
    test_against_vector("kat/simple_test_vector.json");
}

#[test]
fn meta_test() {
    test_against_vector("kat/meta_test_vector.json");
}

#[test]
fn streaming_test() {
    test_against_vector("kat/streaming_test_vector.json");
}

#[test]
fn boundary_test() {
    test_against_vector("kat/boundary_test_vector.json");
}
