use keccak::state_bytes;
use prelude::*;
use strobe::{OpFlags, SecParam, Strobe};

use std::fs::File;
use std::path::Path;

use hex;
use serde::de::Error as SError;
use serde::{Deserialize, Deserializer};
use serde_json;

#[derive(Deserialize)]
struct TestHead {
    proto_string: String,
    #[serde(deserialize_with = "sec_param_from_bits")]
    security: SecParam,
    operations: Vec<TestOp>,
}

#[derive(Deserialize)]
struct TestOp {
    name: String,
    meta: bool,
    #[serde(deserialize_with = "state_from_hex")]
    input_data: Vec<u8>,
    stream: bool,
    #[serde(default, rename = "output", deserialize_with = "state_from_hex_opt")]
    expected_output: Option<Vec<u8>>,
    #[serde(rename = "state_after", deserialize_with = "state_from_hex")]
    expected_state_after: Vec<u8>,
}

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

fn state_from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut s = String::deserialize(deserializer)?;
    // Prepend a 0 if it's not even length
    if s.len() % 2 == 1 {
        s.insert(0, '0');
    }
    hex::decode(s).map_err(|e| SError::custom(format!("{:?}", e)))
}

// This function is a formality. Some fields are not present, so they're wrapped in Option in the
// above structs. Hence, the deserialization function must return an Option. The `default` pragma
// on the members ensure, however, that the value is None when the field is missing.
fn state_from_hex_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    state_from_hex(deserializer).map(|v| Some(v))
}

// Need this because we use Strobe::operate directly
fn get_flags(op_name: &str) -> OpFlags {
    match op_name {
        "AD"       => OpFlags::A,
        "KEY"      => OpFlags::A|OpFlags::C,
        "PRF"      => OpFlags::I|OpFlags::A|OpFlags::C,
        "send_CLR" => OpFlags::A|OpFlags::T,
        "recv_CLR" => OpFlags::I|OpFlags::A|OpFlags::T,
        "send_ENC" => OpFlags::A|OpFlags::C|OpFlags::T,
        "recv_ENC" => OpFlags::I|OpFlags::A|OpFlags::C|OpFlags::T,
        "send_MAC" => OpFlags::C|OpFlags::T,
        "recv_MAC" => OpFlags::I|OpFlags::C|OpFlags::T,
        "RATCHET"  => OpFlags::C,
        _ => panic!("Unexpected op name: {}", op_name),
    }
}

fn test_against_vector<P: AsRef<Path>>(filename: P) {
    let file = File::open(filename).unwrap();
    let TestHead { proto_string, security, operations } = serde_json::from_reader(file).unwrap();
    let mut s = Strobe::new(proto_string.as_bytes().to_vec(), security);

    for test_op in operations.into_iter() {
        let TestOp {
            name,
            meta,
            input_data,
            stream,
            expected_output,
            expected_state_after,
        } = test_op;

        if name == "init" {
            assert_eq!(&state_bytes(&s.st)[..], expected_state_after.as_slice());
        }
        else {
            let mut flags = get_flags(&*name);
            if meta {
                flags = flags | OpFlags::M;
            }
            let output = match s.operate(flags, input_data, None, stream) {
                Ok(o) => o,
                // We don't expect recv_MAC to work on random inputs. We test recv_MAC's
                // correctness in strobe.rs
                Err(_auth_err) => None
            };

            assert_eq!(&state_bytes(&s.st)[..], expected_state_after.as_slice());
            assert_eq!(output, expected_output);
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
