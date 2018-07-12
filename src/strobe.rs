use prelude::*;

use byteorder::{ByteOrder, LittleEndian};
use keccak::{self, keccakf, state_bytes_mut};
use subtle::{self, ConstantTimeEq};

/// Version of Strobe that this crate implements.
pub const STROBE_VERSION: &'static str = "1.0.2";

bitflags! {
    /// Operation flags defined in the Strobe paper. This is defined as a bitflags struct.
    pub struct OpFlags: u8 {
        /// Is data being moved inbound
        const I = 1<<0;
        /// Is data being sent to the application
        const A = 1<<1;
        /// Does this operation use cipher output
        const C = 1<<2;
        /// Is data being sent for transport
        const T = 1<<3;
        /// Use exclusively for metadata operations
        const M = 1<<4;
        /// Reserved and currently unimplemented. Using this will cause a panic.
        const K = 1<<5;
    }
}

/// Security parameter. Choice of 128 or 256 bits.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum SecParam {
    B128 = 128,
    B256 = 256,
}

// Parameter given to `Strobe::duplex` that tells it when to xor input and state
#[derive(Debug)]
enum CombineSeq {
    Before,
    After,
    Never,
}

/// An empty struct that just indicates that an error occurred in verifying a MAC
#[derive(Debug)]
pub struct AuthError;

/// The main Strobe object. This is currently limited to using Keccak-f\[1600\] as the internal
/// permutation function. For more information on this object, the [protocol specification][spec]
/// is a great resource.
///
/// [spec]: https://strobe.sourceforge.io/specs/
///
/// Description of method input
/// ---------------------------
/// Most operations exposed by `Strobe` take the same set of inputs. Some inputs are not
/// meaningful in some contexts. Again, see the specification for more info. The arguments are
///
/// * `data` - The input data to the operation.
/// * `metadata` - An optional tuple containing meta-operation flags and metadata info. See spec
///                for more info.
/// * `more` - Whether or not you want to add more input to the previous operation. For example:
///
/// ```rust
/// # extern crate strobe_rs;
/// # use strobe_rs::{SecParam, Strobe};
/// # fn main() {
/// # let mut s = Strobe::new(b"example-of-more".to_vec(), SecParam::B128);
/// s.ad(b"hello world".to_vec(), None, false);
/// # }
/// ```
/// is equivalent to
/// ```rust
/// # extern crate strobe_rs;
/// # use strobe_rs::{SecParam, Strobe};
/// # fn main() {
/// # let mut s = Strobe::new(b"example-of-more".to_vec(), SecParam::B128);
/// s.ad(b"hello ".to_vec(), None, false);
/// s.ad(b"world".to_vec(), None, true);
/// # }
/// ```
///
/// Some methods take a `usize` argument instead of bytes. These functions are individually
/// commented below.
#[derive(Clone)]
pub struct Strobe {
    /// Internal Keccak state
    pub(crate) st: [u64; keccak::BLOCK_SIZE],
    /// Security parameter (128 or 256)
    pub sec: SecParam,
    /// This is the `R` parameter in the Strobe spec
    pub rate: usize,
    /// Indices into `st`
    pos: usize,
    pos_begin: usize,
    /// Represents whether we're a sender or a receiver or uninitialized
    is_receiver: Option<bool>,
}

// Most methods return some bytes and cannot error. This macro is for those methods.
macro_rules! def_op {
    ($name:ident, $flags:expr, $doc_str:expr) => (
        #[doc = $doc_str]
        pub fn $name(
            &mut self,
            data: Vec<u8>,
            metadata: Option<(OpFlags, Vec<u8>)>,
            more: bool,
        ) -> Vec<u8> {

            let flags = $flags;
            self.operate(flags, data, metadata, more).unwrap().unwrap()
        }
    )
}

// Some methods only take an integer as an input (representing how long the output should be). This
// macro is for those methods.
macro_rules! def_op_int_input {
    ($name:ident, $flags:expr, $doc_str:expr) => (
        #[doc = $doc_str]
        ///
        /// Takes a `usize` argument instead of bytes. This specifies the number of bytes the user
        /// wants as output.
        pub fn $name(
            &mut self,
            output_len: usize,
            metadata: Option<(OpFlags, Vec<u8>)>,
            more: bool,
        ) -> Vec<u8> {

            let flags = $flags;
            self.operate(flags, vec![0;output_len], metadata, more).unwrap().unwrap()
        }
    )
}

// Some methods will only return bytes if metadata was given. This macro is for those methods.
macro_rules! def_op_opt_return {
    ($name:ident, $flags:expr, $doc_str:expr) => (
        #[doc = $doc_str]
        ///
        /// Takes input as normal. This will return a value if and only if metadata is supplied in
        /// the input.
        pub fn $name(
            &mut self,
            data: Vec<u8>,
            metadata: Option<(OpFlags, Vec<u8>)>,
            more: bool,
        ) -> Option<Vec<u8>> {

            let flags = $flags;
            self.operate(flags, data, metadata, more).unwrap()
        }
    )
}

impl Strobe {
    /// Makes a new `Strobe` object with a given protocol byte string and security parameter.
    pub fn new(proto: Vec<u8>, sec: SecParam) -> Strobe {
        let rate = keccak::BLOCK_SIZE * 8 - (sec as usize) / 4 - 2;
        assert!(rate >= 1);
        assert!(rate < 254);

        // Initialize state: st = F([0x01, R+2, 0x01, 0x00, 0x01, 0x60] + b"STROBEvX.Y.Z")
        let mut st = [0u64; keccak::BLOCK_SIZE];
        {
            // Last 6 zero bytes are to pad the input out to 20 bytes so it all gets read into 3
            // 64-bit words
            let pre_iv = {
                let mut tmp = vec![0x01, (rate as u8) + 2, 0x01, 0x00, 0x01, 0x60];
                tmp.extend(format!("STROBEv{}", STROBE_VERSION).as_bytes());
                tmp.extend(&[0x00; 6]);
                tmp
            };
            LittleEndian::read_u64_into(pre_iv.as_slice(), &mut st[..3]);
            keccakf(&mut st)
        }

        let mut s = Strobe {
            st: st,
            sec: sec,
            rate: rate,
            pos: 0,
            pos_begin: 0,
            is_receiver: None,
        };

        // Mix the protocol into the state
        let _ = s.operate(OpFlags::A | OpFlags::M, proto, None, false);

        s
    }

    /// Returns a string of the form `Strobe-Keccak-<sec>/<b>v<ver>` where `sec` is the bits of
    /// security (128 or 256), `b` is the block size (in bits) of the Keccak permutation function,
    /// and `ver` is the protocol version.
    pub fn version_str(&self) -> String {
        format!(
            "Strobe-Keccak-{}/{}-v{}",
            self.sec as usize,
            keccak::BLOCK_SIZE * 64,
            STROBE_VERSION
        )
    }

    fn run_f(&mut self) {
        // Use same scoping trick here as in duplex
        {
            let st = state_bytes_mut(&mut self.st);
            st[self.pos] ^= self.pos_begin as u8;
            st[self.pos + 1] ^= 0x04;
            st[self.rate + 1] ^= 0x80;
        }

        keccakf(&mut self.st);
        self.pos = 0;
        self.pos_begin = 0;
    }

    fn duplex(&mut self, data: &mut [u8], seq: CombineSeq, force_f: bool) {
        for b in data {
            // We need to separately scope st because we can't have two &muts pointing to the same
            // thing in scope at the same time
            {
                let st = state_bytes_mut(&mut self.st);
                if let CombineSeq::Before = seq {
                    *b ^= st[self.pos];
                }
                st[self.pos] ^= *b;
                if let CombineSeq::After = seq {
                    *b = st[self.pos];
                }
            }

            self.pos += 1;
            if self.pos == self.rate {
                self.run_f();
            }
        }

        if force_f && self.pos != 0 {
            self.run_f();
        }
    }

    fn begin_op(&mut self, mut flags: OpFlags) {
        if flags.contains(OpFlags::T) {
            let is_op_receiving = flags.contains(OpFlags::I);
            // If uninitialized, take on the direction of the first directional operation we get
            if self.is_receiver.is_none() {
                self.is_receiver = Some(is_op_receiving);
            }

            // So that the sender and receiver agree, toggle the I flag as necessary
            // This is equivalent to flags ^= is_receiver
            flags.set(OpFlags::I, self.is_receiver.unwrap() != is_op_receiving);
        }

        let old_pos_begin = self.pos_begin;
        self.pos_begin = self.pos + 1;

        // Mix in the position and flags
        let to_mix = &mut [old_pos_begin as u8, flags.bits()];
        let force_f = flags.contains(OpFlags::C) || flags.contains(OpFlags::K);
        self.duplex(&mut to_mix[..], CombineSeq::Never, force_f);
    }

    // TODO?: Keep track of cur_flags and assert they don't change when `more` is set
    pub(crate) fn operate(
        &mut self,
        flags: OpFlags,
        mut data: Vec<u8>,
        metadata: Option<(OpFlags, Vec<u8>)>,
        more: bool,
    ) -> Result<Option<Vec<u8>>, AuthError> {
        assert_eq!(
            flags.contains(OpFlags::K),
            false,
            "Op flag K not implemented"
        );

        let mut meta_out: Option<Vec<u8>> = None;
        if !more {
            if let Some((mut md_flags, md)) = metadata {
                // Metadata must have the M flag set
                md_flags.set(OpFlags::M, true);
                meta_out = self.operate(md_flags, md, None, more)?;
            }
            self.begin_op(flags);
        }

        // TODO?: Assert that input is empty under some flag conditions
        let seq = if flags.contains(OpFlags::C)
            && flags.contains(OpFlags::T)
            && !flags.contains(OpFlags::I)
        {
            CombineSeq::After
        } else if flags.contains(OpFlags::C) {
            CombineSeq::Before
        } else {
            CombineSeq::Never
        };

        self.duplex(data.as_mut_slice(), seq, false);
        // Rename for clarity
        let processed = data;

        // This operation outputs to the application
        if flags.contains(OpFlags::I) && flags.contains(OpFlags::A) {
            if let Some(mut m) = meta_out {
                m.extend(processed);
                Ok(Some(m))
            } else {
                Ok(Some(processed))
            }
        }
        // This operation outputs to transport. This case does the same thing as above.
        else if flags.contains(OpFlags::T) && !flags.contains(OpFlags::I) {
            if let Some(mut m) = meta_out {
                m.extend(processed);
                Ok(Some(m))
            } else {
                Ok(Some(processed))
            }
        }
        // This operation is recv_mac
        else if flags.contains(OpFlags::I)
            && flags.contains(OpFlags::T)
            && !flags.contains(OpFlags::A)
        {
            // Constant-time MAC check. This accumulates the truth values of byte == 0
            let mut all_zero = subtle::Choice::from(1u8);
            for b in processed {
                all_zero = all_zero & b.ct_eq(&0u8);
            }

            if all_zero.unwrap_u8() != 1 {
                Err(AuthError)
            } else {
                Ok(meta_out)
            }
        }
        // Output metadata if any was given
        else {
            Ok(meta_out)
        }
    }

    // This is separately defined because it's the only method that can return a `Result`
    /// Attempts to authenticate the current state against the given MAC. On failure, it returns an
    /// `AuthError`. It behooves the user of this library to check this return value and overreact
    /// on error.
    #[must_use]
    pub fn recv_mac(
        &mut self,
        data: Vec<u8>,
        metadata: Option<(OpFlags, Vec<u8>)>,
        more: bool,
    ) -> Result<Option<Vec<u8>>, AuthError> {
        let flags = OpFlags::I | OpFlags::C | OpFlags::T;
        self.operate(flags, data, metadata, more)
    }

    // This is separately defined because it's the only method that takes an integer and returns an
    // Option<Vec<u8>>.
    /// Ratchets the internal state forward in an irreversible way by zeroing bytes.
    ///
    /// Takes a `usize` argument specifying the number of bytes of public state to zero. If the
    /// size exceeds `self.rate`, Keccak-f will be called before more bytes are zeroed.
    pub fn ratchet(
        &mut self,
        bytes_to_zero: usize,
        metadata: Option<(OpFlags, Vec<u8>)>,
        more: bool,
    ) -> Option<Vec<u8>> {
        let flags = OpFlags::C;
        self.operate(flags, vec![0; bytes_to_zero], metadata, more)
            .unwrap()
    }

    // These operations always return something
    def_op!(
        send_clr,
        OpFlags::A | OpFlags::T,
        "Sends a plaintext message."
    );
    def_op!(
        recv_clr,
        OpFlags::I | OpFlags::A | OpFlags::T,
        "Receives a plaintext message."
    );
    def_op!(
        send_enc,
        OpFlags::A | OpFlags::C | OpFlags::T,
        "Sends an encrypted message."
    );
    def_op!(
        recv_enc,
        OpFlags::I | OpFlags::A | OpFlags::C | OpFlags::T,
        "Receives an encrypted message."
    );
    // These return something and only take length as inputs
    def_op_int_input!(
        send_mac,
        OpFlags::C | OpFlags::T,
        "Sends a MAC of the internal state."
    );
    def_op_int_input!(
        prf,
        OpFlags::I | OpFlags::A | OpFlags::C,
        "Extracts pseudorandom data as a function of the internal state."
    );

    // These operations will return something iff metadata is given
    def_op_opt_return!(
        ad,
        OpFlags::A,
        "Mixes associated data into the internal state."
    );
    def_op_opt_return!(
        key,
        OpFlags::A | OpFlags::C,
        "Sets a symmetric cipher key."
    );
}
