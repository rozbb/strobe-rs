use crate::{
    keccak::{keccakf_u8, AlignedKeccakState, KECCAK_BLOCK_SIZE},
    prelude::*,
};

// The bitflags import is so ugly because these are all macros and bitflags hasn't been updated to
// use Rust 2018
use bitflags::{__bitflags, __impl_bitflags, bitflags};
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
/// # let mut s = Strobe::new(b"example-of-more", SecParam::B128);
/// s.ad(b"hello world", false);
/// # }
/// ```
/// is equivalent to
/// ```rust
/// # extern crate strobe_rs;
/// # use strobe_rs::{SecParam, Strobe};
/// # fn main() {
/// # let mut s = Strobe::new(b"example-of-more", SecParam::B128);
/// s.ad(b"hello ", false);
/// s.ad(b"world", true);
/// # }
/// ```
///
/// Some methods take a `usize` argument instead of bytes. These functions are individually
/// commented below.
#[derive(Clone)]
pub struct Strobe {
    /// Internal Keccak state
    pub(crate) st: AlignedKeccakState,
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
    ($name:ident, $meta_name:ident, $flags:expr, $doc_str:expr) => (
        #[doc = $doc_str]
        pub fn $name(
            &mut self,
            data: &mut [u8],
            more: bool,
        ) {

            let flags = $flags;
            self.operate(flags, data, more);
        }

        pub fn $meta_name(
            &mut self,
            data: &mut [u8],
            more: bool,
        ) {

            let flags = $flags | OpFlags::M;
            self.operate(flags, data, more);
        }
    )
}

// Some methods will only return bytes if metadata was given. This macro is for those methods.
macro_rules! def_op_no_mut {
    ($name:ident, $meta_name:ident, $flags:expr, $doc_str:expr) => (
        #[doc = $doc_str]
        ///
        /// Takes input as normal. This will return a value if and only if metadata is supplied in
        /// the input.
        pub fn $name(&mut self, data: &[u8], more: bool) {
            let flags = $flags;
            self.operate_no_mutate(flags, data, more);
        }

        pub fn $meta_name(&mut self, data: &[u8], more: bool) {
            let flags = $flags | OpFlags::M;
            self.operate_no_mutate(flags, data, more);
        }
    )
}

impl Strobe {
    /// Makes a new `Strobe` object with a given protocol byte string and security parameter.
    pub fn new(proto: &[u8], sec: SecParam) -> Strobe {
        let rate = KECCAK_BLOCK_SIZE * 8 - (sec as usize) / 4 - 2;
        assert!(rate >= 1);
        assert!(rate < 254);

        // Initialize state: st = F([0x01, R+2, 0x01, 0x00, 0x01, 0x60] + b"STROBEvX.Y.Z")
        let mut st_buf = [0u8; KECCAK_BLOCK_SIZE * 8];
        st_buf[0..6].copy_from_slice(&[0x01, (rate as u8) + 2, 0x01, 0x00, 0x01, 0x60]);
        st_buf[6..13].copy_from_slice(b"STROBEv");
        st_buf[13..18].copy_from_slice(STROBE_VERSION.as_bytes());

        let mut st = AlignedKeccakState(st_buf);
        keccakf_u8(&mut st);

        let mut strobe = Strobe {
            st: st,
            sec: sec,
            rate: rate,
            pos: 0,
            pos_begin: 0,
            is_receiver: None,
        };

        // Mix the protocol into the state
        let _ = strobe.meta_ad(proto, false);

        strobe
    }

    /// Returns a string of the form `Strobe-Keccak-<sec>/<b>v<ver>` where `sec` is the bits of
    /// security (128 or 256), `b` is the block size (in bits) of the Keccak permutation function,
    /// and `ver` is the protocol version.
    pub fn version_str(&self) -> String {
        format!(
            "Strobe-Keccak-{}/{}-v{}",
            self.sec as usize,
            KECCAK_BLOCK_SIZE * 64,
            STROBE_VERSION
        )
    }

    fn run_f(&mut self) {
        self.st.0[self.pos] ^= self.pos_begin as u8;
        self.st.0[self.pos + 1] ^= 0x04;
        self.st.0[self.rate + 1] ^= 0x80;

        keccakf_u8(&mut self.st);
        self.pos = 0;
        self.pos_begin = 0;
    }

    /// XORs the given data into the state. This is a special case of the `duplex` code in the
    /// STROBE paper.
    fn absorb(&mut self, data: &[u8]) {
        for b in data {
            self.st.0[self.pos] ^= *b;

            self.pos += 1;
            if self.pos == self.rate {
                self.run_f();
            }
        }
    }

    /// XORs the given data into the state, then set the data equal the state.  This is a special
    /// case of the `duplex` code in the STROBE paper.
    fn absorb_and_set(&mut self, data: &mut [u8]) {
        for b in data {
            let state_byte = self.st.0.get_mut(self.pos).unwrap();
            *state_byte ^= *b;
            *b = *state_byte;

            self.pos += 1;
            if self.pos == self.rate {
                self.run_f();
            }
        }
    }

    /// Overwrites the state with the given data while XORing the given data with the old state.
    /// This is a special case of the `duplex` code in the STROBE paper.
    fn exchange(&mut self, data: &mut [u8]) {
        for b in data {
            let state_byte = self.st.0.get_mut(self.pos).unwrap();
            *b ^= *state_byte;
            *state_byte ^= *b;

            self.pos += 1;
            if self.pos == self.rate {
                self.run_f();
            }
        }
    }

    /// Overwrites the state with the given data. This is a special case of `Strobe::exchange`,
    /// where we do not want to mutate the input data.
    fn overwrite(&mut self, data: &[u8]) {
        for b in data {
            self.st.0[self.pos] = *b;

            self.pos += 1;
            if self.pos == self.rate {
                self.run_f();
            }
        }
    }

    /// Copies the state into the given buffer and sets the state to 0. This is a special case of
    /// `Strobe::exchange`, where `data` is assumed to be the all-zeros string (which is the case
    /// for the PRF operation).
    fn squeeze(&mut self, data: &mut [u8]) {
        for b in data {
            let state_byte = self.st.0.get_mut(self.pos).unwrap();
            *b = *state_byte;
            *state_byte = 0;

            self.pos += 1;
            if self.pos == self.rate {
                self.run_f();
            }
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
        self.absorb(&to_mix[..]);

        let force_f = flags.contains(OpFlags::C) || flags.contains(OpFlags::K);
        if force_f && self.pos != 0 {
            self.run_f();
        }
    }

    // TODO?: Keep track of cur_flags and assert they don't change when `more` is set
    pub(crate) fn operate(&mut self, flags: OpFlags, data: &mut [u8], more: bool) {
        assert!(
            !flags.contains(OpFlags::K),
            "Op flag K not implemented"
        );

        if !more {
            self.begin_op(flags);
        }

        // TODO?: Assert that input is empty under some flag conditions
        if flags.contains(OpFlags::C) && flags.contains(OpFlags::T) && !flags.contains(OpFlags::I) {
            self.absorb_and_set(data);
        } else if flags == OpFlags::I | OpFlags::A | OpFlags::C {
            // This is PRF. Use squeeze() instead of exchange()
            self.squeeze(data);
        } else if flags.contains(OpFlags::C) {
            self.exchange(data);
        } else {
            self.absorb(data);
        };
    }

    pub(crate) fn operate_no_mutate(&mut self, flags: OpFlags, data: &[u8], more: bool) {
        assert!(
            !flags.contains(OpFlags::K),
            "Op flag K not implemented"
        );

        if !more {
            self.begin_op(flags);
        }

        if flags.contains(OpFlags::C) {
            // Use the non-mutable version of exchange()
            self.overwrite(data);
        } else {
            self.absorb(data);
        };
    }

    // This is separately defined because it's the only method that can return a `Result`
    /// Attempts to authenticate the current state against the given MAC. On failure, it returns an
    /// `AuthError`. It behooves the user of this library to check this return value and overreact
    /// on error.
    #[must_use]
    pub fn recv_mac(&mut self, data: &mut [u8], more: bool) -> Result<(), AuthError> {
        let flags = OpFlags::I | OpFlags::C | OpFlags::T;
        self.operate(flags, data, more);

        // Constant-time MAC check. This accumulates the truth values of byte == 0
        let mut all_zero = subtle::Choice::from(1u8);
        for b in data {
            all_zero = all_zero & b.ct_eq(&0u8);
        }

        if all_zero.unwrap_u8() != 1 {
            Err(AuthError)
        } else {
            Ok(())
        }
    }

    // This is separately defined because it's the only method that can return a `Result`
    /// Attempts to authenticate the current state against the given MAC. On failure, it returns an
    /// `AuthError`. It behooves the user of this library to check this return value and overreact
    /// on error.
    #[must_use]
    pub fn meta_recv_mac(&mut self, data: &mut [u8], more: bool) -> Result<(), AuthError> {
        let flags = OpFlags::I | OpFlags::C | OpFlags::T | OpFlags::M;
        self.operate(flags, data, more);

        // Constant-time MAC check. This accumulates the truth values of byte == 0
        let mut all_zero = subtle::Choice::from(1u8);
        for b in data {
            all_zero = all_zero & b.ct_eq(&0u8);
        }

        if all_zero.unwrap_u8() != 1 {
            Err(AuthError)
        } else {
            Ok(())
        }
    }

    // This is separately defined because it's the only method that takes an integer and returns an
    // Option<Vec<u8>>.
    /// Ratchets the internal state forward in an irreversible way by zeroing bytes.
    ///
    /// Takes a `usize` argument specifying the number of bytes of public state to zero. If the
    /// size exceeds `self.rate`, Keccak-f will be called before more bytes are zeroed.
    pub fn ratchet(&mut self, bytes_to_zero: usize, more: bool) {
        let flags = OpFlags::C;
        let mut zeros = vec![0u8; bytes_to_zero];
        self.operate(flags, zeros.as_mut_slice(), more);
    }

    // This is separately defined because it's the only method that takes an integer and returns an
    // Option<Vec<u8>>.
    /// Ratchets the internal state forward in an irreversible way by zeroing bytes.
    ///
    /// Takes a `usize` argument specifying the number of bytes of public state to zero. If the
    /// size exceeds `self.rate`, Keccak-f will be called before more bytes are zeroed.
    pub fn meta_ratchet(&mut self, bytes_to_zero: usize, more: bool) {
        let flags = OpFlags::C | OpFlags::M;
        let mut zeros = vec![0u8; bytes_to_zero];
        self.operate(flags, zeros.as_mut_slice(), more);
    }

    // These operations mutate their inputs
    def_op!(
        send_enc,
        meta_send_enc,
        OpFlags::A | OpFlags::C | OpFlags::T,
        "Sends an encrypted message."
    );
    def_op!(
        recv_enc,
        meta_recv_enc,
        OpFlags::I | OpFlags::A | OpFlags::C | OpFlags::T,
        "Receives an encrypted message."
    );
    def_op!(
        send_mac,
        meta_send_mac,
        OpFlags::C | OpFlags::T,
        "Sends a MAC of the internal state."
    );
    def_op!(
        prf,
        meta_prf,
        OpFlags::I | OpFlags::A | OpFlags::C,
        "Extracts pseudorandom data as a function of the internal state."
    );

    // These operations do not mutate their inputs
    def_op_no_mut!(
        send_clr,
        meta_send_clr,
        OpFlags::A | OpFlags::T,
        "Sends a plaintext message."
    );
    def_op_no_mut!(
        recv_clr,
        meta_recv_clr,
        OpFlags::I | OpFlags::A | OpFlags::T,
        "Receives a plaintext message."
    );
    def_op_no_mut!(
        ad,
        meta_ad,
        OpFlags::A,
        "Mixes associated data into the internal state."
    );
    def_op_no_mut!(
        key,
        meta_key,
        OpFlags::A | OpFlags::C,
        "Sets a symmetric cipher key."
    );
}
