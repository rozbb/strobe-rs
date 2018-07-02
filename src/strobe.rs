use prelude::*;

use byteorder::{ByteOrder, LittleEndian};
use keccak::{self, keccakf, state_bytes_mut};
use subtle::{self, ConstantTimeEq};

const STROBE_VERSION: &'static str = "1.0.2";

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
    st: [u64; keccak::BLOCK_SIZE],
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
    fn operate(
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

/*
   How to run the Python 2 code listed below:
     1. Download a copy of strobe (https://sourceforge.net/p/strobe)
     2. cd into the root directory and then cd into `python`
     3. Make a file with the desired code
     4. Run `python2 <FILE>`
*/
#[cfg(test)]
mod test {
    use keccak::{self, state_bytes};
    use strobe::*;

    /*
        # The Python 2 code used to generate this test vector:
        from Strobe.Strobe import Strobe
        s = Strobe("", security=128)
        print("[{}]".format(', '.join(map("0x{:02x}".format, s.st))))
    */
    #[test]
    fn test_init_128() {
        let s = Strobe::new(Vec::new(), SecParam::B128);
        let initial_st = state_bytes(&s.st);
        let expected_st: &[u8; keccak::BLOCK_SIZE * 8] = &[
            0x9c, 0x7f, 0x16, 0x8f, 0xf8, 0xfd, 0x55, 0xda, 0x2a, 0xa7, 0x3c, 0x23, 0x55, 0x65,
            0x35, 0x63, 0xdc, 0x0c, 0x47, 0x5c, 0x55, 0x15, 0x26, 0xf6, 0x73, 0x3b, 0xea, 0x22,
            0xf1, 0x6c, 0xb5, 0x7c, 0xd3, 0x1f, 0x68, 0x2e, 0x66, 0x0e, 0xe9, 0x12, 0x82, 0x4a,
            0x77, 0x22, 0x01, 0xee, 0x13, 0x94, 0x22, 0x6f, 0x4a, 0xfc, 0xb6, 0x2d, 0x33, 0x12,
            0x93, 0xcc, 0x92, 0xe8, 0xa6, 0x24, 0xac, 0xf6, 0xe1, 0xb6, 0x00, 0x95, 0xe3, 0x22,
            0xbb, 0xfb, 0xc8, 0x45, 0xe5, 0xb2, 0x69, 0x95, 0xfe, 0x7d, 0x7c, 0x84, 0x13, 0x74,
            0xd1, 0xff, 0x58, 0x98, 0xc9, 0x2e, 0xe0, 0x63, 0x6b, 0x06, 0x72, 0x73, 0x21, 0xc9,
            0x2a, 0x60, 0x39, 0x07, 0x03, 0x53, 0x49, 0xcc, 0xbb, 0x1b, 0x92, 0xb7, 0xb0, 0x05,
            0x7e, 0x8f, 0xa8, 0x7f, 0xce, 0xbc, 0x7e, 0x88, 0x65, 0x6f, 0xcb, 0x45, 0xae, 0x04,
            0xbc, 0x34, 0xca, 0xbe, 0xae, 0xbe, 0x79, 0xd9, 0x17, 0x50, 0xc0, 0xe8, 0xbf, 0x13,
            0xb9, 0x66, 0x50, 0x4d, 0x13, 0x43, 0x59, 0x72, 0x65, 0xdd, 0x88, 0x65, 0xad, 0xf9,
            0x14, 0x09, 0xcc, 0x9b, 0x20, 0xd5, 0xf4, 0x74, 0x44, 0x04, 0x1f, 0x97, 0xb6, 0x99,
            0xdd, 0xfb, 0xde, 0xe9, 0x1e, 0xa8, 0x7b, 0xd0, 0x9b, 0xf8, 0xb0, 0x2d, 0xa7, 0x5a,
            0x96, 0xe9, 0x47, 0xf0, 0x7f, 0x5b, 0x65, 0xbb, 0x4e, 0x6e, 0xfe, 0xfa, 0xa1, 0x6a,
            0xbf, 0xd9, 0xfb, 0xf6,
        ];

        assert_eq!(&initial_st[..], &expected_st[..]);
    }

    /*
        # The Python 2 code used to generate this test vector:
        from Strobe.Strobe import Strobe
        s = Strobe("", security=256)
        print("[{}]".format(', '.join(map("0x{:02x}".format, s.st))))
    */
    #[test]
    fn test_init_256() {
        let s = Strobe::new(Vec::new(), SecParam::B256);
        let initial_st = state_bytes(&s.st);
        let expected_st: &[u8; keccak::BLOCK_SIZE * 8] = &[
            0x37, 0xc1, 0x15, 0x06, 0xed, 0x61, 0xe7, 0xda, 0x7c, 0x1a, 0x2f, 0x2c, 0x1f, 0x49,
            0x74, 0xb0, 0x71, 0x66, 0xc2, 0xea, 0x7f, 0x62, 0xec, 0xa6, 0xe0, 0x36, 0xc1, 0x6e,
            0xae, 0x39, 0xb4, 0xdf, 0x3a, 0x06, 0x11, 0xf1, 0x36, 0xc7, 0x33, 0x94, 0x31, 0x13,
            0x2c, 0xdb, 0x18, 0x03, 0x08, 0xc0, 0x53, 0x61, 0xab, 0xf7, 0xb9, 0xc6, 0x89, 0x49,
            0xab, 0x1e, 0x5c, 0x0b, 0xbf, 0xab, 0x0a, 0xb0, 0x66, 0xa0, 0x13, 0x96, 0xdb, 0x8d,
            0xb1, 0x26, 0x02, 0x0c, 0xf7, 0x96, 0xb2, 0x3f, 0x0e, 0xe1, 0xcf, 0x40, 0xda, 0x8f,
            0x8b, 0xfc, 0x34, 0x27, 0x34, 0x14, 0x4a, 0x64, 0x08, 0x29, 0x44, 0x5a, 0x67, 0xab,
            0x3e, 0x15, 0x46, 0xc0, 0x97, 0xe3, 0x23, 0xd3, 0xda, 0xe7, 0xc6, 0x2e, 0x62, 0xd3,
            0xdd, 0xae, 0x90, 0x98, 0x31, 0xa1, 0x64, 0x9c, 0xd8, 0x07, 0x97, 0x7b, 0x5e, 0x44,
            0x88, 0xae, 0x42, 0xfc, 0x36, 0xec, 0x2c, 0x5a, 0x78, 0x0d, 0x52, 0xa3, 0x22, 0xa6,
            0xe9, 0xbe, 0xff, 0x73, 0x89, 0xcb, 0x8f, 0xe7, 0x6a, 0xb5, 0x5d, 0xc6, 0xa0, 0x60,
            0xa7, 0x22, 0xb9, 0x64, 0xb6, 0xe8, 0xfe, 0x8b, 0xb5, 0xb9, 0x1a, 0x9b, 0xbc, 0x61,
            0xc0, 0x86, 0x7e, 0x6d, 0xfc, 0x5b, 0x5c, 0x6d, 0xd5, 0xb5, 0xa7, 0x26, 0xc9, 0x18,
            0xe4, 0x0b, 0xe9, 0xb1, 0xcf, 0xa7, 0xef, 0xa6, 0x92, 0xf5, 0x05, 0xdc, 0xac, 0xde,
            0x80, 0x03, 0xe8, 0xbb,
        ];

        assert_eq!(&initial_st[..], &expected_st[..]);
    }

    /*
        # The Python 2 code used to generate this test vector:
        from Strobe.Strobe import Strobe
        s = Strobe("seqtest", security=256)

        s.prf(10)
        s.ad("Hello")
        s.send_enc("World")
        s.send_clr("foo")
        s.ratchet()
        s.recv_clr("bar")
        s.recv_enc("baz")
        for i in xrange(100):
            s.send_enc("X"*i)
        s.prf(123)
        s.send_mac()

        print("[{}]".format(', '.join(map("0x{:02x}".format, s.st))))
    */
    #[test]
    fn test_seq() {
        let mut s = Strobe::new(b"seqtest".to_vec(), SecParam::B256);
        s.prf(10, None, false);
        s.ad(b"Hello".to_vec(), None, false);
        s.send_enc(b"World".to_vec(), None, false);
        s.send_clr(b"foo".to_vec(), None, false);
        s.ratchet(32, None, false);
        s.recv_clr(b"bar".to_vec(), None, false);
        s.recv_enc(b"baz".to_vec(), None, false);
        for i in 0..100 {
            s.send_enc(vec![b'X'; i], None, false);
        }
        s.prf(123, None, false);
        s.send_mac(16, None, false);

        let final_st = state_bytes(&s.st);
        let expected_st = [
            0xdf, 0x7a, 0x38, 0x71, 0x06, 0xcc, 0x24, 0x82, 0x11, 0x31, 0x60, 0x43, 0xa9, 0xf0,
            0xf5, 0xd0, 0x49, 0xc2, 0xce, 0xd3, 0x85, 0xfc, 0x9e, 0xa8, 0x0e, 0xc1, 0x46, 0xa4,
            0xa1, 0x96, 0x02, 0x30, 0x78, 0xe6, 0x16, 0x62, 0x50, 0x1b, 0xab, 0x23, 0x5d, 0xcb,
            0x85, 0x34, 0x3a, 0x67, 0xc6, 0x6c, 0xd8, 0x79, 0x45, 0xee, 0x2b, 0xaa, 0xc0, 0x09,
            0x45, 0xc7, 0xf6, 0x42, 0xd9, 0xbc, 0x43, 0xe1, 0xd5, 0x2c, 0x6e, 0x71, 0x6f, 0xfa,
            0x9a, 0x39, 0x9d, 0x11, 0xfd, 0x62, 0xfb, 0x15, 0x04, 0x85, 0xf9, 0xe3, 0xc1, 0x24,
            0x95, 0x04, 0x84, 0x95, 0x3c, 0x74, 0x38, 0x3d, 0x5e, 0x08, 0x87, 0x64, 0xa3, 0x57,
            0xdd, 0xb0, 0x40, 0x5b, 0x40, 0x25, 0x93, 0xb8, 0x3a, 0x75, 0x1d, 0xb7, 0xdf, 0xc4,
            0x34, 0x4d, 0xfa, 0x94, 0xc6, 0x98, 0x13, 0xb3, 0x75, 0xf2, 0xdc, 0xd0, 0xe3, 0xe9,
            0x44, 0xba, 0xfd, 0x98, 0x13, 0xc1, 0x59, 0xc7, 0x46, 0xa7, 0xb0, 0x65, 0x70, 0x20,
            0x3d, 0x56, 0xeb, 0x84, 0x18, 0x1c, 0xca, 0x5b, 0x7a, 0xe4, 0xad, 0x3a, 0x57, 0x6b,
            0x40, 0x80, 0x29, 0x0c, 0x63, 0x11, 0xd8, 0x6f, 0x89, 0xb8, 0x32, 0xf0, 0xb1, 0xde,
            0x8c, 0x0a, 0x4f, 0x00, 0x90, 0x16, 0x0d, 0xc1, 0x9f, 0xd4, 0x69, 0x9c, 0x56, 0xb1,
            0xd8, 0x9e, 0xc0, 0x8d, 0x40, 0x7a, 0x36, 0xe3, 0xb3, 0x9c, 0xd4, 0x91, 0x17, 0xd7,
            0xed, 0x4c, 0x4b, 0xa5,
        ];

        assert_eq!(&final_st[..], &expected_st[..]);
    }

    /*
        # The Python 2 code used to generate these test vectors:
        from Strobe.Strobe import Strobe
        I,A,C,T,M,K = 1<<0, 1<<1, 1<<2, 1<<3, 1<<4, 1<<5
        s = Strobe("metadatatest", security=256)

        m = s.key("key", meta_flags=A|T|M, metadata="meta1")
        m += s.prf(10, meta_flags=I|C|M, metadata=10)
        m += s.send_enc("pt", meta_flags=A|T|M, metadata="meta3")

        print("accumulated metadata == [{}]".format(', '.join(map("0x{:02x}".format, m))))
        print("state == [{}]".format(', '.join(map("0x{:02x}".format, s.st))))
    */
    #[test]
    fn test_metadata() {
        let mut s = Strobe::new(b"metadatatest".to_vec(), SecParam::B256);

        // Accumulate metadata over 3 operations
        let mut md =
            s.key(
                b"key".to_vec(),
                Some((OpFlags::A | OpFlags::T | OpFlags::M, b"meta1".to_vec())),
                false,
            ).unwrap();
        md.extend(s.prf(
            10,
            Some((OpFlags::I | OpFlags::C | OpFlags::M, vec![0; 10])),
            false,
        ));
        md.extend(s.send_enc(
            b"pt".to_vec(),
            Some((OpFlags::A | OpFlags::T | OpFlags::M, b"meta3".to_vec())),
            false,
        ));

        let expected_md = [
            0x6d, 0x65, 0x74, 0x61, 0x31, 0x54, 0x27, 0xd1, 0x29, 0x82, 0xad, 0xf6, 0x70, 0x0a,
            0xf9, 0x6d, 0x65, 0x74, 0x61, 0x33, 0x32, 0x0e,
        ];
        let expected_st = [
            0x32, 0x0e, 0x1a, 0xe8, 0xf6, 0x6e, 0x0a, 0x87, 0x2a, 0xea, 0xdf, 0x4f, 0x85, 0x26,
            0x6a, 0x6c, 0x72, 0xc9, 0xb1, 0x78, 0xfd, 0xfc, 0x11, 0x89, 0x8a, 0x52, 0x34, 0xa0,
            0x95, 0x4f, 0x1e, 0xb4, 0x9b, 0xc6, 0xb2, 0xf2, 0x16, 0xce, 0xff, 0xdf, 0xb2, 0x36,
            0x78, 0x23, 0xd5, 0xf7, 0x67, 0xc6, 0xe2, 0x2c, 0xbc, 0xd9, 0x63, 0x3e, 0x8d, 0xa4,
            0x3e, 0x05, 0x93, 0x30, 0x88, 0xe0, 0x70, 0x99, 0x0b, 0x13, 0x07, 0x23, 0x05, 0x4a,
            0x2b, 0x24, 0x94, 0xdb, 0x0f, 0xca, 0xe8, 0xd7, 0xf3, 0x96, 0xf0, 0xe6, 0xfd, 0x42,
            0x67, 0x30, 0xb8, 0xc9, 0x09, 0x47, 0x74, 0x9a, 0x1b, 0xc3, 0x52, 0x21, 0x97, 0x38,
            0x24, 0x25, 0xda, 0xa3, 0x41, 0x5a, 0x93, 0x25, 0xc7, 0x6b, 0xba, 0x8a, 0xdc, 0x79,
            0x39, 0x11, 0xc8, 0xf3, 0x40, 0xd9, 0x95, 0x0f, 0x72, 0xcf, 0xb2, 0xef, 0xcb, 0x58,
            0x34, 0xe0, 0xac, 0xad, 0xbb, 0x60, 0xa8, 0x56, 0x48, 0x5c, 0x37, 0xbb, 0x9b, 0xa5,
            0x19, 0xa5, 0xd9, 0x3f, 0xf8, 0x4b, 0x0e, 0x90, 0x8b, 0x92, 0xc2, 0x1c, 0x81, 0x27,
            0xd2, 0x79, 0x9f, 0x04, 0x3f, 0xe9, 0xb9, 0xe7, 0xe1, 0xed, 0x43, 0x64, 0x2d, 0xe2,
            0xc0, 0x08, 0x13, 0x17, 0x27, 0x8e, 0xaa, 0xa8, 0x17, 0xe0, 0xa4, 0x48, 0x06, 0x61,
            0x1b, 0x5e, 0x31, 0x6e, 0xd4, 0x4d, 0x8d, 0xaa, 0x5b, 0x64, 0xae, 0xf9, 0x22, 0x57,
            0x50, 0x19, 0x52, 0x79,
        ];

        assert_eq!(&*md, &expected_md[..]);
        assert_eq!(&state_bytes(&s.st)[..], &expected_st[..]);
    }

    // Test that streaming in data using the `more` flag works as expected
    #[test]
    fn test_streaming() {
        // Compute a few things without breaking up their inputs
        let one_shot_st: Vec<u8> = {
            let mut s = Strobe::new(b"streamingtest".to_vec(), SecParam::B256);
            s.ad(b"mynonce".to_vec(), None, false);
            s.recv_enc(b"hello there".to_vec(), None, false);
            s.send_mac(16, None, false);
            state_bytes(&s.st).to_vec()
        };
        // Now do the same thing but stream the inputs
        let streamed_st: Vec<u8> = {
            let mut s = Strobe::new(b"streamingtest".to_vec(), SecParam::B256);
            s.ad(b"my".to_vec(), None, false);
            s.ad(b"nonce".to_vec(), None, true);
            s.recv_enc(b"hello".to_vec(), None, false);
            s.recv_enc(b" there".to_vec(), None, true);
            s.send_mac(10, None, false);
            s.send_mac(6, None, true);
            state_bytes(&s.st).to_vec()
        };

        assert_eq!(one_shot_st, streamed_st);
    }

    // Test that decrypt(encrypt(msg)) == msg
    #[test]
    fn test_enc_correctness() {
        let orig_msg = b"Hello there".to_vec();
        let mut tx = Strobe::new(b"enccorrectnesstest".to_vec(), SecParam::B256);
        let mut rx = Strobe::new(b"enccorrectnesstest".to_vec(), SecParam::B256);

        tx.key(b"the-combination-on-my-luggage".to_vec(), None, false);
        rx.key(b"the-combination-on-my-luggage".to_vec(), None, false);

        let ciphertext = tx.send_enc(orig_msg.clone(), None, false);
        let decrypted_msg = rx.recv_enc(ciphertext, None, false);

        assert_eq!(orig_msg, decrypted_msg);
    }

    #[test]
    fn test_mac_correctness() {
        let mut tx = Strobe::new(b"maccorrectnesstest".to_vec(), SecParam::B256);
        let mut rx = Strobe::new(b"maccorrectnesstest".to_vec(), SecParam::B256);

        // Just do some stuff with the state
        tx.key(b"secretsauce".to_vec(), None, false);
        let ct = tx.send_enc(b"attack at dawn".to_vec(), None, false);
        let mac = tx.send_mac(16, None, false);

        rx.key(b"secretsauce".to_vec(), None, false);
        rx.recv_enc(ct, None, false);

        // Test that valid MACs are accepted
        let mut rx_copy = rx.clone();
        let good_res = rx_copy.recv_mac(mac.clone(), None, false);
        assert!(good_res.is_ok());

        // Test that invalid MACs are rejected
        let bad_mac = {
            let mut tmp = mac.clone();
            tmp.push(0);
            tmp
        };
        let bad_res = rx.recv_mac(bad_mac, None, false);
        assert!(bad_res.is_err());
    }
}
