# strobe-rs Code Audit

**Scope:** `strobe-rs` v0.13.0 — pure-Rust implementation of the STROBE protocol framework (Keccak-f[1600]).
**Files reviewed:** `src/strobe.rs`, `src/keccak.rs`, `src/lib.rs`, tests, benches, examples, `Cargo.toml`.
**Date:** 2026-08-02

> Context: this is a small (~600 LOC of real logic), well-structured, `no_std` crypto primitive with strong known-answer-test (KAT) coverage against the reference Python implementation. The README already states it is unaudited. Overall the implementation is clean and the cryptographically sensitive paths (MAC verification) are handled correctly. The findings below are mostly defense-in-depth, hygiene, and performance items — I found no memory-safety bugs and no exploitable timing side channel.

---

## Summary

| # | Category | Severity | Item |
|---|----------|----------|------|
| S1 | Security | Low–Med | Full secret state left in un-zeroized stack buffer on every permutation |
| S2 | Security | Info | `serialize_secret_state` emits keys in cleartext |
| S3 | Security | Info | Misuse causes `panic!` (fail-closed, but an availability consideration) |
| S4 | Security | ✅ Positive | Constant-time MAC check; no secret-dependent branching |
| P1 | Misoptimization | Med | Byte-at-a-time duplex loops with a per-byte branch |
| P2 | Misoptimization | Low | `keccakf_u8` copies the 200-byte state in and out on every call |
| C1 | Code smell | Low | `#[repr(align(8))]` rationale is obsolete/misleading |
| C2 | Code smell | Low | Dead asserts in `new()` |
| C3 | Code smell | Low | Dead `OpFlags::K` branch in `begin_op` |
| C4 | Code smell | Low | Inconsistent `.get_mut().unwrap()` vs direct indexing |
| C5 | Code smell | Trivial | Typos in comments/identifiers/docs |

---

## Security

### S1 — Secret state is left in an un-zeroized stack buffer on every permutation (Low–Medium)

`src/keccak.rs:31`

```rust
pub(crate) fn keccakf_u8(st: &mut AlignedKeccakState) {
    let mut keccak_block = [0u64; KECCAK_BLOCK_SIZE];
    LittleEndian::read_u64_into(&st.0, &mut keccak_block);
    Keccak::new().with_f1600(|f| f(&mut keccak_block));
    LittleEndian::write_u64_into(&keccak_block, &mut st.0);
}
```

`keccak_block` holds a complete copy of the secret Keccak state (which after `key()` is derived from key material) and is **not** zeroized when it goes out of scope. This runs on essentially every operation, so a fresh plaintext copy of the secret state is repeatedly left on the stack.

The crate goes to real trouble elsewhere to protect secrets — `Strobe` derives `ZeroizeOnDrop`, and `generalized_recv_mac` explicitly zeroizes its temporary MAC copy — so this is an inconsistency that partially undermines that guarantee. An attacker with a stack-memory disclosure (core dump, cold-boot, uninitialized-memory-reuse bug in a caller) could recover state material.

**Fix:** zeroize the temporary before returning, e.g.

```rust
use zeroize::Zeroize;
// ...
LittleEndian::write_u64_into(&keccak_block, &mut st.0);
keccak_block.zeroize();
```

Note this only covers *this* crate's copy; the upstream `keccak` crate may also keep the state in registers/stack. Still worth closing the copy we own.

### S2 — `serialize_secret_state` serializes keys in cleartext (Informational)

The optional `serialize_secret_state` feature derives `Serialize`/`Deserialize` on `Strobe`, whose `st` field *is* the secret keystream state. This is by design and gated behind a non-default feature, but the produced blob is unencrypted key-equivalent material. Worth an explicit doc warning that the serialized output must be stored/transmitted with the same protection as a raw key (it currently has no such caveat at the feature/type level).

### S3 — Misuse is handled with `panic!` (Informational / availability)

`operate`, `operate_no_mutate`, and `validate_streaming` `panic!` / `assert!` on misuse (the unimplemented `K` flag, and improper use of the `more` streaming flag). This is a reasonable fail-closed choice for a crypto primitive, and the offending inputs are developer-chosen (flags come from the typed API, not attacker bytes), so it is not an attacker-triggered DoS in normal use. Flagging only so downstream integrators know these paths abort the process rather than return an error.

### S4 — Positive findings ✅

- **Constant-time MAC verification** (`generalized_recv_mac`, `src/strobe.rs:449`) uses `subtle::ConstantTimeEq` and accumulates with `&=`, only branching on the final aggregated `Choice`. This is the standard correct pattern, and the comparison length is a public const generic. The temporary MAC copy is zeroized. Good.
- **No secret-dependent control flow.** Every duplex loop iterates over `data.len()` (a public message length); there are no branches or table lookups keyed on secret bytes, and the underlying `keccak` f1600 is constant-time. I did not find a timing side channel on secret data.
- No `unsafe`, no `transmute`, no raw pointers. The only `.unwrap()`s in non-test code (`src/strobe.rs:263,291,320,364`) are statically unreachable given the surrounding invariants.

---

## Misoptimizations

### P1 — Byte-at-a-time duplex loops (Medium)

`absorb`, `absorb_and_set`, `copy_state`, `exchange`, `overwrite`, and `squeeze` (`src/strobe.rs:248–329`) all follow this shape:

```rust
for b in data {
    self.st.0[self.pos] ^= *b;
    self.pos += 1;
    if self.pos == self.rate {
        self.run_f();
    }
}
```

Every single byte incurs a bounds-checked index and a `pos == rate` branch. Between permutations there are up to `rate` (134–166) contiguous bytes that could be processed as a slice. `zero_state` (`src/strobe.rs:335`) already does exactly this chunking — the same pattern should be applied to the others. This is the dominant throughput cost for bulk `send_enc`/`recv_enc`/`prf`, and refactoring to slice-at-a-time (`copy_from_slice` / a chunked XOR over `st.0[pos..pos+n]`) would let the compiler autovectorize the XOR and drop the per-byte branch. Correctness is easy to hold constant thanks to the existing KATs.

### P2 — `keccakf_u8` round-trips the whole state every call (Low)

`src/keccak.rs:31` copies all 200 bytes into a `[u64; 25]`, permutes, then copies back — on every `run_f`. The comment ("Hopefully the compiler will optimize out the copy if we're on a little endian machine") is optimistic: `read_u64_into`/`write_u64_into` are real byte-shuffling copies and won't vanish. The clean fix is to store the state natively as `[u64; 25]` and only convert at the byte-oriented boundaries (state init, KAT comparisons, serde), removing the per-permutation copy entirely. That's a larger refactor (`AlignedKeccakState` is currently a byte array threaded through all the duplex code), so it's a Low-priority structural improvement rather than a quick win.

---

## Code smells

### C1 — `#[repr(align(8))]` rationale is obsolete (`src/keccak.rs:17–25`)

The doc comment says the 8-byte alignment exists "to make pointers to it safely convertible to a pointer to `[u64; 25]`". No such conversion happens anywhere — the code uses `read_u64_into`/`write_u64_into` byte copies precisely to avoid a transmute (see the `keccak.rs:28` comment: "I don't feel comfortable doing a mem transmute"). The alignment is harmless (and marginally helps the copies) but the stated justification is misleading. Either restore the intended zero-copy path (see P2) or update the comment to reflect why the alignment is actually kept.

### C2 — Dead asserts in `new()` (`src/strobe.rs:170–171`)

```rust
assert!(rate >= 1);
assert!(rate < 254);
```

`rate` is fully determined by `SecParam`, which has exactly two variants → `rate` is 166 (B128) or 134 (B256). These asserts can never fire. Harmless, but they read as guarding attacker input when they don't. Fine to keep as documentation, but worth a comment noting they're structurally unreachable.

### C3 — Dead `OpFlags::K` branch (`src/strobe.rs:374`)

```rust
let force_f = flags.contains(OpFlags::C) || flags.contains(OpFlags::K);
```

`K` triggers `panic!("Op flag K not implemented")` in both `operate` and `operate_no_mutate` before `begin_op` runs, and the only other caller (`generalized_ratchet`) never sets `K`. The `|| flags.contains(OpFlags::K)` term is therefore unreachable. Drop it or leave a note that it's forward-looking for when `K` lands.

### C4 — Inconsistent element access (`src/strobe.rs`)

`absorb_and_set` (263), `exchange` (291), and `squeeze` (320) use `self.st.0.get_mut(self.pos).unwrap()`, while the structurally identical `absorb` (250), `copy_state` (278), and `overwrite` (305) use direct indexing `self.st.0[self.pos]`. Both forms panic identically on out-of-range and compile to the same bounds check; the mix is just visual noise. Pick one (direct indexing is the more idiomatic and reads cleaner here).

### C5 — Typos (Trivial)

- `src/keccak.rs:29` — "if we' re on a little endian machine".
- `Cargo.toml:41` — "Criteron benches" (→ Criterion).
- `README.md` — "target/crieteron/report" (→ criterion).
- `benches/benches.rs` — `"rachet 16"`, `"meta_rachet 16"` (→ ratchet).

---

## Suggested priority order

1. **S1** — zeroize `keccak_block` (tiny, closes a real defense-in-depth gap consistent with the crate's own posture).
2. **P1** — chunk the duplex loops (best perf/effort ratio; KATs de-risk it).
3. **C1–C3** — remove/annotate dead code and the stale alignment rationale.
4. **P2** — consider a native `[u64; 25]` state representation (larger refactor).
5. **S2** — add a security caveat to the `serialize_secret_state` docs.
6. **C4/C5** — cosmetic cleanup.

*No memory-safety or correctness defects were found; the KAT suite passes against the reference implementation and covers streaming, metadata, long inputs, and boundary cases.*
