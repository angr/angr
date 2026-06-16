//! Reference-model tests for `BitVec`.
//!
//! These complement the example-based unit tests by checking every operator
//! against a `BigUint`/`BigInt` reference across many bit-widths — crucially
//! including widths that straddle the 64-bit word boundary (65, 96, 127, 128,
//! 200) and shift amounts that exercise 0, `>= 64`, and `>= width`. The
//! deterministic PRNG keeps failures reproducible without adding a dependency.

use super::{BitVec, BitVecError};

use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Deterministic xorshift64 PRNG.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_u32(&mut self, bound: u32) -> u32 {
        (self.next() % bound as u64) as u32
    }
}

const WIDTHS: &[u32] = &[1, 2, 7, 8, 13, 31, 32, 63, 64, 65, 96, 127, 128, 130, 200];

fn modulus(width: u32) -> BigUint {
    BigUint::one() << width
}

fn mask(value: BigUint, width: u32) -> BigUint {
    value % modulus(width)
}

/// Random unsigned value in `[0, 2^width)`.
fn rand_biguint(rng: &mut Rng, width: u32) -> BigUint {
    let words = (width as usize).div_ceil(64);
    let mut value = BigUint::zero();
    for i in 0..words {
        value |= BigUint::from(rng.next()) << (i * 64);
    }
    mask(value, width)
}

/// Interpret a width-bit unsigned value as a signed (two's complement) integer.
fn signed_val(value: &BigUint, width: u32) -> BigInt {
    let signed = BigInt::from(value.clone());
    if value.bit((width - 1) as u64) {
        signed - (BigInt::from(1) << width)
    } else {
        signed
    }
}

fn bv_u(value: &BigUint, width: u32) -> BitVec {
    BitVec::from_biguint(value, width)
}

// ----------------------------------------------------------------------------
// Regression tests: each pins a specific bug found in the original code.
// ----------------------------------------------------------------------------

#[test]
fn regression_shl_multiword_ge_64() {
    // 128-bit `1 << 70`. The old word-shift overflowed (panic in debug, silently
    // `1 << 6 == 64` in release).
    let v = bv_u(&BigUint::one(), 128);
    let got = (v << 70).unwrap();
    assert_eq!(got.to_biguint(), BigUint::one() << 70u32);
}

#[test]
fn regression_lshr_multiword_word_order() {
    // 128-bit `((0xA << 64) | 0xF) >> 4`. The old shr collected words in reversed
    // order, yielding `0xA << 124` instead of `0xA << 60`.
    let value = (BigUint::from(0xAu8) << 64u32) | BigUint::from(0xFu8);
    let got = (bv_u(&value, 128) >> 4).unwrap();
    assert_eq!(got.to_biguint(), BigUint::from(0xAu8) << 60u32);
}

#[test]
fn regression_shift_by_ge_width_is_zero() {
    for &width in WIDTHS {
        let v = BitVec::ones(width);
        assert!((v.clone() << width).unwrap().is_zero());
        assert!((v.clone() >> width).unwrap().is_zero());
        assert!((v.clone() << (width + 5)).unwrap().is_zero());
        assert!((v >> (width + 5)).unwrap().is_zero());
    }
}

#[test]
fn regression_shift_by_zero_is_identity() {
    for &width in WIDTHS {
        let v = BitVec::from_biguint(&(modulus(width) - 1u8 - 1u8), width);
        assert_eq!((v.clone() << 0).unwrap(), v);
        assert_eq!((v.clone() >> 0).unwrap(), v);
    }
}

#[test]
fn regression_rem_by_zero_is_error_not_panic() {
    let a = BitVec::from(42u64);
    let b = BitVec::from(0u64);
    assert!(matches!(a % b, Err(BitVecError::DivisionByZero)));
}

#[test]
fn regression_zero_length_is_canonical() {
    let from_prim = BitVec::from_prim_with_size(0u8, 0).unwrap();
    let zeros = BitVec::zeros(0);
    assert_eq!(from_prim, zeros);
    assert_eq!(from_prim.is_all_ones(), zeros.is_all_ones());
    assert!(from_prim.is_zero());
    assert!(from_prim.is_all_ones());
}

#[test]
fn regression_new_trims_excess_words() {
    // A length of 64 must keep exactly one word; a stray high word is dropped.
    let mut words = smallvec::SmallVec::<[u64; 1]>::new();
    words.push(0);
    words.push(0xDEAD);
    let bv = BitVec::new(words, 64).unwrap();
    assert!(bv.is_zero());
    assert_eq!(bv.to_biguint(), BigUint::zero());
}

#[test]
fn regression_rotate_zero_length_does_not_panic() {
    let v = BitVec::zeros(0);
    assert_eq!(v.rotate_left(0).unwrap().len(), 0);
    assert_eq!(v.rotate_right(3).unwrap().len(), 0);
}

// ----------------------------------------------------------------------------
// Randomized reference sweep.
// ----------------------------------------------------------------------------

#[test]
fn reference_sweep_unsigned() {
    let mut rng = Rng(0x1234_5678_9abc_def1);

    for &width in WIDTHS {
        for _ in 0..24 {
            let a = rand_biguint(&mut rng, width);
            let mut b = rand_biguint(&mut rng, width);
            let bv_a = bv_u(&a, width);
            let bv_b = bv_u(&b, width);

            // Arithmetic.
            assert_eq!(
                (bv_a.clone() + bv_b.clone()).unwrap(),
                bv_u(&mask(&a + &b, width), width),
                "add w={width} a={a} b={b}"
            );
            assert_eq!(
                (bv_a.clone() - bv_b.clone()).unwrap(),
                BitVec::from_bigint(&(BigInt::from(a.clone()) - BigInt::from(b.clone())), width),
                "sub w={width} a={a} b={b}"
            );
            assert_eq!(
                (bv_a.clone() * bv_b.clone()).unwrap(),
                bv_u(&mask(&a * &b, width), width),
                "mul w={width} a={a} b={b}"
            );
            assert_eq!(
                (-bv_a.clone()).unwrap(),
                BitVec::from_bigint(&(-BigInt::from(a.clone())), width),
                "neg w={width} a={a}"
            );

            // Bitwise.
            assert_eq!(
                (bv_a.clone() & bv_b.clone()).unwrap(),
                bv_u(&(&a & &b), width),
                "and w={width} a={a} b={b}"
            );
            assert_eq!(
                (bv_a.clone() | bv_b.clone()).unwrap(),
                bv_u(&(&a | &b), width),
                "or w={width} a={a} b={b}"
            );
            assert_eq!(
                (bv_a.clone() ^ bv_b.clone()).unwrap(),
                bv_u(&(&a ^ &b), width),
                "xor w={width} a={a} b={b}"
            );
            assert_eq!(
                (!bv_a.clone()).unwrap(),
                bv_u(&((modulus(width) - 1u8) ^ &a), width),
                "not w={width} a={a}"
            );

            // Division (avoid a zero divisor).
            if b.is_zero() {
                b = BigUint::one();
            }
            let bv_b = bv_u(&b, width);
            assert_eq!(
                (bv_a.clone() / bv_b.clone()).unwrap(),
                bv_u(&(&a / &b), width),
                "udiv w={width} a={a} b={b}"
            );
            assert_eq!(
                bv_a.urem(&bv_b),
                bv_u(&(&a % &b), width),
                "urem w={width} a={a} b={b}"
            );
            let (sa, sb) = (signed_val(&a, width), signed_val(&b, width));
            assert_eq!(
                bv_a.sdiv(&bv_b).unwrap(),
                BitVec::from_bigint(&(&sa / &sb), width),
                "sdiv w={width} a={a} b={b}"
            );
            assert_eq!(
                bv_a.srem(&bv_b).unwrap(),
                BitVec::from_bigint(&(&sa % &sb), width),
                "srem w={width} a={a} b={b}"
            );

            // Comparisons.
            assert_eq!(bv_a.cmp(&bv_b), a.cmp(&b), "ucmp w={width} a={a} b={b}");
            assert_eq!(
                bv_a.signed_lt(&bv_b).unwrap(),
                sa < sb,
                "slt w={width} a={a} b={b}"
            );

            // Shifts, including amounts >= 64 and >= width.
            for &s in &[
                0u32,
                1,
                7,
                63,
                64,
                65,
                width.saturating_sub(1),
                width,
                width + 9,
            ] {
                let expect_shl = if s >= width {
                    BigUint::zero()
                } else {
                    mask(&a << s, width)
                };
                assert_eq!(
                    (bv_a.clone() << s).unwrap(),
                    bv_u(&expect_shl, width),
                    "shl w={width} a={a} s={s}"
                );
                let expect_shr = if s >= width { BigUint::zero() } else { &a >> s };
                assert_eq!(
                    (bv_a.clone() >> s).unwrap(),
                    bv_u(&expect_shr, width),
                    "lshr w={width} a={a} s={s}"
                );
            }

            // Rotations.
            for _ in 0..3 {
                let r = rng.next_u32(2 * width + 1);
                let rm = r % width;
                let rl = if rm == 0 {
                    a.clone()
                } else {
                    mask((&a << rm) | (&a >> (width - rm)), width)
                };
                assert_eq!(
                    bv_a.rotate_left(r).unwrap(),
                    bv_u(&rl, width),
                    "rotl w={width} a={a} r={r}"
                );
                let rr = if rm == 0 {
                    a.clone()
                } else {
                    mask((&a >> rm) | (&a << (width - rm)), width)
                };
                assert_eq!(
                    bv_a.rotate_right(r).unwrap(),
                    bv_u(&rr, width),
                    "rotr w={width} a={a} r={r}"
                );
            }

            // Extract.
            let lo = rng.next_u32(width);
            let hi = lo + rng.next_u32(width - lo);
            let ext_width = hi - lo + 1;
            let expect_ext = mask(&a >> lo, ext_width);
            assert_eq!(
                bv_a.extract(lo, hi).unwrap(),
                bv_u(&expect_ext, ext_width),
                "extract w={width} a={a} lo={lo} hi={hi}"
            );

            // Concatenation: (a : b) has value (a << width) | b.
            assert_eq!(
                bv_a.concat(&bv_b).unwrap(),
                bv_u(&((&a << width) | &b), 2 * width),
                "concat w={width} a={a} b={b}"
            );

            // Extensions.
            let n = rng.next_u32(80);
            assert_eq!(
                bv_a.zero_extend(n).unwrap(),
                bv_u(&a, width + n),
                "zext w={width} a={a} n={n}"
            );
            assert_eq!(
                bv_a.sign_extend(n).unwrap(),
                BitVec::from_bigint(&sa, width + n),
                "sext w={width} a={a} n={n}"
            );

            // Bit counting.
            assert_eq!(bv_a.bits(), a.bits() as usize, "bits w={width} a={a}");
            assert_eq!(
                bv_a.leading_zeros(),
                (width as u64 - a.bits()) as usize,
                "lz w={width} a={a}"
            );
        }
    }
}
