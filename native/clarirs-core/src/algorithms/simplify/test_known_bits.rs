use super::known_bits::{KnownBits, KnownMemo, known_bits};
use crate::prelude::*;
use anyhow::Result;
use std::time::Instant;

fn bvv<'c>(ctx: &'c Context<'c>, v: u64, n: u32) -> AstRef<'c> {
    ctx.bvv(BitVec::from((v, n))).unwrap()
}

fn kb(known: u64, value: u64, w: u32) -> KnownBits {
    KnownBits::new(BitVec::from((known, w)), BitVec::from((value, w))).unwrap()
}

/// Known bits of `e` as (known, value) u64 pairs; `e` is at most 64 bits wide.
fn known_of(e: &AstRef<'_>) -> (u64, u64) {
    let mut memo = KnownMemo::default();
    let k = known_bits(e, &mut memo).unwrap();
    (k.known().to_u64().unwrap(), k.value().to_u64().unwrap())
}

/// Asserts `e` simplifies to the constant `v` without Debug-printing `e` on failure.
#[track_caller]
fn assert_const(e: &AstRef<'_>, v: u64) {
    let s = e.simplify().unwrap();
    match s.op() {
        AstOp::BVV(x) => assert_eq!(x.to_u64(), Some(v), "folded to the wrong constant"),
        _ => panic!("not folded to a constant (depth {})", s.depth()),
    }
}

#[track_caller]
fn assert_unchanged(e: &AstRef<'_>) {
    let s = e.simplify().unwrap();
    assert!(s.hash() == e.hash(), "shape changed (depth {})", s.depth());
}

// -------- transfer functions against brute force (8-bit) --------

/// Every 8-bit value consistent with `k`.
fn consistent(k: &KnownBits) -> Vec<u64> {
    let known = k.known().to_u64().unwrap();
    let value = k.value().to_u64().unwrap();
    (0..256u64).filter(|v| v & known == value).collect()
}

/// Checks the 8-bit transfer `f` against `op` on every consistent operand pair.
fn check_binary(
    f: impl Fn(&KnownBits, &KnownBits) -> KnownBits,
    op: impl Fn(u64, u64) -> u64,
    seed: &mut u64,
) {
    for _ in 0..200 {
        let (a, b) = (rand_kb(seed), rand_kb(seed));
        let r = f(&a, &b);
        let known = r.known().to_u64().unwrap();
        let value = r.value().to_u64().unwrap();
        for x in consistent(&a) {
            for y in consistent(&b) {
                let actual = op(x, y) & 0xff;
                assert_eq!(actual & known, value, "unsound: {x:#x} op {y:#x}");
            }
        }
    }
}

fn check_unary(f: impl Fn(&KnownBits) -> KnownBits, op: impl Fn(u64) -> u64, seed: &mut u64) {
    for _ in 0..300 {
        let a = rand_kb(seed);
        let r = f(&a);
        let known = r.known().to_u64().unwrap();
        let value = r.value().to_u64().unwrap();
        for x in consistent(&a) {
            assert_eq!(op(x) & known, value, "unsound: op {x:#x}");
        }
    }
}

fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn rand_kb(seed: &mut u64) -> KnownBits {
    let known = next(seed) & 0xff & next(seed);
    let value = next(seed) & 0xff;
    kb(known, value, 8)
}

#[test]
fn test_transfer_bitwise_and_arith() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    check_binary(|a, b| a.and(b).unwrap(), |x, y| x & y, &mut seed);
    check_binary(|a, b| a.or(b).unwrap(), |x, y| x | y, &mut seed);
    check_binary(|a, b| a.xor(b).unwrap(), |x, y| x ^ y, &mut seed);
    check_binary(|a, b| a.add(b).unwrap(), |x, y| x + y, &mut seed);
    check_binary(|a, b| a.sub(b).unwrap(), |x, y| x.wrapping_sub(y), &mut seed);
    check_binary(|a, b| a.mul(b).unwrap(), |x, y| x * y, &mut seed);
    check_binary(|a, b| a.select(b).unwrap(), |x, _| x, &mut seed);
    check_binary(|a, b| a.select(b).unwrap(), |_, y| y, &mut seed);
    check_unary(|a| a.not().unwrap(), |x| !x, &mut seed);
    check_unary(|a| a.neg().unwrap(), |x| x.wrapping_neg(), &mut seed);
    check_unary(|a| a.byte_reverse().unwrap(), |x| x, &mut seed);
    for k in 0..=9u32 {
        check_unary(|a| a.shl(k).unwrap(), |x| if k >= 8 { 0 } else { x << k }, &mut seed);
        check_unary(|a| a.lshr(k).unwrap(), |x| if k >= 8 { 0 } else { x >> k }, &mut seed);
        check_unary(
            |a| a.ashr(k).unwrap(),
            |x| ((x as u8 as i8) >> k.min(7)) as u8 as u64,
            &mut seed,
        );
        if k < 8 {
            check_unary(
                |a| a.rotate_left(k).unwrap(),
                |x| (x as u8).rotate_left(k) as u64,
                &mut seed,
            );
            check_unary(
                |a| a.rotate_right(k).unwrap(),
                |x| (x as u8).rotate_right(k) as u64,
                &mut seed,
            );
        }
    }
    // ext / extract / concat on 4-bit halves
    for _ in 0..200 {
        let a = rand_kb(&mut seed);
        let lo = a.extract(3, 0).unwrap();
        let hi = a.extract(7, 4).unwrap();
        let (lk, lv) = (lo.known().to_u64().unwrap(), lo.value().to_u64().unwrap());
        let (hk, hv) = (hi.known().to_u64().unwrap(), hi.value().to_u64().unwrap());
        let z = lo.zero_ext(4).unwrap();
        let s = lo.sign_ext(4).unwrap();
        let c = hi.concat(&lo).unwrap();
        for x in consistent(&a) {
            assert_eq!((x & 0xf) & lk, lv);
            assert_eq!((x >> 4) & hk, hv);
            let l = x & 0xf;
            assert_eq!(l & z.known().to_u64().unwrap(), z.value().to_u64().unwrap());
            let se = if l & 8 != 0 { l | 0xf0 } else { l };
            assert_eq!(se & s.known().to_u64().unwrap(), s.value().to_u64().unwrap());
            assert_eq!(x & c.known().to_u64().unwrap(), c.value().to_u64().unwrap());
        }
    }
}

#[test]
fn test_carry_propagation() {
    // (x & 0xff00) + 1: the low byte is known, the high byte is not
    assert_eq!(kb(0xff, 0, 16).add(&kb(0xffff, 1, 16)).unwrap().known().to_u64(), Some(0xff));
    assert_eq!(kb(0xff, 0, 16).add(&kb(0xffff, 1, 16)).unwrap().value().to_u64(), Some(1));
    // (x & 0xff) + 0xff: bits 0..8 are unknown, the sum is below 0x200
    let r = kb(0xff00, 0, 16).add(&kb(0xffff, 0xff, 16)).unwrap();
    assert_eq!(r.known().to_u64(), Some(0xfe00));
    assert_eq!(r.value().to_u64(), Some(0));
    // known low bits survive until the first unknown carry: (x | 0x7) + 1 has bits 0..2 = 0
    let r = kb(0x7, 0x7, 8).add(&kb(0xff, 1, 8)).unwrap();
    assert_eq!(r.known().to_u64(), Some(0x7));
    assert_eq!(r.value().to_u64(), Some(0));
    // known-1 carry: (x | 1) + (y | 1): bit 0 = 0, bit 1 unknown
    let r = kb(1, 1, 8).add(&kb(1, 1, 8)).unwrap();
    assert_eq!(r.known().to_u64(), Some(1));
    assert_eq!(r.value().to_u64(), Some(0));
    // sub: (x | 1) - 1: bit 0 known 0, no borrow into bit 1
    let r = kb(1, 1, 8).sub(&kb(0xff, 1, 8)).unwrap();
    assert_eq!(r.known().to_u64(), Some(1));
    // a - a with unknown a: nothing is known (bits are not tracked as correlated)
    let r = kb(0, 0, 8).sub(&kb(0, 0, 8)).unwrap();
    assert_eq!(r.known().to_u64(), Some(0));
}

// -------- folding through the simplifier --------

#[test]
fn test_examples() -> Result<()> {
    let ctx = Context::new();
    let r = ctx.bvs("r", 64)?;
    // (r & 0x68 | 0xf8) => 0xf8
    let e = ctx.or2(ctx.and2(&r, bvv(&ctx, 0x68, 64))?, bvv(&ctx, 0xf8, 64))?;
    assert_const(&e, 0xf8);

    // Themida mask chain
    let k = |v: u64| bvv(&ctx, v, 64);
    let e = ctx.or2(&r, k(0x201))?;
    let e = ctx.xor2(&e, k(0x7ff75452ef80))?;
    let e = ctx.sub(&e, k(0x42))?;
    let e = ctx.xor2(&e, k(0xc9))?;
    let e = ctx.add(&e, k(0x7ff75452ef04))?;
    let e = ctx.or2(&e, k(0x7ff75452ef05))?;
    let e = ctx.xor2(&e, k(0x7ff75452ed99))?;
    let e = ctx.or2(&e, k(0xcc))?;
    let e = ctx.xor2(&e, k(0xffffffffffffff32))?;
    let e = ctx.and2(&e, k(0x7ff75452ee04))?;
    let e = ctx.xor2(&e, k(0x106))?;
    let e = ctx.add(&e, k(0x80))?;
    let e = ctx.xor2(&e, k(0x7ff75452ee84))?;
    let e = ctx.add(&e, k(0x5c))?;
    let e = ctx.xor2(&e, k(0x82))?;
    assert_const(&e, 0x3e0);

    // flag-masked tail: (((s & 0x40) - 0xffffffffffffffe0 | 0xfb) ^ K | 0xffffffffffffffe0) * 2 | 0xcc) & 0x80) - 0xf7
    let s = ctx.bvs("s", 64)?;
    let e = ctx.and2(&s, k(0x40))?;
    let e = ctx.sub(&e, k(0xffffffffffffffe0))?;
    let e = ctx.or2(&e, k(0xfb))?;
    let e = ctx.xor2(&e, k(0x7ff75452ef88))?;
    let e = ctx.or2(&e, k(0xffffffffffffffe0))?;
    let e = ctx.mul(&e, k(2))?;
    let e = ctx.or2(&e, k(0xcc))?;
    let e = ctx.and2(&e, k(0x80))?;
    let e = ctx.sub(&e, k(0xf7))?;
    assert_const(&e, 0xffffffffffffff89);

    // rflags bits: a 1-bit flag zero-extended and shifted lands in one bit
    let f = ctx.bvs("f", 1)?;
    let e = ctx.shl(ctx.zero_ext(&f, 63)?, k(6))?;
    let e = ctx.and2(ctx.or2(&e, k(0x2))?, k(0xffbf))?;
    assert_const(&e, 0x2);
    Ok(())
}

#[test]
fn test_per_operator_folds() -> Result<()> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 8)?;
    let k = |v: u64| bvv(&ctx, v, 8);
    let hi = ctx.or2(&x, k(0xf0))?; // high nibble known 1
    let lo = ctx.and2(&x, k(0x0f))?; // high nibble known 0
    assert_const(&ctx.and2(&hi, k(0xf0))?, 0xf0);
    assert_const(&ctx.and2(ctx.or2(&lo, k(0xf0))?, k(0xf0))?, 0xf0);
    assert_const(&ctx.xor2(ctx.and2(&hi, k(0xf0))?, k(0x3))?, 0xf3);
    assert_const(&ctx.not(&lo)?.and2_const(&ctx, 0xf0)?, 0xf0);
    assert_const(&ctx.lshr(&hi, k(4))?, 0x0f);
    assert_const(&ctx.ashr(&hi, k(4))?, 0xff);
    assert_const(&ctx.shl(&lo, k(4))?.and2_const(&ctx, 0x0f)?, 0);
    assert_const(&ctx.extract(&hi, 7, 4)?, 0xf);
    assert_const(&ctx.extract(&lo, 7, 4)?, 0);
    assert_const(&ctx.extract(ctx.zero_ext(&x, 8)?, 15, 8)?, 0);
    assert_const(&ctx.extract(ctx.sign_ext(&hi, 8)?, 15, 8)?, 0xff);
    assert_const(
        &ctx.extract(ctx.concat2(&hi, &lo)?, 11, 4)?.and2_const(&ctx, 0x0f)?,
        0,
    );
    assert_const(&ctx.rotate_left(&hi, k(4))?.and2_const(&ctx, 0x0f)?, 0x0f);
    assert_const(&ctx.rotate_right(&hi, k(4))?.and2_const(&ctx, 0x0f)?, 0x0f);
    let c = ctx.bools("c")?;
    let e = ctx.ite(&c, ctx.or2(&x, k(0xf1))?, ctx.or2(&x, k(0xf2))?)?;
    assert_const(&ctx.and2(&e, k(0xf0))?, 0xf0);
    assert_const(&ctx.and2(ctx.neg(ctx.or2(&x, k(1))?)?, k(0x1))?, 1);
    assert_const(&ctx.and2(ctx.mul(&x, k(8))?, k(0x7))?, 0);
    assert_const(&ctx.and2(ctx.mul(&x, k(12))?, k(0x3))?, 0);
    assert_const(&ctx.and2(ctx.mul(&lo, k(0x30))?, k(0x0f))?, 0);
    assert_const(&ctx.and2(ctx.byte_reverse(ctx.zero_ext(&x, 8)?)?, bvv(&ctx, 0xff, 16))?, 0);
    Ok(())
}

trait Masked<'c> {
    fn and2_const(&self, ctx: &'c Context<'c>, v: u64) -> Result<AstRef<'c>>;
    fn or2_const(&self, ctx: &'c Context<'c>, v: u64) -> Result<AstRef<'c>>;
}

impl<'c> Masked<'c> for AstRef<'c> {
    fn and2_const(&self, ctx: &'c Context<'c>, v: u64) -> Result<AstRef<'c>> {
        Ok(ctx.and2(self, bvv(ctx, v, self.size()))?)
    }
    fn or2_const(&self, ctx: &'c Context<'c>, v: u64) -> Result<AstRef<'c>> {
        Ok(ctx.or2(self, bvv(ctx, v, self.size()))?)
    }
}

#[test]
fn test_partial_knowledge_leaves_shape() -> Result<()> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 64)?;
    let k = |v: u64| bvv(&ctx, v, 64);
    for e in [
        ctx.or2(&x, k(0xf0))?,
        ctx.and2(&x, k(0xf0))?,
        ctx.add(ctx.and2(&x, k(0xff00))?, k(1))?,
        ctx.xor2(ctx.or2(&x, k(1))?, k(0xff))?,
        ctx.and2(ctx.add(ctx.and2(&x, k(0xff))?, k(0xff))?, k(0x100))?,
        ctx.lshr(&x, ctx.bvs("n", 64)?)?,
        ctx.sub(&x, ctx.or2(&x, k(1))?)?.and2_const(&ctx, 1)?,
    ] {
        let s = e.simplify()?;
        assert!(s.symbolic(), "folded on partial knowledge");
    }
    assert_unchanged(&ctx.or2(&x, k(0xf0))?);
    assert_unchanged(&ctx.add(ctx.and2(&x, k(0xff00))?, k(1))?);
    let (known, value) = known_of(&ctx.add(ctx.and2(&x, k(0xff00))?, k(1))?);
    assert_eq!((known, value), (!0xff00u64, 1));
    let (known, _) = known_of(&ctx.add(ctx.and2(&x, k(0xff))?, k(0xff))?);
    assert_eq!(known, !0x1ffu64);
    Ok(())
}

#[test]
fn test_widths() -> Result<()> {
    let ctx = Context::new();
    let b = ctx.bvs("b", 1)?;
    assert_const(&ctx.or2(&b, bvv(&ctx, 1, 1))?, 1);
    assert_const(&ctx.and2(ctx.not(&b)?, &b)?, 0);
    assert_const(&ctx.and2(ctx.add(&b, &b)?, bvv(&ctx, 1, 1))?, 0);
    let x = ctx.bvs("x", 8)?;
    assert_const(&ctx.or2(ctx.and2(&x, bvv(&ctx, 0x68, 8))?, bvv(&ctx, 0xf8, 8))?, 0xf8);
    let w = ctx.bvs("w", 128)?;
    let one = ctx.bvv(BitVec::from((1u64, 128)))?;
    let low = ctx.bvv(BitVec::from((0xffu64, 128)))?;
    let high = ctx.bvv((!BitVec::from((0xffu64, 128)))?)?;
    // (w & 0xff) | 0xff..ff00: the low byte stays unknown
    let e = ctx.or2(ctx.and2(&w, &low)?, &high)?;
    assert!(e.simplify()?.symbolic());
    // ((w | 0xff) + 1) & 0xff = 0: the carry leaves the low byte
    let e = ctx.and2(ctx.add(ctx.or2(&w, &low)?, &one)?, &low)?;
    let s = e.simplify()?;
    assert!(matches!(s.op(), AstOp::BVV(v) if v.is_zero()));
    // ((w & 0xff..ff00) + 1) & 0xff = 1
    let e = ctx.and2(ctx.add(ctx.and2(&w, &high)?, &one)?, &low)?;
    let s = e.simplify()?;
    assert!(matches!(s.op(), AstOp::BVV(v) if v.is_one()));
    // (w | 0xff..ff00) >> 120 = 0xff
    let e = ctx.lshr(ctx.or2(&w, &high)?, ctx.bvv(BitVec::from((120u64, 128)))?)?;
    let s = e.simplify()?;
    assert!(matches!(s.op(), AstOp::BVV(v) if v.to_biguint() == num_bigint::BigUint::from(0xffu64)));
    let e = ctx.extract(ctx.shl(ctx.zero_ext(&x, 120)?, ctx.bvv(BitVec::from((100u64, 128)))?)?, 99, 0)?;
    let s = e.simplify()?;
    assert!(matches!(s.op(), AstOp::BVV(v) if v.is_zero()));
    Ok(())
}

#[test]
fn test_annotations() -> Result<()> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 32)?;
    let k = |v: u64| bvv(&ctx, v, 32);
    fn masked<'c>(ctx: &'c Context<'c>, y: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        ctx.or2(ctx.and2(y, bvv(ctx, 0x68, 32))?, bvv(ctx, 0xf8, 32))
    }

    // relocatable: folds, the annotation moves onto the constant
    let reloc = Annotation::new(AnnotationType::Uninitialized, false, true);
    let xa = ctx.annotate(&x, [reloc.clone()])?;
    let r = masked(&ctx, &xa)?.simplify()?;
    assert!(matches!(r.op(), AstOp::BVV(v) if v.to_u64() == Some(0xf8)));
    assert!(r.annotations().contains(&reloc));
    let r = ctx.annotate(&masked(&ctx, &x)?, [reloc.clone()])?.simplify()?;
    assert!(matches!(r.op(), AstOp::BVV(v) if v.to_u64() == Some(0xf8)));
    assert!(r.annotations().contains(&reloc));

    // eliminatable: folds, the annotation is dropped
    let elim = Annotation::new(AnnotationType::Uninitialized, true, false);
    let xe = ctx.annotate(&x, [elim.clone()])?;
    let r = masked(&ctx, &xe)?.simplify()?;
    assert!(matches!(r.op(), AstOp::BVV(v) if v.to_u64() == Some(0xf8)));
    assert!(r.annotations().is_empty());

    // pinned: opaque; a pinned node is never looked into or folded
    let pin = Annotation::new(AnnotationType::SimplificationAvoidance, false, false);
    let xp = ctx.annotate(&x, [pin.clone()])?;
    let e = ctx.or2(&xp, k(0xf8))?;
    assert!(e.simplify()?.symbolic());
    let inner = ctx.annotate(&ctx.and2(&x, k(0x68))?, [pin.clone()])?;
    let r = ctx.or2(&inner, k(0xf8))?.simplify()?;
    assert!(r.symbolic());
    let pinned_root = ctx.annotate(&masked(&ctx, &x)?, [pin])?;
    assert!(pinned_root.simplify()?.symbolic());
    Ok(())
}

#[test]
fn test_shared_dag_stays_fast() -> Result<()> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 64)?;
    let start = Instant::now();
    // e' = ((e ^ k) | e) & m: shared, partially known at every level
    let mut e = x.clone();
    for i in 0..60u64 {
        let k = bvv(&ctx, 0x1_0000 + i, 64);
        e = ctx.and2(ctx.or2(ctx.xor2(&e, &k)?, &e)?, bvv(&ctx, !(1u64 << (i % 60)), 64))?;
    }
    let s = e.simplify()?;
    assert!(s.symbolic(), "folded on partial knowledge");
    // the same with a mask that makes every level fully known
    let mut e = x.clone();
    for i in 0..60u64 {
        e = ctx.or2(ctx.add(ctx.and2(&e, bvv(&ctx, 0xff00, 64))?, &e)?, bvv(&ctx, 0xf0 + i, 64))?;
        e = ctx.and2(&e, bvv(&ctx, 0xf0, 64))?;
    }
    assert_const(&e, 0xf0);
    assert!(start.elapsed().as_secs_f64() < 2.0);
    Ok(())
}

// -------- urem / udiv --------

/// Every (known, value) pair of width `w`.
fn all_kb(w: u32) -> Vec<KnownBits> {
    let mut out = Vec::new();
    for known in 0..(1u64 << w) {
        for value in 0..(1u64 << w) {
            if value & !known == 0 {
                out.push(kb(known, value, w));
            }
        }
    }
    out
}

fn consistent_w(k: &KnownBits) -> Vec<u64> {
    let known = k.known().to_u64().unwrap();
    let value = k.value().to_u64().unwrap();
    (0..(1u64 << k.width()))
        .filter(|v| v & known == value)
        .collect()
}

fn urem_ref(x: u64, y: u64) -> u64 {
    if y == 0 { x } else { x % y }
}

fn udiv_ref(x: u64, y: u64, w: u32) -> u64 {
    if y == 0 { (1u64 << w) - 1 } else { x / y }
}

#[test]
fn test_transfer_urem_udiv_exhaustive() {
    for w in 1..=4u32 {
        let kbs = all_kb(w);
        for a in &kbs {
            for b in &kbs {
                let r = a.urem(b).unwrap();
                let d = a.udiv(b).unwrap();
                let (rk, rv) = (r.known().to_u64().unwrap(), r.value().to_u64().unwrap());
                let (dk, dv) = (d.known().to_u64().unwrap(), d.value().to_u64().unwrap());
                for x in consistent_w(a) {
                    for y in consistent_w(b) {
                        assert_eq!(urem_ref(x, y) & rk, rv, "urem unsound w={w} {x} {y}");
                        assert_eq!(udiv_ref(x, y, w) & dk, dv, "udiv unsound w={w} {x} {y}");
                    }
                }
            }
        }
    }
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    check_binary(|a, b| a.urem(b).unwrap(), urem_ref, &mut seed);
    check_binary(
        |a, b| a.udiv(b).unwrap(),
        |x, y| udiv_ref(x, y, 8),
        &mut seed,
    );
}

#[test]
fn test_urem_byte_extracts_fold() -> Result<()> {
    let ctx = Context::new();
    // ((0#32 .. a[31:0]) .. b) % 10, any byte above bit 3 is 0
    let a = ctx.bvs("a", 64)?;
    let b = ctx.bvs("b", 64)?;
    let wide = ctx.concat([bvv(&ctx, 0, 32), ctx.extract(&a, 31, 0)?, b.clone()])?;
    let rem = ctx.urem(&wide, ctx.bvv(BitVec::from((10u64, 128)))?)?;
    for lo in (8..128).step_by(8) {
        assert_const(&ctx.extract(&rem, lo + 7, lo)?, 0);
    }
    assert!(ctx.extract(&rem, 7, 0)?.simplify()?.symbolic());
    Ok(())
}
