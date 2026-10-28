use crate::prelude::*;
use anyhow::Result;
use std::time::Instant;

fn bvv<'c>(ctx: &'c Context<'c>, v: u64, n: u32) -> AstRef<'c> {
    ctx.bvv(BitVec::from((v, n))).unwrap()
}

#[test]
fn test_cancel_add_sub() -> Result<()> {
    let ctx = Context::new();
    let y = ctx.bvs("y", 32)?;
    let c = bvv(&ctx, 3, 32);

    let e = ctx.sub(ctx.add(&c, &y)?, &y)?;
    assert_eq!(e.simplify()?, c);

    // 5 - (7 + y) + y + 7
    let e = ctx.add_many([
        ctx.sub(bvv(&ctx, 5, 32), ctx.add(bvv(&ctx, 7, 32), &y)?)?,
        y.clone(),
        bvv(&ctx, 7, 32),
    ])?;
    assert_eq!(e.simplify()?, bvv(&ctx, 5, 32));

    // (K - (C + Y)) + Y + C, built from binary adds
    let k = bvv(&ctx, 0x1400_0a000, 64);
    let cc = bvv(&ctx, 0x7f12_3456, 64);
    let yy = ctx.bvs("Y", 64)?;
    let e = ctx.add(ctx.add(ctx.sub(&k, ctx.add(&cc, &yy)?)?, &yy)?, &cc)?;
    assert_eq!(e.simplify()?, k);
    Ok(())
}

#[test]
fn test_partial_cancel_and_coefficients() -> Result<()> {
    let ctx = Context::new();
    let a = ctx.bvs("a", 32)?;
    let b = ctx.bvs("b", 32)?;
    let c = ctx.bvs("c", 32)?;

    // a - (b + c) + c => a - b
    let e = ctx.add(ctx.sub(&a, ctx.add(&b, &c)?)?, &c)?;
    assert_eq!(e.simplify()?, ctx.sub(&a, &b)?);

    // (a + a) - a => a
    let e = ctx.sub(ctx.add(&a, &a)?, &a)?;
    assert_eq!(e.simplify()?, a);

    // a + a + b - b => a * 2
    let e = ctx.sub(ctx.add_many([a.clone(), a.clone(), b.clone()])?, &b)?;
    assert_eq!(e.simplify()?, ctx.mul(&a, bvv(&ctx, 2, 32))?);

    // -a + a => 0, -(a - b) - b => -a
    assert_eq!(ctx.add(ctx.neg(&a)?, &a)?.simplify()?, bvv(&ctx, 0, 32));
    let e = ctx.sub(ctx.neg(ctx.sub(&a, &b)?)?, &b)?;
    assert_eq!(e.simplify()?, ctx.neg(&a)?);

    // 3*a - 2*a - a + 9 => 9
    let e = ctx.add_many([
        ctx.mul(&a, bvv(&ctx, 3, 32))?,
        ctx.neg(ctx.mul(bvv(&ctx, 2, 32), &a)?)?,
        ctx.neg(&a)?,
        bvv(&ctx, 9, 32),
    ])?;
    assert_eq!(e.simplify()?, bvv(&ctx, 9, 32));

    // no cancellation: shape is left to the existing rules
    let e = ctx.sub(ctx.add(&a, &b)?, &c)?;
    assert_eq!(e.simplify()?, e);
    Ok(())
}

#[test]
fn test_wraparound_and_widths() -> Result<()> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 32)?;
    let e = ctx.add_many([x.clone(), bvv(&ctx, 0xffff_ffff, 32), bvv(&ctx, 1, 32)])?;
    assert_eq!(e.simplify()?, x);

    // 1-bit: x + x == 0
    let b = ctx.bvs("b", 1)?;
    assert_eq!(ctx.add(&b, &b)?.simplify()?, bvv(&ctx, 0, 1));

    // 8-bit: x*0x80 + x*0x80 == 0
    let x8 = ctx.bvs("x8", 8)?;
    let h = ctx.mul(&x8, bvv(&ctx, 0x80, 8))?;
    assert_eq!(ctx.add(&h, &h)?.simplify()?, bvv(&ctx, 0, 8));

    // 128-bit: coefficients and constants wrap at 2^128
    let w = ctx.bvs("w", 128)?;
    let max = ctx.bvv(BitVec::ones(128))?;
    let e = ctx.sub(
        ctx.add_many([w.clone(), max.clone(), bvv(&ctx, 5, 128)])?,
        &w,
    )?;
    assert_eq!(e.simplify()?, bvv(&ctx, 4, 128));

    // terms of other widths are opaque
    let y8 = ctx.bvs("y8", 8)?;
    let e = ctx.zero_ext(ctx.sub(ctx.add(&x8, &y8)?, &y8)?, 24)?;
    assert_eq!(e.simplify()?, ctx.zero_ext(&x8, 24)?);
    let a = ctx.bvs("a", 64)?;
    let lo = ctx.extract(&a, 31, 0)?;
    let e = ctx.add(ctx.sub(&x, &lo)?, &lo)?;
    assert_eq!(e.simplify()?, x);
    let hi = ctx.extract(&a, 63, 32)?;
    let e = ctx.sub(ctx.add(&lo, &x)?, &hi)?;
    assert_eq!(e.simplify()?, e);
    Ok(())
}

#[test]
fn test_annotations() -> Result<()> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 32)?;
    let y = ctx.bvs("y", 32)?;
    let c = bvv(&ctx, 3, 32);

    // relocatable: cancels against the same annotated term and moves to the result
    let reloc = Annotation::new(AnnotationType::Uninitialized, false, true);
    let ya = ctx.annotate(&y, [reloc.clone()])?;
    let r = ctx.sub(ctx.add(&c, &ya)?, &ya)?.simplify()?;
    assert!(matches!(r.op(), AstOp::BVV(v) if v.to_u64() == Some(3)));
    assert!(r.annotations().contains(&reloc));
    // differently annotated leaves are different terms
    let e = ctx.sub(ctx.add(&c, &ya)?, &y)?;
    assert!(e.simplify()?.variables().len() == 1 && !matches!(e.simplify()?.op(), AstOp::BVV(_)));

    // eliminatable, not relocatable: cancels against itself only, and is dropped
    let elim = Annotation::new(AnnotationType::Uninitialized, true, false);
    let ye = ctx.annotate(&y, [elim])?;
    let r = ctx.sub(ctx.add(&x, &ye)?, &ye)?.simplify()?;
    assert_eq!(r, x);
    let e = ctx.sub(ctx.add(&x, &ye)?, &y)?;
    assert_eq!(e.simplify()?, e);

    // neither: never cancelled or merged
    let pin = Annotation::new(AnnotationType::SimplificationAvoidance, false, false);
    let yp = ctx.annotate(&y, [pin])?;
    let e = ctx.sub(ctx.add(&x, &yp)?, ctx.add(&yp, &c)?)?;
    let r = e.simplify()?;
    assert!(r.variables().len() == 2, "{r:?}");

    Ok(())
}

#[test]
fn test_shared_dag_stays_linear() -> Result<()> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 64)?;
    let start = Instant::now();

    // e' = (e + e) - e collapses at every level
    let mut e = x.clone();
    for _ in 0..60 {
        e = ctx.sub(ctx.add(&e, &e)?, &e)?;
    }
    // no Debug output on failure: these DAGs print as exponentially large trees
    assert!(e.simplify()? == x, "(e + e) - e not collapsed");

    // e' = (e ^ k) + e - k: shared, nothing cancels across levels
    let mut e = x.clone();
    for i in 0..60u64 {
        let k = bvv(&ctx, i + 1, 64);
        e = ctx.sub(ctx.add(ctx.xor2(&e, &k)?, &e)?, &k)?;
    }
    e.simplify()?;

    // e' = ((k - (c + e)) + e + c) + e, the VM handler shape; without cancellation the
    // flattened Add doubles per level
    let mut e = x.clone();
    let mut total = 0u64;
    for i in 0..16u64 {
        let k = bvv(&ctx, 0x1000 + i, 64);
        let c = bvv(&ctx, 0x77 * i, 64);
        let t = ctx.add(ctx.add(ctx.sub(&k, ctx.add(&c, &e)?)?, &e)?, &c)?;
        e = ctx.add(&t, &e)?;
        total += 0x1000 + i;
    }
    assert!(
        e.simplify()? == ctx.add(&x, bvv(&ctx, total, 64))?,
        "VM shape not collapsed"
    );
    assert!(start.elapsed().as_secs_f64() < 2.0);
    Ok(())
}
