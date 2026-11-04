use crate::prelude::*;
use anyhow::Result;

#[test]
fn test_bv_to_fp_of_fp_to_ieeebv_is_identity() -> Result<()> {
    let ctx = Context::new();

    let x = ctx.fps("x", FSort::f64())?;
    let round_trip = ctx.bv_to_fp(ctx.fp_to_ieeebv(&x)?, FSort::f64())?;

    assert_eq!(round_trip.simplify()?, x);
    Ok(())
}

#[test]
fn test_bv_to_fp_of_fp_to_ieeebv_different_sort_not_simplified() -> Result<()> {
    let ctx = Context::new();

    // Reinterpreting an f64's 64-bit pattern as some other 64-bit float sort
    // is NOT the identity; the round-trip must be preserved.
    let odd_sort = FSort::new(15, 49);
    let x = ctx.fps("x", FSort::f64())?;
    let reinterpret = ctx.bv_to_fp(ctx.fp_to_ieeebv(&x)?, odd_sort)?;

    let simplified = reinterpret.simplify()?;
    assert!(matches!(simplified.op(), AstOp::BvToFp(..)));
    Ok(())
}

#[test]
fn test_ite_absorbs_nested_ite_on_same_condition() -> Result<()> {
    let ctx = Context::new();
    let c = ctx.bools("c")?;
    let a = ctx.fps("a", FSort::f64())?;
    let b = ctx.fps("b", FSort::f64())?;
    let d = ctx.fps("d", FSort::f64())?;
    let inner = ctx.ite(&c, &a, &b)?;

    assert_eq!(ctx.ite(&c, &inner, &d)?.simplify()?, ctx.ite(&c, &a, &d)?);
    assert_eq!(ctx.ite(&c, &d, &inner)?.simplify()?, ctx.ite(&c, &d, &b)?);
    Ok(())
}
