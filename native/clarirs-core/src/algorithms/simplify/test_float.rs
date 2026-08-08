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
