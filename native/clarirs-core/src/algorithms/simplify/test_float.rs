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
fn test_min_max_fma_round_fold_constants() -> Result<()> {
    let ctx = Context::new();
    let fpv = |v: f64| ctx.fpv(Float::from(v));

    assert_eq!(ctx.fp_min(fpv(1.0)?, fpv(2.0)?)?.simplify()?, fpv(1.0)?);
    assert_eq!(ctx.fp_max(fpv(1.0)?, fpv(2.0)?)?.simplify()?, fpv(2.0)?);
    assert_eq!(
        ctx.fp_min(fpv(f64::NAN)?, fpv(2.0)?)?.simplify()?,
        fpv(2.0)?
    );
    assert_eq!(
        ctx.fp_fma(fpv(0.1)?, fpv(10.0)?, fpv(-1.0)?, FPRM::NearestTiesToEven)?
            .simplify()?,
        fpv(0.1f64.mul_add(10.0, -1.0))?
    );
    assert_eq!(
        ctx.fp_round_to_integral(fpv(2.5)?, FPRM::NearestTiesToEven)?
            .simplify()?,
        fpv(2.0)?
    );

    // The FMA fold rounds to nearest-even, so another mode stays for Z3
    let rtz = ctx
        .fp_fma(fpv(0.1)?, fpv(10.0)?, fpv(-1.0)?, FPRM::TowardZero)?
        .simplify()?;
    assert!(matches!(rtz.op(), AstOp::FpFma(..)));

    // +0/-0 folds too, so the concrete solver can evaluate it
    let zeros = ctx.fp_min(fpv(0.0)?, fpv(-0.0)?)?.simplify()?;
    assert!(matches!(zeros.op(), AstOp::FPV(f) if f.is_zero() && f.sign()));
    Ok(())
}
