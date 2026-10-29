use crate::{algorithms::simplify::SimplifyError, prelude::*};

pub(crate) fn simplify_float<'c>(
    state: &mut super::SimplifyState<'c>,
) -> Result<AstRef<'c>, SimplifyError<'c>> {
    let ctx = state.expr.context();
    let float_expr = state.expr.clone();

    match float_expr.op() {
        AstOp::FPS(..) | AstOp::FPV(_) => Ok(float_expr),

        AstOp::FpFP(..) => {
            let sign = state.get_child_simplified(0)?;
            let exp = state.get_child_simplified(1)?;
            let sig = state.get_child_simplified(2)?;

            // If all components are concrete, construct a concrete float
            match (sign.op(), exp.op(), sig.op()) {
                (AstOp::BVV(sign_bv), AstOp::BVV(exp_bv), AstOp::BVV(sig_bv)) => {
                    let float = Float::new(
                        !sign_bv.is_zero(), // sign is true if bit is 1
                        exp_bv.clone(),
                        sig_bv.clone(),
                    )?;
                    Ok(ctx.fpv(float)?)
                }
                _ => Ok(ctx.fp_fp(sign, exp, sig)?),
            }
        }

        AstOp::FpNeg(..) => {
            let inner = state.get_child_simplified(0)?;
            match inner.op() {
                AstOp::FPV(float) => Ok(ctx.fpv(-*float)?),
                _ => Ok(ctx.fp_neg(inner)?),
            }
        }
        AstOp::FpAbs(..) => {
            let inner = state.get_child_simplified(0)?;
            match inner.op() {
                AstOp::FPV(float) => Ok(ctx.fpv(float.abs())?),
                _ => Ok(ctx.fp_abs(inner)?),
            }
        }
        AstOp::FpAdd(_, _, fprm) => {
            let lhs = state.get_child_simplified(0)?;
            let rhs = state.get_child_simplified(1)?;
            match (lhs.op(), rhs.op()) {
                (AstOp::FPV(float1), AstOp::FPV(float2)) => Ok(ctx.fpv(*float1 + *float2)?),
                _ => Ok(ctx.fp_add(lhs, rhs, *fprm)?),
            }
        }
        AstOp::FpSub(_, _, fprm) => {
            let lhs = state.get_child_simplified(0)?;
            let rhs = state.get_child_simplified(1)?;
            match (lhs.op(), rhs.op()) {
                (AstOp::FPV(float1), AstOp::FPV(float2)) => Ok(ctx.fpv(*float1 - *float2)?),
                _ => Ok(ctx.fp_sub(lhs, rhs, *fprm)?),
            }
        }
        AstOp::FpMul(_, _, fprm) => {
            let lhs = state.get_child_simplified(0)?;
            let rhs = state.get_child_simplified(1)?;
            match (lhs.op(), rhs.op()) {
                (AstOp::FPV(float1), AstOp::FPV(float2)) => Ok(ctx.fpv(*float1 * *float2)?),
                _ => Ok(ctx.fp_mul(lhs, rhs, *fprm)?),
            }
        }
        AstOp::FpDiv(_, _, fprm) => {
            let lhs = state.get_child_simplified(0)?;
            let rhs = state.get_child_simplified(1)?;
            match (lhs.op(), rhs.op()) {
                (AstOp::FPV(float1), AstOp::FPV(float2)) => Ok(ctx.fpv(*float1 / *float2)?),
                _ => Ok(ctx.fp_div(lhs, rhs, *fprm)?),
            }
        }
        AstOp::FpSqrt(_, fprm) => {
            let inner = state.get_child_simplified(0)?;
            match inner.op() {
                AstOp::FPV(float_val) => Ok(ctx.fpv(float_val.sqrt())?),
                _ => Ok(ctx.fp_sqrt(inner, *fprm)?),
            }
        }
        AstOp::FpMin(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (AstOp::FPV(float1), AstOp::FPV(float2)) => Ok(ctx.fpv(float1.min(float2))?),
                _ => Ok(ctx.fp_min(arc, arc1)?),
            }
        }
        AstOp::FpMax(..) => {
            let (arc, arc1) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
            );
            match (arc.op(), arc1.op()) {
                (AstOp::FPV(float1), AstOp::FPV(float2)) => Ok(ctx.fpv(float1.max(float2))?),
                _ => Ok(ctx.fp_max(arc, arc1)?),
            }
        }
        AstOp::FpFma(.., fprm) => {
            let (a, b, c) = (
                state.get_child_simplified(0)?,
                state.get_child_simplified(1)?,
                state.get_child_simplified(2)?,
            );
            match (a.op(), b.op(), c.op()) {
                (AstOp::FPV(fa), AstOp::FPV(fb), AstOp::FPV(fc)) => {
                    Ok(ctx.fpv(fa.mul_add(fb, fc, *fprm))?)
                }
                _ => Ok(ctx.fp_fma(a, b, c, *fprm)?),
            }
        }
        AstOp::FpRoundToIntegral(_, fprm) => {
            let arc = state.get_child_simplified(0)?;
            match arc.op() {
                AstOp::FPV(float) => Ok(ctx.fpv(float.round_to_integral(*fprm))?),
                _ => Ok(ctx.fp_round_to_integral(arc, *fprm)?),
            }
        }
        AstOp::FpToFp(_, fsort, fprm) => {
            let inner = state.get_child_simplified(0)?;
            match inner.op() {
                AstOp::FPV(float_val) if float_val.fsort() == *fsort => Ok(inner),
                AstOp::FPV(float_val) => {
                    let converted_value = float_val.convert_to_format(*fsort, *fprm)?;
                    Ok(ctx.fpv(converted_value)?)
                }
                _ => Ok(ctx.fp_to_fp(inner, *fsort, *fprm)?),
            }
        }
        AstOp::BvToFp(_, fsort) => {
            let inner = state.get_child_simplified(0)?;
            match inner.op() {
                AstOp::BVV(bv_val) => {
                    // Extract sign, exponent, and mantissa from IEEE 754 representation
                    let total_bits = bv_val.len();
                    let man_bits = fsort.mantissa;

                    // Ensure the bitvector size matches the float sort
                    if total_bits != fsort.size() {
                        return Err(SimplifyError::Error(ClarirsError::InvalidArguments(
                            format!(
                                "bitvector size {} does not match float sort size {}",
                                total_bits,
                                fsort.size()
                            ),
                        )));
                    }

                    // Extract components: sign (1 bit) | exponent (exp_bits) | mantissa (man_bits)
                    let sign_bit = bv_val.extract(total_bits - 1, total_bits - 1)?;
                    let exponent = bv_val.extract(man_bits, total_bits - 2)?;
                    let mantissa = bv_val.extract(0, man_bits - 1)?;

                    // Construct Float from components
                    let float = Float::new(
                        !sign_bit.is_zero(), // sign is true if bit is 1
                        exponent,
                        mantissa,
                    )?;
                    Ok(ctx.fpv(float)?)
                }
                // Reinterpreting a float's own IEEE bit pattern back as a float
                // of the same sort is the identity: to_fp(to_ieee_bv(x)) = x.
                // Sound for NaN too -- SMT-LIB FP has a single NaN value, so
                // whichever NaN bit pattern to_ieee_bv picks converts back to x.
                AstOp::FpToIEEEBV(inner) if matches!(inner.ast_type(), AstType::Float(inner_fsort) if inner_fsort == *fsort) => {
                    Ok(inner.clone())
                }
                _ => Ok(ctx.bv_to_fp(inner, *fsort)?),
            }
        }
        AstOp::BvToFpSigned(_, fsort, fprm) => {
            let inner = state.get_child_simplified(0)?;
            match inner.op() {
                AstOp::BVV(bv_val) => {
                    // Handle conversion from signed bitvector to float
                    let float_value =
                        Float::from_bigint_with_rounding(&bv_val.to_bigint(), *fsort, *fprm)?;
                    Ok(ctx.fpv(float_value)?)
                }
                _ => Ok(ctx.bv_to_fp_signed(inner, *fsort, *fprm)?),
            }
        }
        AstOp::BvToFpUnsigned(_, fsort, fprm) => {
            let inner = state.get_child_simplified(0)?;
            match inner.op() {
                AstOp::BVV(bv_val) => {
                    // Interpret `bv_val` as an unsigned integer and convert to float
                    let float_value =
                        Float::from_biguint_with_rounding(&bv_val.to_biguint(), *fsort, *fprm)?;
                    Ok(ctx.fpv(float_value)?)
                }
                _ => Ok(ctx.bv_to_fp_unsigned(inner, *fsort, *fprm)?),
            }
        }
        AstOp::ITE(..) => super::simplify_ite(state),
        _ => unreachable!("non-float op dispatched to simplify_float"),
    }
}
