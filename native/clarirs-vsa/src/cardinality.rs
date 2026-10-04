use clarirs_core::prelude::*;
use num_bigint::BigUint;
use num_traits::One;

use crate::{reduce::Reduce, strided_interval::ComparisonResult};

pub trait Cardinality {
    fn cardinality(&self) -> Result<BigUint, ClarirsError>;
}

impl Cardinality for AstRef<'_> {
    fn cardinality(&self) -> Result<BigUint, ClarirsError> {
        match self.ast_type() {
            AstType::BitVec(_) => Ok(self.reduce()?.into_bv()?.cardinality()),
            AstType::Bool => match self.reduce()?.into_bool()? {
                ComparisonResult::True | ComparisonResult::False => Ok(BigUint::one()),
                ComparisonResult::Maybe => Ok(BigUint::from(2u32)),
            },
            // VSA does not track floats: a concrete one has a single value,
            // otherwise over-approximate with every bit pattern of the sort.
            AstType::Float(sort) => {
                if self.concrete() && matches!(self.simplify()?.op(), AstOp::FPV(_)) {
                    Ok(BigUint::one())
                } else {
                    Ok(BigUint::one() << sort.size())
                }
            }
            AstType::String => Err(ClarirsError::UnsupportedOperation(
                "Cardinality is not supported for this type".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_float_cardinality() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let fps = ctx.fps("fp", FSort::f32())?;
        let fpv = ctx.fpv(Float::from(1.0f32))?;
        let bvs = ctx.bvs("x", 32)?;

        assert_eq!(fpv.cardinality()?, BigUint::one());
        assert_eq!(fps.cardinality()?, BigUint::one() << 32u32);
        assert_eq!(ctx.fp_to_ieeebv(&fpv)?.cardinality()?, BigUint::one());
        assert_eq!(
            ctx.add(&bvs, ctx.fp_to_ieeebv(&fpv)?)?.cardinality()?,
            BigUint::one() << 32u32
        );
        assert_eq!(
            ctx.fp_to_ieeebv(&fps)?.cardinality()?,
            BigUint::one() << 32u32
        );
        assert_eq!(ctx.fp_is_nan(&fps)?.cardinality()?, BigUint::from(2u32));
        assert_eq!(ctx.fp_is_nan(&fpv)?.cardinality()?, BigUint::one());
        assert_eq!(ctx.eq_(&fps, &fpv)?.cardinality()?, BigUint::from(2u32));
        Ok(())
    }
}
