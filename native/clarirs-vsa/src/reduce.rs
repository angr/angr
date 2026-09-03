mod bool;
mod bv;

use crate::strided_interval::{ComparisonResult, StridedInterval};
use clarirs_core::algorithms::walk;
use clarirs_core::cache::GenericCache;
use clarirs_core::prelude::*;

// Define an enum to represent the result of reduction
#[derive(Debug, Clone)]
pub enum ReduceResult {
    BitVec(StridedInterval),
    Bool(ComparisonResult),
}

impl ReduceResult {
    /// Extract the strided interval, erroring if this is not a bitvector result.
    pub fn into_bv(self) -> Result<StridedInterval, ClarirsError> {
        match self {
            ReduceResult::BitVec(si) => Ok(si),
            _ => Err(ClarirsError::InvalidArguments(
                "Expected BitVec result".to_string(),
            )),
        }
    }

    /// Extract the comparison result, erroring if this is not a bool result.
    pub fn into_bool(self) -> Result<ComparisonResult, ClarirsError> {
        match self {
            ReduceResult::Bool(result) => Ok(result),
            _ => Err(ClarirsError::InvalidArguments(
                "Expected Bool result".to_string(),
            )),
        }
    }
}

/// Reduces expressions into abstract domains:
/// - BitVec expressions are reduced to StridedIntervals
/// - Bool expressions are reduced to ComparisonResults
/// - Float and String expressions return errors
///
/// The result is wrapped in a [`ReduceResult`]; callers extract the relevant
/// variant via [`ReduceResult::into_bv`]/[`ReduceResult::into_bool`].
pub trait Reduce<'c>: Sized {
    fn reduce(&self) -> Result<ReduceResult, ClarirsError>;
}

impl<'c> Reduce<'c> for AstRef<'c> {
    fn reduce(&self) -> Result<ReduceResult, ClarirsError> {
        let cache = GenericCache::default();
        walk(
            self.clone(),
            |_| Ok(None),
            |node, children| match node.ast_type() {
                AstType::BitVec(_) => bv::reduce_bv(&node, children).map(ReduceResult::BitVec),
                AstType::Bool => bool::reduce_bool(&node, children).map(ReduceResult::Bool),
                _ => Err(ClarirsError::UnsupportedOperation(
                    "Unsupported operation for reduction".to_string(),
                )),
            },
            &cache,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduce_folds_every_operand_of_nary_ops() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let bv = |value: u64| ctx.bvv(BitVec::from((value, 8)));

        let sum = ctx.add_many([bv(1)?, bv(2)?, bv(3)?])?;
        assert_eq!(sum.reduce()?.into_bv()?, StridedInterval::constant(8, 6u8));

        let product = ctx.mul_many([bv(2)?, bv(3)?, bv(4)?])?;
        assert_eq!(
            product.reduce()?.into_bv()?,
            StridedInterval::constant(8, 24u8)
        );

        let xor = ctx.xor([bv(1)?, bv(2)?, bv(4)?])?;
        assert_eq!(xor.reduce()?.into_bv()?, StridedInterval::constant(8, 7u8));

        Ok(())
    }
}
