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
            _ => Err(ClarirsError::UnsupportedOperation(
                "Cardinality is not supported for this type".to_string(),
            )),
        }
    }
}
