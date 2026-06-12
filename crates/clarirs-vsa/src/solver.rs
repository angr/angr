use clarirs_core::prelude::*;
use num_traits::Signed;

use crate::{reduce::Reduce, strided_interval::ComparisonResult};

/// A solver that uses Value Set Analysis (VSA) for symbolic computation
#[derive(Clone, Debug)]
pub struct VSASolver<'c> {
    ctx: &'c Context<'c>,
}

impl<'c> VSASolver<'c> {
    /// Create a new VSA solver
    pub fn new(ctx: &'c Context<'c>) -> Self {
        Self { ctx }
    }
}

impl<'c> HasContext<'c> for VSASolver<'c> {
    fn context(&self) -> &'c Context<'c> {
        self.ctx
    }
}

impl<'c> Solver<'c> for VSASolver<'c> {
    fn add(&mut self, _: &AstRef<'c>) -> Result<(), ClarirsError> {
        Ok(())
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        Ok(())
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        Ok(vec![])
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        Ok(())
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        Ok(true)
    }

    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        match expr.ast_type() {
            AstType::Bool => expr
                .simplify()?
                .reduce()?
                .into_bool()
                .and_then(|comp_result| match comp_result {
                    ComparisonResult::True => Ok(vec![self.context().boolv(true)?]),
                    ComparisonResult::False => Ok(vec![self.context().boolv(false)?]),
                    ComparisonResult::Maybe => match n {
                        0 => Ok(vec![]),
                        1 => Ok(vec![self.context().boolv(true)?]),
                        _ => Ok(vec![
                            self.context().boolv(true)?,
                            self.context().boolv(false)?,
                        ]),
                    },
                }),
            AstType::BitVec(_) => expr.simplify()?.reduce()?.into_bv().and_then(|si| {
                if si.is_empty() {
                    return Ok(vec![]);
                }
                si.eval(n)
                    .into_iter()
                    .map(|bv| self.context().bvv_from_biguint_with_size(&bv, expr.size()))
                    .collect()
            }),
            AstType::Float(_) | AstType::String => Err(ClarirsError::UnsupportedOperation(
                "Only boolean and bitvector evaluation is supported in VSASolver".to_string(),
            )),
        }
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(matches!(
            expr.simplify()?.reduce()?.into_bool()?,
            ComparisonResult::True
        ))
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(matches!(
            expr.simplify()?.reduce()?.into_bool()?,
            ComparisonResult::False
        ))
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(matches!(
            expr.simplify()?.reduce()?.into_bool()?,
            ComparisonResult::True | ComparisonResult::Maybe
        ))
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        Ok(matches!(
            expr.simplify()?.reduce()?.into_bool()?,
            ComparisonResult::False | ComparisonResult::Maybe
        ))
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.simplify()?.reduce()?.into_bv().and_then(|si| {
            let (min_bound, _) = si.get_unsigned_bounds();
            expr.context()
                .bvv_from_biguint_with_size(&min_bound, expr.size())
        })
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.simplify()?.reduce()?.into_bv().and_then(|si| {
            let (_, max_bound) = si.get_unsigned_bounds();
            expr.context()
                .bvv_from_biguint_with_size(&max_bound, expr.size())
        })
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.simplify()?.reduce()?.into_bv().and_then(|si| {
            let (min_bound, _) = si.get_signed_bounds();
            // Convert BigInt back to unsigned representation for two's complement
            let unsigned_min = if min_bound.is_negative() {
                let modulus = num_bigint::BigUint::from(1u32) << expr.size();
                let abs_val = (-min_bound.clone()).to_biguint().unwrap();
                &modulus - &abs_val
            } else {
                min_bound.to_biguint().unwrap()
            };
            expr.context()
                .bvv_from_biguint_with_size(&unsigned_min, expr.size())
        })
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.simplify()?.reduce()?.into_bv().and_then(|si| {
            let (_, max_bound) = si.get_signed_bounds();
            // Convert BigInt back to unsigned representation for two's complement
            let unsigned_max = if max_bound.is_negative() {
                let modulus = num_bigint::BigUint::from(1u32) << expr.size();
                let abs_val = (-max_bound.clone()).to_biguint().unwrap();
                &modulus - &abs_val
            } else {
                max_bound.to_biguint().unwrap()
            };
            expr.context()
                .bvv_from_biguint_with_size(&unsigned_max, expr.size())
        })
    }
}
