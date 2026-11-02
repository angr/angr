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

    fn batch_eval_n(
        &mut self,
        exprs: &[AstRef<'c>],
        n: u32,
    ) -> Result<Vec<Vec<AstRef<'c>>>, ClarirsError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        // VSA tracks each expression's value set independently and keeps no
        // relational information between them, so the set of consistent rows
        // is over-approximated by the cartesian product of the per-expression
        // value sets. Each column needs at most `n` values to fill `n` rows.
        let mut columns = Vec::with_capacity(exprs.len());
        for expr in exprs {
            let values = match expr.ast_type() {
                AstType::Bool => match expr.simplify()?.reduce()?.into_bool()? {
                    ComparisonResult::True => vec![self.context().boolv(true)?],
                    ComparisonResult::False => vec![self.context().boolv(false)?],
                    ComparisonResult::Maybe => {
                        vec![self.context().boolv(true)?, self.context().boolv(false)?]
                    }
                },
                AstType::BitVec(_) => {
                    let si = expr.simplify()?.reduce()?.into_bv()?;
                    if si.is_empty() {
                        return Ok(Vec::new());
                    }
                    si.eval(n)
                        .into_iter()
                        .map(|bv| self.context().bvv(BitVec::from((bv, expr.size()))))
                        .collect::<Result<Vec<_>, _>>()?
                }
                AstType::Float(_) | AstType::String => {
                    return Err(ClarirsError::UnsupportedOperation(
                        "Only boolean and bitvector evaluation is supported in VSASolver"
                            .to_string(),
                    ));
                }
            };
            columns.push(values);
        }

        // Rows are the cartesian product in lexicographic order of column
        // indices (the last column varies fastest): row `r` is `r` written in
        // mixed radix over the column lengths. No column is empty here.
        let total = columns
            .iter()
            .fold(1usize, |acc, column| acc.saturating_mul(column.len()));
        Ok((0..total.min(n as usize))
            .map(|mut r| {
                let mut row: Vec<AstRef<'c>> = columns
                    .iter()
                    .rev()
                    .map(|column| {
                        let value = column[r % column.len()].clone();
                        r /= column.len();
                        value
                    })
                    .collect();
                row.reverse();
                row
            })
            .collect())
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
            expr.context().bvv(BitVec::from((min_bound, expr.size())))
        })
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.simplify()?.reduce()?.into_bv().and_then(|si| {
            let (_, max_bound) = si.get_unsigned_bounds();
            expr.context().bvv(BitVec::from((max_bound, expr.size())))
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
                .bvv(BitVec::from((unsigned_min, expr.size())))
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
                .bvv(BitVec::from((unsigned_max, expr.size())))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_eval_n_combines_value_sets() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = VSASolver::new(&ctx);
        let k = |v: u64| ctx.bvv(BitVec::from((v, 8)));

        // A concrete bitvector has one value, a symbolic boolean two: the
        // rows are their product, each row one value per expression.
        let b = ctx.bools("b")?;
        let rows = solver.batch_eval_n(&[k(7)?, b.clone()], 5)?;
        assert_eq!(
            rows,
            vec![vec![k(7)?, ctx.true_()?], vec![k(7)?, ctx.false_()?]]
        );
        // Truncated to the requested count.
        assert_eq!(solver.batch_eval_n(&[k(7)?, b.clone()], 1)?.len(), 1);
        assert!(solver.batch_eval_n(std::slice::from_ref(&b), 0)?.is_empty());
        // The last column varies fastest: three rows of (b, x) all share the
        // first value of b and run through distinct values of x.
        let x = ctx.bvs("x", 8)?;
        let rows = solver.batch_eval_n(&[b.clone(), x], 3)?;
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row[0] == rows[0][0]));
        assert_ne!(rows[0][1], rows[1][1]);
        assert_ne!(rows[1][1], rows[2][1]);
        // No expressions: the single empty row.
        assert_eq!(solver.batch_eval_n(&[], 3)?, vec![Vec::new()]);

        // The single-expression entry points go through the same path.
        assert_eq!(solver.eval_n(&b, 5)?.len(), 2);
        assert_eq!(solver.eval(&k(7)?)?, k(7)?);
        Ok(())
    }
}
