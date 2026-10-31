mod composite;
mod concrete;
mod hybrid;

pub use composite::CompositeSolver;
pub use concrete::ConcreteSolver;
pub use hybrid::HybridSolver;

use std::collections::BTreeSet;

use crate::prelude::*;

pub trait Solver<'c>: Clone + HasContext<'c> {
    // Constraint management
    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError>;

    fn clear(&mut self) -> Result<(), ClarirsError>;

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError>;

    /// Simplify the constraints held internally by the solver
    fn simplify(&mut self) -> Result<(), ClarirsError>;

    /// Get all variables involved in the current set of constraints
    fn variables(&self) -> Result<BTreeSet<InternedString>, ClarirsError> {
        Ok(self
            .constraints()?
            .iter()
            .flat_map(|c| c.variables())
            .cloned()
            .collect())
    }

    /// Check if the current set of constraints is satisfiable
    fn satisfiable(&mut self) -> Result<bool, ClarirsError>;

    /// Check satisfiability with `extra` constraints temporarily added.
    /// The default clones the solver and adds the constraints; backends
    /// override this with cheaper scoped checks (e.g. Z3 assumptions on the
    /// persistent incremental solver). This is the hot path of symbolic
    /// execution: every branch feasibility check goes through it.
    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        if extra.is_empty() {
            return self.satisfiable();
        }
        let mut solver = self.clone();
        for constraint in extra {
            solver.add(constraint)?;
        }
        solver.satisfiable()
    }

    /// Evaluate an expression in the current model. The result has the same
    /// sort as the input expression.
    ///
    /// If the constraints are unsatisfiable, an error is returned.
    fn eval(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let mut results = self.eval_n(expr, 1)?;
        results.pop().ok_or(ClarirsError::Unsat)
    }

    /// Evaluate several expressions against a single, shared model, returning
    /// one value per input expression in order.
    ///
    /// Unlike calling [`Solver::eval`] in a loop, every value is drawn from the
    /// same satisfying assignment, so the results are mutually consistent. This
    /// is what makes the values usable as a *model*. Returns
    /// [`ClarirsError::Unsat`] if the constraints are unsatisfiable.
    ///
    /// The default implementation evaluates each expression independently,
    /// which is only consistent for solvers that admit a single model (e.g.
    /// [`ConcreteSolver`]). A backend that admits multiple models (e.g. Z3)
    /// must override this, and every mixin or frontend above such a backend
    /// must forward it as one call, or the values come from different models.
    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        exprs.iter().map(|expr| self.eval(expr)).collect()
    }

    /// Up to `n` distinct rows of values for `exprs`, each row drawn from a
    /// single model (claripy's `batch_eval`). For more than one row, the
    /// expressions are packed into one bitvector and enumerated with
    /// [`Solver::eval_n`], so rows get exactly the enumeration (scoped
    /// exclusions, budgets) of a single-expression query. Unsat yields no rows.
    fn batch_eval_n(
        &mut self,
        exprs: &[AstRef<'c>],
        n: u32,
    ) -> Result<Vec<Vec<AstRef<'c>>>, ClarirsError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if exprs.is_empty() {
            return Ok(vec![Vec::new()]);
        }
        if n == 1 {
            return match self.batch_eval(exprs) {
                Ok(row) => Ok(vec![row]),
                Err(ClarirsError::Unsat) => Ok(Vec::new()),
                Err(e) => Err(e),
            };
        }
        let ctx = self.context();
        match pack_exprs(ctx, exprs)? {
            Some(packed) => match self.eval_n(&packed, n) {
                Ok(values) => values
                    .iter()
                    .map(|value| unpack_row(ctx, exprs, value))
                    .collect(),
                Err(ClarirsError::Unsat) => Ok(Vec::new()),
                Err(e) => Err(e),
            },
            None => batch_eval_n_by_blocking(self, exprs, n),
        }
    }

    /// Check if an expression is true in the current model. If the constraints are unsatisfiable, an
    /// error is returned. Equivalent to `eval(expr) == ctx.true_()`
    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError>;

    /// Check if an expression is false in the current model. If the constraints are unsatisfiable, an
    /// error is returned. Equivalent to `eval(expr) == ctx.false_()`
    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError>;

    /// Check if an expression could be true in the current model. If the constraints are unsatisfiable, an
    /// error is returned. Equivalent to `eval(expr) == ctx.true_()`
    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError>;

    /// Check if an expression could be false in the current model. If the constraints are unsatisfiable, an
    /// error is returned. Equivalent to `eval(expr) == ctx.false_()`
    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError>;

    /// Get the minimum value of an expression in the current model, interpreting the bitvector as unsigned.
    /// If the constraints are unsatisfiable, an error is returned.
    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError>;

    /// Get the maximum value of an expression in the current model, interpreting the bitvector as unsigned.
    /// If the constraints are unsatisfiable, an error is returned.
    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError>;

    /// Get the minimum value of an expression in the current model, interpreting the bitvector as signed.
    /// If the constraints are unsatisfiable, an error is returned.
    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError>;

    /// Get the maximum value of an expression in the current model, interpreting the bitvector as signed.
    /// If the constraints are unsatisfiable, an error is returned.
    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError>;

    /// Find up to `n` solutions for an expression. The results have the same
    /// sort as the input expression.
    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError>;

    /// `eval_n(expr, 2)` for callers that only need to know whether `expr` has a single value:
    /// one result is that value, none means unsatisfiable, and two results only mean "more than
    /// one value" (they need not be the two `eval_n` would return).
    fn eval_unique(&mut self, expr: &AstRef<'c>) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        self.eval_n(expr, 2)
    }
}

/// Width of `expr` in a packed row, or `None` if it has no fixed-width bit
/// encoding that `unpack_row` can decode.
fn packed_width(expr: &AstRef<'_>) -> Option<u32> {
    match expr.ast_type() {
        AstType::BitVec(w) => Some(w),
        AstType::Bool => Some(1),
        AstType::Float(fsort) if matches!(fsort.size(), 32 | 64) => Some(fsort.size()),
        _ => None,
    }
}

/// All of `exprs` as one bitvector, first expression in the high bits.
fn pack_exprs<'c>(
    ctx: &'c Context<'c>,
    exprs: &[AstRef<'c>],
) -> Result<Option<AstRef<'c>>, ClarirsError> {
    let mut parts = Vec::with_capacity(exprs.len());
    for expr in exprs {
        if packed_width(expr).is_none() {
            return Ok(None);
        }
        parts.push(match expr.ast_type() {
            AstType::Bool => ctx.ite(
                expr,
                ctx.bvv(BitVec::from((1, 1)))?,
                ctx.bvv(BitVec::from((0, 1)))?,
            )?,
            AstType::Float(_) => ctx.fp_to_ieeebv(expr)?,
            _ => expr.clone(),
        });
    }
    if parts.len() == 1 {
        return Ok(parts.pop());
    }
    Ok(Some(ctx.concat(parts)?))
}

fn unpack_row<'c>(
    ctx: &'c Context<'c>,
    exprs: &[AstRef<'c>],
    value: &AstRef<'c>,
) -> Result<Vec<AstRef<'c>>, ClarirsError> {
    let AstOp::BVV(bits) = value.op() else {
        return Err(ClarirsError::UnsupportedOperation(
            "batch_eval_n: solver returned a non-constant row".to_string(),
        ));
    };
    let mut row = Vec::with_capacity(exprs.len());
    let mut low = 0;
    for expr in exprs.iter().rev() {
        let width = packed_width(expr).expect("checked by pack_exprs");
        let slice = bits.extract(low, low + width - 1)?;
        low += width;
        row.push(match expr.ast_type() {
            AstType::Bool => ctx.boolv(!slice.is_zero())?,
            AstType::Float(_) => ctx.fpv(Float::try_from_ieee_bits(&slice)?)?,
            _ => ctx.bvv(slice)?,
        });
    }
    row.reverse();
    Ok(row)
}

/// Enumerate rows by adding a clause that blocks each row found, on a copy of
/// the solver. Used for expressions that cannot be packed (strings).
fn batch_eval_n_by_blocking<'c, S: Solver<'c>>(
    solver: &S,
    exprs: &[AstRef<'c>],
    n: u32,
) -> Result<Vec<Vec<AstRef<'c>>>, ClarirsError> {
    let ctx = solver.context();
    let mut work = solver.clone();
    let mut rows = Vec::new();
    for _ in 0..n {
        let row = match work.batch_eval(exprs) {
            Ok(row) => row,
            Err(ClarirsError::Unsat) => break,
            Err(e) => return Err(e),
        };
        let disequalities = exprs
            .iter()
            .zip(&row)
            .map(|(expr, value)| ctx.neq(expr, value))
            .collect::<Result<Vec<_>, _>>()?;
        work.add(&ctx.or(disequalities)?)?;
        rows.push(row);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::{BTreeSet, HashMap};
    use std::rc::Rc;

    use super::*;

    /// Brute-force solver over a fixed set of small variables. `eval_n` starts
    /// at a different model on every call, as a real backend may, so only a
    /// single `batch_eval` call yields a consistent row.
    #[derive(Clone, Debug)]
    struct Brute<'c> {
        ctx: &'c Context<'c>,
        vars: Vec<AstRef<'c>>,
        constraints: Vec<AstRef<'c>>,
        cursor: Rc<Cell<usize>>,
    }

    impl<'c> Brute<'c> {
        fn new(ctx: &'c Context<'c>, vars: &[AstRef<'c>]) -> Self {
            Self { ctx, vars: vars.to_vec(), constraints: Vec::new(), cursor: Rc::new(Cell::new(0)) }
        }

        fn models(&self) -> Result<Vec<HashMap<u64, AstRef<'c>>>, ClarirsError> {
            let mut models = vec![HashMap::new()];
            for var in &self.vars {
                let mut next = Vec::new();
                for m in &models {
                    for v in 0..(1u64 << var.size()) {
                        let mut m: HashMap<u64, AstRef<'c>> = m.clone();
                        m.insert(var.hash(), self.ctx.bvv(BitVec::from((v, var.size())))?);
                        next.push(m);
                    }
                }
                models = next;
            }
            let mut sat = Vec::new();
            for m in models {
                let mut ok = true;
                for c in &self.constraints {
                    ok &= c.replace_many(&m)?.simplify()?.is_true();
                }
                if ok {
                    sat.push(m);
                }
            }
            Ok(sat)
        }

        fn rotated_models(&self) -> Result<Vec<HashMap<u64, AstRef<'c>>>, ClarirsError> {
            let mut models = self.models()?;
            if models.is_empty() {
                return Err(ClarirsError::Unsat);
            }
            let k = self.cursor.get() % models.len();
            self.cursor.set(self.cursor.get() + 1);
            models.rotate_left(k);
            Ok(models)
        }
    }

    impl<'c> HasContext<'c> for Brute<'c> {
        fn context(&self) -> &'c Context<'c> {
            self.ctx
        }
    }

    impl<'c> Solver<'c> for Brute<'c> {
        fn add(&mut self, c: &AstRef<'c>) -> Result<(), ClarirsError> {
            self.constraints.push(c.clone());
            Ok(())
        }
        fn clear(&mut self) -> Result<(), ClarirsError> {
            self.constraints.clear();
            Ok(())
        }
        fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
            Ok(self.constraints.clone())
        }
        fn simplify(&mut self) -> Result<(), ClarirsError> {
            Ok(())
        }
        fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
            Ok(!self.models()?.is_empty())
        }
        fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
            let m = self.rotated_models()?.swap_remove(0);
            exprs.iter().map(|e| e.replace_many(&m)?.simplify()).collect()
        }
        fn is_true(&mut self, _: &AstRef<'c>) -> Result<bool, ClarirsError> {
            unimplemented!()
        }
        fn is_false(&mut self, _: &AstRef<'c>) -> Result<bool, ClarirsError> {
            unimplemented!()
        }
        fn has_true(&mut self, _: &AstRef<'c>) -> Result<bool, ClarirsError> {
            unimplemented!()
        }
        fn has_false(&mut self, _: &AstRef<'c>) -> Result<bool, ClarirsError> {
            unimplemented!()
        }
        fn min_unsigned(&mut self, _: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            unimplemented!()
        }
        fn max_unsigned(&mut self, _: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            unimplemented!()
        }
        fn min_signed(&mut self, _: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            unimplemented!()
        }
        fn max_signed(&mut self, _: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            unimplemented!()
        }
        fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
            let mut out: Vec<AstRef<'c>> = Vec::new();
            let models = match self.rotated_models() {
                Ok(models) => models,
                Err(ClarirsError::Unsat) => return Ok(out),
                Err(e) => return Err(e),
            };
            for m in models {
                let v = expr.replace_many(&m)?.simplify()?;
                if out.len() < n as usize && !out.contains(&v) {
                    out.push(v);
                }
            }
            Ok(out)
        }
    }

    fn bv<'c>(ctx: &'c Context<'c>, v: u64, w: u32) -> AstRef<'c> {
        ctx.bvv(BitVec::from((v, w))).unwrap()
    }

    /// Every row satisfies the constraints jointly, rows are distinct, and the
    /// set equals the brute-force set (truncated to `n`).
    fn check_rows<'c, S: Solver<'c>>(
        solver: &mut S,
        reference: &Brute<'c>,
        exprs: &[AstRef<'c>],
        n: u32,
    ) -> Result<(), ClarirsError> {
        let rows = solver.batch_eval_n(exprs, n)?;
        let mut expected = BTreeSet::new();
        for m in reference.models()? {
            let row: Vec<AstRef<'c>> =
                exprs.iter().map(|e| e.replace_many(&m)?.simplify()).collect::<Result<_, _>>()?;
            expected.insert(row.iter().map(|v| v.hash()).collect::<Vec<_>>());
        }
        let got: BTreeSet<Vec<u64>> =
            rows.iter().map(|r| r.iter().map(|v| v.hash()).collect()).collect();
        assert_eq!(got.len(), rows.len(), "duplicate rows");
        assert_eq!(rows.len(), expected.len().min(n as usize));
        assert!(got.is_subset(&expected), "a row matches no single model");
        Ok(())
    }

    #[test]
    fn test_replacement_batch_eval_is_one_model() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 3)?;
        let mut solver = ReplacementSolver::new(Brute::new(&ctx, std::slice::from_ref(&x)));
        let x1 = ctx.add(&x, &bv(&ctx, 1, 3))?;
        for _ in 0..8 {
            let row = solver.batch_eval(&[x.clone(), x1.clone()])?;
            assert_eq!(ctx.add(&row[0], &bv(&ctx, 1, 3))?.simplify()?, row[1]);
        }
        Ok(())
    }

    #[test]
    fn test_batch_eval_n_rows_are_models() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 3)?;
        let y = ctx.bvs("y", 3)?;
        let vars = [x.clone(), y.clone()];
        let mut solver = ReplacementSolver::new_with_options(Brute::new(&ctx, &vars), false);
        let mut reference = Brute::new(&ctx, &vars);
        let c = ctx.ult(&x, &bv(&ctx, 3, 3))?;
        solver.add(&c)?;
        reference.add(&c)?;
        let lt1 = ctx.ult(&x, &bv(&ctx, 1, 3))?;
        let sum = ctx.add(&x, &y)?;

        check_rows(&mut solver, &reference, &[x.clone(), sum.clone()], 100)?;
        check_rows(&mut solver, &reference, &[x.clone(), sum.clone()], 3)?;
        check_rows(&mut solver, &reference, &[lt1.clone(), x.clone()], 100)?;
        check_rows(&mut solver, &reference, &[lt1.clone()], 5)?;
        check_rows(&mut solver, &reference, &[x.clone(), sum.clone()], 1)?;
        assert!(solver.batch_eval_n(&[x.clone()], 0)?.is_empty());

        // A replacement applies to every expression of the row.
        let y_is_x1 = ctx.eq_(&y, &ctx.add(&x, &bv(&ctx, 1, 3))?)?;
        solver.add_replacement(y.clone(), ctx.add(&x, &bv(&ctx, 1, 3))?);
        reference.add(&y_is_x1)?;
        check_rows(&mut solver, &reference, &[x.clone(), y.clone(), lt1.clone()], 100)?;

        // The blocking-clause fallback agrees.
        let mut expected = BTreeSet::new();
        for row in solver.batch_eval_n(&[x.clone(), sum.clone()], 100)? {
            expected.insert(row.iter().map(|v| v.hash()).collect::<Vec<_>>());
        }
        let mut got = BTreeSet::new();
        for row in batch_eval_n_by_blocking(&solver, &[x.clone(), sum.clone()], 100)? {
            got.insert(row.iter().map(|v| v.hash()).collect::<Vec<_>>());
        }
        assert_eq!(got, expected);

        solver.add(&ctx.eq_(&x, &bv(&ctx, 7, 3))?)?;
        assert!(solver.batch_eval_n(&[x.clone(), sum], 4)?.is_empty());
        Ok(())
    }

    #[test]
    fn test_composite_batch_eval_n_spans_children() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 2)?;
        let y = ctx.bvs("y", 2)?;
        let vars = [x.clone(), y.clone()];
        let mut solver = CompositeSolver::new(&ctx, Brute::new(&ctx, &vars));
        let mut reference = Brute::new(&ctx, &vars);
        for c in [ctx.ult(&x, &bv(&ctx, 2, 2))?, ctx.ugt(&y, &bv(&ctx, 1, 2))?] {
            solver.add(&c)?;
            reference.add(&c)?;
        }
        let xor = ctx.xor([x.clone(), y.clone()])?;
        check_rows(&mut solver, &reference, &[x.clone(), y.clone(), xor.clone()], 100)?;
        check_rows(&mut solver, &reference, &[y.clone(), xor], 1)?;
        Ok(())
    }

    #[test]
    fn test_batch_eval_n_unpacks_mixed_sorts() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = ConcreteSolver::new(&ctx);
        let exprs = [bv(&ctx, 0xabc, 12), ctx.true_()?, ctx.fpv(1.5f64)?, ctx.fpv(-2.0f32)?, ctx.false_()?];
        let rows = solver.batch_eval_n(&exprs, 3)?;
        assert_eq!(rows, vec![exprs.to_vec()]);
        Ok(())
    }
}
