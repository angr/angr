use std::collections::BTreeSet;

use crate::prelude::*;

/// A hybrid solver that combines an approximate solver with an exact solver.
///
/// Modeled after claripy's HybridFrontend, this solver maintains two backends:
/// - An **approximate** solver (e.g., VSA) for fast but imprecise results
/// - An **exact** solver (e.g., Z3) for precise constraint solving
///
/// Constraints are added to both solvers. For evaluation, the solver first
/// tries the approximate backend and falls back to the exact backend when:
/// - The approximate solver returns an error
/// - The approximate solver returns results that need validation
///
/// For operations requiring correctness (satisfiability, is_true, is_false),
/// the exact solver is always consulted when the approximate solver cannot
/// give a definitive answer.
#[derive(Clone, Debug)]
pub struct HybridSolver<'c, A: Solver<'c>, E: Solver<'c>> {
    approximate: A,
    exact: E,
    ctx: &'c Context<'c>,
}

impl<'c, A: Solver<'c>, E: Solver<'c>> HybridSolver<'c, A, E> {
    /// Create a new hybrid solver with the given approximate and exact backends.
    pub fn new(ctx: &'c Context<'c>, approximate: A, exact: E) -> Self {
        Self {
            approximate,
            exact,
            ctx,
        }
    }

    /// Get a reference to the approximate solver.
    pub fn approximate(&self) -> &A {
        &self.approximate
    }

    /// Get a mutable reference to the approximate solver.
    pub fn approximate_mut(&mut self) -> &mut A {
        &mut self.approximate
    }

    /// Get a reference to the exact solver.
    pub fn exact(&self) -> &E {
        &self.exact
    }

    /// Get a mutable reference to the exact solver.
    pub fn exact_mut(&mut self) -> &mut E {
        &mut self.exact
    }
}

impl<'c, A: Solver<'c>, E: Solver<'c>> HasContext<'c> for HybridSolver<'c, A, E> {
    fn context(&self) -> &'c Context<'c> {
        self.ctx
    }
}

impl<'c, A: Solver<'c>, E: Solver<'c>> Solver<'c> for HybridSolver<'c, A, E> {
    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        // Add constraints to both backends. The approximate solver may ignore
        // them (as VSA does), but the exact solver tracks them.
        let _ = self.approximate.add(constraint);
        self.exact.add(constraint)
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        let _ = self.approximate.clear();
        self.exact.clear()
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        self.exact.constraints()
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        let _ = self.approximate.simplify();
        self.exact.simplify()
    }

    fn variables(&self) -> Result<BTreeSet<InternedString>, ClarirsError> {
        self.exact.variables()
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        // Try approximate first - if it says definitely unsat, trust it.
        // Otherwise, fall back to exact.
        if let Ok(false) = self.approximate.satisfiable() {
            return Ok(false);
        }
        self.exact.satisfiable()
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        if let Ok(false) = self.approximate.satisfiable_with_extra(extra) {
            return Ok(false);
        }
        self.exact.satisfiable_with_extra(extra)
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        if !expr.symbolic() {
            return self.approximate.is_true(expr);
        }
        // For symbolic expressions, always consult exact solver
        self.exact.is_true(expr)
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        if !expr.symbolic() {
            return self.approximate.is_false(expr);
        }
        self.exact.is_false(expr)
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        if !expr.symbolic() {
            return self.approximate.has_true(expr);
        }
        // If approximate says definitely true, trust it (over-approximation is safe here)
        match self.approximate.has_true(expr) {
            Ok(true) => Ok(true),
            _ => self.exact.has_true(expr),
        }
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        if !expr.symbolic() {
            return self.approximate.has_false(expr);
        }
        match self.approximate.has_false(expr) {
            Ok(true) => Ok(true),
            _ => self.exact.has_false(expr),
        }
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        if !expr.symbolic() {
            return self.approximate.min_unsigned(expr);
        }
        self.exact.min_unsigned(expr)
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        if !expr.symbolic() {
            return self.approximate.max_unsigned(expr);
        }
        self.exact.max_unsigned(expr)
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        if !expr.symbolic() {
            return self.approximate.min_signed(expr);
        }
        self.exact.min_signed(expr)
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        if !expr.symbolic() {
            return self.approximate.max_signed(expr);
        }
        self.exact.max_signed(expr)
    }

    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        // Try the approximate solver first; verify symbolic results against
        // the exact solver, and fall back to it whenever the approximate
        // solver fails or produces nothing.
        if !expr.symbolic() {
            if let Ok(result) = self.approximate.eval_n(expr, n)
                && !result.is_empty()
            {
                return Ok(result);
            }
            return self.exact.eval_n(expr, n);
        }
        match self.approximate.eval_n(expr, n) {
            Ok(approx_results) if !approx_results.is_empty() => match self.exact.eval_n(expr, n) {
                Ok(exact) => Ok(exact),
                Err(_) => Ok(approx_results),
            },
            _ => self.exact.eval_n(expr, n),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ast::AstFactory;
    use crate::prelude::*;

    #[test]
    fn test_hybrid_solver_concrete() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let approx = ConcreteSolver::new(&ctx);
        let exact = ConcreteSolver::new(&ctx);
        let mut solver = HybridSolver::new(&ctx, approx, exact);

        let t = ctx.true_()?;
        let f = ctx.false_()?;
        assert!(solver.is_true(&t)?);
        assert!(solver.is_false(&f)?);
        assert!(!solver.is_true(&f)?);
        assert!(!solver.is_false(&t)?);

        let a = ctx.bvv_prim(10u8)?;
        let b = ctx.bvv_prim(20u8)?;
        let sum = ctx.add(&a, &b)?;
        let result = solver.eval(&sum)?;
        assert_eq!(result, ctx.bvv_prim(30u8)?);

        assert!(solver.satisfiable()?);

        Ok(())
    }
}
