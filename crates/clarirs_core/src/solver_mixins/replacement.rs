use std::collections::HashMap;

use crate::prelude::*;

/// A solver mixin that applies expression replacements before delegating to
/// the inner solver. This mirrors claripy's `ReplacementFrontend`.
///
/// When constraints of the form `x == <concrete>` are added, the replacement
/// solver automatically extracts the mapping and uses it to simplify future
/// queries. Explicit replacements can also be added via [`add_replacement`].
///
/// The replacement dictionary maps AST hashes to their replacement `AstRef`
/// values. When a query is made, all known replacements are applied to the
/// expression in a single pass before forwarding to the inner solver.
#[derive(Clone, Debug)]
pub struct ReplacementSolver<'c, S: Solver<'c>> {
    inner: S,
    /// The constraints as added, before replacement. claripy's
    /// ReplacementFrontend reports the original constraints; only the inner
    /// solver sees the replaced forms. Callers rely on this: e.g. rebuilding a
    /// solver from `constraints()` must not pick up values substituted by the
    /// replacements.
    original_constraints: Vec<AstRef<'c>>,
    /// The canonical set of replacements (hash → replacement AST).
    replacements: HashMap<u64, AstRef<'c>>,
    /// Cache that includes derived replacements from sub-expression traversal.
    replacement_cache: HashMap<u64, AstRef<'c>>,
    /// Whether to automatically extract replacements from `x == <concrete>` constraints.
    auto_replace: bool,
    _marker: std::marker::PhantomData<&'c ()>,
}

impl<'c, S: Solver<'c>> ReplacementSolver<'c, S> {
    pub fn new(inner: S) -> Self {
        Self::new_with_options(inner, true)
    }

    pub fn new_with_options(inner: S, auto_replace: bool) -> Self {
        Self {
            inner,
            original_constraints: Vec::new(),
            replacements: HashMap::new(),
            replacement_cache: HashMap::new(),
            auto_replace,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Add an explicit replacement mapping: occurrences of `old` will be
    /// replaced with `new` in all future queries.
    pub fn add_replacement(&mut self, old: AstRef<'c>, new: AstRef<'c>) {
        let hash = old.hash();
        self.replacements.insert(hash, new.clone());
        self.replacement_cache.insert(hash, new);
    }

    /// Remove specific replacements by their hashes.
    pub fn remove_replacements(&mut self, hashes: &[u64]) {
        for hash in hashes {
            self.replacements.remove(hash);
        }
        // Rebuild cache from canonical replacements
        self.replacement_cache = self.replacements.clone();
    }

    /// Clear all replacements.
    pub fn clear_replacements(&mut self) {
        self.replacements.clear();
        self.replacement_cache.clear();
    }

    /// Get the current replacement map (hash → AstRef).
    pub fn replacements(&self) -> &HashMap<u64, AstRef<'c>> {
        &self.replacements
    }

    /// Apply known replacements to an AstRef.
    fn apply_replacements(&self, ast: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        ast.replace_many(&self.replacement_cache)
    }

    /// Try to extract a replacement from an equality constraint like `sym == concrete`.
    fn try_extract_replacement(&mut self, constraint: &AstRef<'c>) {
        match constraint.op() {
            AstOp::Eq(lhs, rhs) => {
                if lhs.symbolic() && !rhs.symbolic() {
                    self.add_replacement(lhs.clone(), rhs.clone());
                } else if !lhs.symbolic() && rhs.symbolic() {
                    self.add_replacement(rhs.clone(), lhs.clone());
                }
            }
            AstOp::Not(inner) => {
                // Not(x) means x is false
                if inner.symbolic()
                    && let Ok(false_val) = constraint.context().false_()
                {
                    self.add_replacement(inner.clone(), false_val);
                }
            }
            _ => {}
        }
    }
}

impl<'c, S: Solver<'c>> HasContext<'c> for ReplacementSolver<'c, S> {
    fn context(&self) -> &'c Context<'c> {
        self.inner.context()
    }
}

impl<'c, S: Solver<'c>> Solver<'c> for ReplacementSolver<'c, S> {
    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        if self.auto_replace {
            self.try_extract_replacement(constraint);
        }

        self.original_constraints.push(constraint.clone());
        let replaced = self.apply_replacements(constraint)?;
        self.inner.add(&replaced)
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        self.original_constraints.clear();
        self.inner.clear()
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        Ok(self.original_constraints.clone())
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        self.inner.simplify()
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        self.inner.satisfiable()
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        let replaced = extra
            .iter()
            .map(|c| self.apply_replacements(c))
            .collect::<Result<Vec<_>, _>>()?;
        self.inner.satisfiable_with_extra(&replaced)
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.is_true(&replaced)
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.is_false(&replaced)
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.has_true(&replaced)
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.has_false(&replaced)
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.min_unsigned(&replaced)
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.max_unsigned(&replaced)
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.min_signed(&replaced)
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.max_signed(&replaced)
    }

    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.eval_n(&replaced, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::AstFactory;

    #[test]
    fn test_replacement_solver_basic() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv_prim(5u8)?;

        // Add explicit replacement: x -> 5
        solver.add_replacement(x.clone(), five.clone());

        // Evaluating x should now return 5
        let result = solver.eval(&x)?;
        assert_eq!(result, five);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_auto_extract() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv_prim(5u8)?;

        // Add constraint: x == 5 (should auto-extract replacement)
        let eq_constraint = ctx.eq_(&x, &five)?;
        solver.add(&eq_constraint)?;

        // Evaluating x should now return 5
        let result = solver.eval(&x)?;
        assert_eq!(result, five);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_expression() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv_prim(5u8)?;
        let three = ctx.bvv_prim(3u8)?;

        // Replace x with 5
        solver.add_replacement(x.clone(), five.clone());

        // Evaluating x + 3 should return 8
        let expr = ctx.add(&x, &three)?;
        let result = solver.eval(&expr)?;
        let expected = ctx.bvv_prim(8u8)?;
        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_clear() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv_prim(5u8)?;

        solver.add_replacement(x.clone(), five.clone());
        assert!(!solver.replacements().is_empty());

        solver.clear_replacements();
        assert!(solver.replacements().is_empty());

        Ok(())
    }

    #[test]
    fn test_replacement_solver_bool() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bools("x")?;

        // Replace x with true
        solver.add_replacement(x.clone(), ctx.true_()?);

        assert!(solver.is_true(&x)?);
        assert!(!solver.is_false(&x)?);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_reports_original_constraints() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let one = ctx.bvv_prim(1u8)?;
        let five = ctx.bvv_prim(5u8)?;
        let six = ctx.bvv_prim(6u8)?;

        // x == 5 auto-extracts the replacement x -> 5.
        let eq = ctx.eq_(&x, &five)?;
        solver.add(&eq)?;
        // x + 1 == 6 folds to `true` once x is replaced by 5, but constraints()
        // must report the original form, not the replaced one.
        let derived = ctx.eq_(&ctx.add(&x, &one)?, &six)?;
        solver.add(&derived)?;

        let constraints = solver.constraints()?;
        assert!(constraints.contains(&eq));
        assert!(constraints.contains(&derived));

        solver.clear()?;
        assert!(solver.constraints()?.is_empty());

        Ok(())
    }
}
