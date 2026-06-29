use std::collections::{HashMap, HashSet};

use crate::algorithms::collect_vars::collect_vars;
use crate::prelude::*;

/// Upper bound on the number of distinct models retained. Bounds the work each
/// query may do scanning the cache; once reached, no new models are stored
/// (existing ones are still used).
const MAX_CACHED_MODELS: usize = 64;

/// A cached satisfying assignment: a map from each variable's hash to a
/// concrete value, plus bookkeeping to keep reuse cheap. This mirrors
/// claripy's `ModelCache`.
#[derive(Clone, Debug)]
struct Model<'c> {
    /// Variable hash -> concrete value.
    assignments: HashMap<u64, AstRef<'c>>,
    /// Order-independent signature of `assignments`, used to deduplicate
    /// models without comparing the whole map.
    signature: u64,
    /// Hashes of persistent constraints this model is already known to
    /// satisfy. Because constraints are only ever appended, re-checking a
    /// model against the growing set only evaluates the constraints it has not
    /// seen yet, keeping verification amortized-cheap.
    verified: HashSet<u64>,
}

impl<'c> Model<'c> {
    fn new(assignments: HashMap<u64, AstRef<'c>>) -> Self {
        let signature = assignments
            .iter()
            .map(|(k, v)| k.wrapping_mul(31).wrapping_add(v.hash()))
            .fold(0u64, u64::wrapping_add);
        Self {
            assignments,
            signature,
            verified: HashSet::new(),
        }
    }

    /// Evaluate `expr` under this assignment. The result is concrete when the
    /// assignment covers every variable in `expr`; otherwise it stays
    /// (partially) symbolic and callers must treat it as a cache miss.
    fn eval(&self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.replace_many(&self.assignments)?.simplify()
    }

    /// Whether this model satisfies every persistent constraint. Constraints
    /// already verified are skipped. Returns `false` on the first constraint
    /// the model fails (or cannot decide); the caller then discards the model
    /// as stale.
    fn satisfies(&mut self, constraints: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        for c in constraints {
            if self.verified.contains(&c.hash()) {
                continue;
            }
            if self.eval(c)?.is_true() {
                self.verified.insert(c.hash());
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether this model satisfies all of `extra`. These transient
    /// constraints are never memoized, since they are not part of the solver's
    /// persistent set.
    fn satisfies_extra(&self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        for c in extra {
            if !self.eval(c)?.is_true() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A mixin that caches satisfiability results and satisfying models, reusing
/// them to answer queries without re-invoking the underlying solver.
///
/// This is what distinguishes claripy's `Solver` from `SolverCacheless`: the
/// former layers `SatCacheMixin` + `ModelCacheMixin` over the backend, the
/// latter does not. The two caches mirror those mixins:
/// - `sat`: the satisfiability of the current constraint set (claripy's
///   `SatCacheMixin`).
/// - `models`: known satisfying assignments, populated by evaluation and
///   reused to answer `eval`/`satisfiable` without the backend (claripy's
///   `ModelCacheMixin`).
///
/// The cache only ever *avoids* work — it can never change an answer:
/// - A model is only trusted after it has been verified to satisfy the current
///   constraints, so a backend returning an inconsistent assignment simply
///   yields a cache miss.
/// - When the cache cannot fully answer a query, the underlying solver is
///   consulted and remains authoritative.
#[derive(Clone, Debug)]
pub struct ModelCacheMixin<'c, S: Solver<'c>> {
    inner: S,
    /// Cached satisfiability of the current constraints, when known. `None`
    /// means "unknown, ask the solver". Adding a constraint can only turn a
    /// satisfiable set unsatisfiable, never the reverse, so an unsatisfiable
    /// result survives `add` while a satisfiable one is invalidated.
    sat: Option<bool>,
    /// Known satisfying assignments for the current constraints.
    models: Vec<Model<'c>>,
}

impl<'c, S: Solver<'c>> ModelCacheMixin<'c, S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            sat: None,
            models: Vec::new(),
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Extract a model from the inner solver for the current constraints and
    /// cache it for future reuse. Best-effort: any failure (including an
    /// unverifiable assignment) is silently ignored, since the cache is only
    /// an optimization.
    fn cache_model(&mut self) {
        if self.models.len() >= MAX_CACHED_MODELS {
            return;
        }
        let _ = self.try_cache_model();
    }

    fn try_cache_model(&mut self) -> Result<(), ClarirsError> {
        let constraints = self.inner.constraints()?;

        // Collect every distinct variable leaf across all constraints.
        let mut leaves: Vec<AstRef<'c>> = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        for c in &constraints {
            for v in collect_vars(c)? {
                if seen.insert(v.hash()) {
                    leaves.push(v);
                }
            }
        }

        // A single batch_eval yields a consistent assignment for all leaves.
        let values = match self.inner.batch_eval(&leaves) {
            Ok(values) => values,
            Err(ClarirsError::Unsat) => {
                self.sat = Some(false);
                return Ok(());
            }
            // Don't let caching surface backend errors; treat as a miss.
            Err(_) => return Ok(()),
        };

        let assignments: HashMap<u64, AstRef<'c>> =
            leaves.iter().map(|l| l.hash()).zip(values).collect();
        let mut model = Model::new(assignments);

        // Only trust the model if it actually satisfies the constraints. This
        // guards against backends that don't return a consistent model.
        if !model.satisfies(&constraints).unwrap_or(false) {
            return Ok(());
        }
        if self.models.iter().any(|m| m.signature == model.signature) {
            return Ok(());
        }
        self.models.push(model);
        Ok(())
    }

    /// Return true if a cached model satisfies all `constraints`. Models found
    /// to be stale (failing a constraint) are dropped along the way.
    fn has_witness(&mut self, constraints: &[AstRef<'c>]) -> bool {
        while let Some(model) = self.models.first_mut() {
            match model.satisfies(constraints) {
                Ok(true) => return true,
                _ => {
                    self.models.swap_remove(0);
                }
            }
        }
        false
    }

    /// Return true if a cached model satisfies all `constraints` *and* all
    /// `extra`. A model that satisfies the persistent constraints but not the
    /// transient `extra` is kept (it remains a valid witness for the persistent
    /// set); only genuinely stale models are dropped.
    fn has_witness_with_extra(&mut self, constraints: &[AstRef<'c>], extra: &[AstRef<'c>]) -> bool {
        let mut i = 0;
        while i < self.models.len() {
            match self.models[i].satisfies(constraints) {
                Ok(true) => {
                    if matches!(self.models[i].satisfies_extra(extra), Ok(true)) {
                        return true;
                    }
                    i += 1;
                }
                _ => {
                    self.models.swap_remove(i);
                }
            }
        }
        false
    }
}

impl<'c, S: Solver<'c>> HasContext<'c> for ModelCacheMixin<'c, S> {
    fn context(&self) -> &'c Context<'c> {
        self.inner.context()
    }
}

impl<'c, S: Solver<'c>> Solver<'c> for ModelCacheMixin<'c, S> {
    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        // Adding a constraint only tightens the set. A satisfiable result may
        // no longer hold, so drop it; an unsatisfiable result stays
        // unsatisfiable, so keep it. Cached models that the new constraint
        // invalidates are pruned lazily on next use (see `has_witness`).
        if self.sat == Some(true) {
            self.sat = None;
        }
        self.inner.add(constraint)
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        self.sat = None;
        self.models.clear();
        self.inner.clear()
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        self.inner.constraints()
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        // Simplification rewrites the constraints; drop cached models rather
        // than reason about whether each still applies. Equivalence-preserving
        // simplification cannot change satisfiability, so keep `sat`.
        self.models.clear();
        self.inner.simplify()
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        if let Some(sat) = self.sat {
            return Ok(sat);
        }
        let constraints = self.inner.constraints()?;
        let sat = if self.has_witness(&constraints) {
            true
        } else {
            self.inner.satisfiable()?
        };
        self.sat = Some(sat);
        Ok(sat)
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        if extra.is_empty() {
            return self.satisfiable();
        }
        // If the persistent set alone is unsatisfiable, so is any extension.
        if self.sat == Some(false) {
            return Ok(false);
        }
        let constraints = self.inner.constraints()?;
        if self.has_witness_with_extra(&constraints, extra) {
            return Ok(true);
        }
        // Cache miss: defer to the inner solver, which can check the extra
        // constraints incrementally (e.g. via Z3 assumptions).
        self.inner.satisfiable_with_extra(extra)
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        self.inner.is_true(expr)
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        self.inner.is_false(expr)
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        self.inner.has_true(expr)
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        self.inner.has_false(expr)
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.inner.min_unsigned(expr)
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.inner.max_unsigned(expr)
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.inner.min_signed(expr)
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.inner.max_signed(expr)
    }

    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if self.sat == Some(false) {
            return Ok(Vec::new());
        }

        // Try to answer entirely from cached models. Each value comes from a
        // model verified to satisfy the constraints, so it is a genuine,
        // distinct solution.
        let constraints = self.inner.constraints()?;
        let mut solutions: Vec<AstRef<'c>> = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let mut i = 0;
        while i < self.models.len() {
            match self.models[i].satisfies(&constraints) {
                Ok(true) => {
                    if let Ok(value) = self.models[i].eval(expr)
                        && value.concrete()
                        && seen.insert(value.hash())
                    {
                        solutions.push(value);
                        if solutions.len() == n as usize {
                            return Ok(solutions);
                        }
                    }
                    i += 1;
                }
                _ => {
                    self.models.swap_remove(i);
                }
            }
        }

        // The cache could not fully answer the query; the inner solver is
        // authoritative. Warm the cache with a fresh model for next time.
        let results = self.inner.eval_n(expr, n)?;
        if !results.is_empty() {
            // A solution exists, so the constraints are satisfiable.
            self.sat = Some(true);
            self.cache_model();
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// Wraps a solver and counts how many times each cacheable query reaches
    /// it, so tests can assert that the cache short-circuits calls.
    #[derive(Clone, Debug)]
    struct CountingSolver<'c, S: Solver<'c>> {
        inner: S,
        satisfiable_calls: Rc<Cell<usize>>,
        eval_calls: Rc<Cell<usize>>,
        _marker: std::marker::PhantomData<&'c ()>,
    }

    impl<'c, S: Solver<'c>> CountingSolver<'c, S> {
        fn new(inner: S) -> Self {
            Self {
                inner,
                satisfiable_calls: Rc::new(Cell::new(0)),
                eval_calls: Rc::new(Cell::new(0)),
                _marker: std::marker::PhantomData,
            }
        }
    }

    impl<'c, S: Solver<'c>> HasContext<'c> for CountingSolver<'c, S> {
        fn context(&self) -> &'c Context<'c> {
            self.inner.context()
        }
    }

    impl<'c, S: Solver<'c>> Solver<'c> for CountingSolver<'c, S> {
        fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
            self.inner.add(constraint)
        }
        fn clear(&mut self) -> Result<(), ClarirsError> {
            self.inner.clear()
        }
        fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
            self.inner.constraints()
        }
        fn simplify(&mut self) -> Result<(), ClarirsError> {
            self.inner.simplify()
        }
        fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
            self.satisfiable_calls.set(self.satisfiable_calls.get() + 1);
            self.inner.satisfiable()
        }
        fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
            self.inner.is_true(expr)
        }
        fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
            self.inner.is_false(expr)
        }
        fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
            self.inner.has_true(expr)
        }
        fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
            self.inner.has_false(expr)
        }
        fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            self.inner.min_unsigned(expr)
        }
        fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            self.inner.max_unsigned(expr)
        }
        fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            self.inner.min_signed(expr)
        }
        fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            self.inner.max_signed(expr)
        }
        fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
            self.eval_calls.set(self.eval_calls.get() + 1);
            self.inner.eval_n(expr, n)
        }
    }

    #[test]
    fn test_model_eval_and_satisfies() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;

        let mut assignments = HashMap::new();
        assignments.insert(x.hash(), five.clone());
        let mut model = Model::new(assignments);

        // x + 1 under {x: 5} evaluates to 6.
        let expr = ctx.add(&x, &ctx.bvv(BitVec::from((1, 8)))?)?;
        assert_eq!(model.eval(&expr)?, ctx.bvv(BitVec::from((6, 8)))?);

        // The model satisfies x == 5 but not x == 6.
        assert!(model.satisfies(&[ctx.eq_(&x, &five)?])?);
        assert!(!model.satisfies(&[ctx.eq_(&x, &ctx.bvv(BitVec::from((6, 8)))?)?])?);

        Ok(())
    }

    /// A model that does not cover a variable cannot decide a constraint on it,
    /// so `satisfies` conservatively returns false.
    #[test]
    fn test_model_partial_assignment_is_conservative() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8)?;
        let y = ctx.bvs("y", 8)?;

        let mut assignments = HashMap::new();
        assignments.insert(x.hash(), ctx.bvv(BitVec::from((5, 8)))?);
        let mut model = Model::new(assignments);

        // Constraint references y, which the model doesn't assign.
        assert!(!model.satisfies(&[ctx.eq_(&y, &ctx.bvv(BitVec::from((1, 8)))?)?])?);
        Ok(())
    }

    #[test]
    fn test_satisfiable_is_cached() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = CountingSolver::new(ConcreteSolver::new(&ctx));
        let calls = inner.satisfiable_calls.clone();
        let mut solver = ModelCacheMixin::new(inner);

        assert!(solver.satisfiable()?);
        assert!(solver.satisfiable()?);
        // The second call is answered from the cache (a known model), so the
        // inner solver is only consulted once.
        assert_eq!(calls.get(), 1);
        Ok(())
    }

    #[test]
    fn test_eval_reuses_cached_model() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = CountingSolver::new(ConcreteSolver::new(&ctx));
        let eval_calls = inner.eval_calls.clone();
        let mut solver = ModelCacheMixin::new(inner);

        let expr = ctx.add(
            &ctx.bvv(BitVec::from((1, 8)))?,
            &ctx.bvv(BitVec::from((2, 8)))?,
        )?;

        let first = solver.eval(&expr)?;
        let second = solver.eval(&expr)?;
        assert_eq!(first, second);
        assert_eq!(first, ctx.bvv(BitVec::from((3, 8)))?);
        // ConcreteSolver has no variables, so the cached (empty) model can
        // evaluate the concrete expression and the second eval avoids the
        // inner solver entirely.
        assert_eq!(eval_calls.get(), 1);
        Ok(())
    }

    #[test]
    fn test_clear_resets_cache() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = CountingSolver::new(ConcreteSolver::new(&ctx));
        let calls = inner.satisfiable_calls.clone();
        let mut solver = ModelCacheMixin::new(inner);

        assert!(solver.satisfiable()?);
        solver.clear()?;
        assert!(solver.satisfiable()?);
        // The cache was reset by clear(), so the inner solver is consulted
        // again.
        assert_eq!(calls.get(), 2);
        Ok(())
    }
}
