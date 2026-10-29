use std::collections::{BTreeSet, HashMap, HashSet};

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
    /// Expressions (by hash) for which eval_n returned fewer values than asked, i.e. every
    /// solution, as claripy's `_eval_exhausted`. Valid until the constraints change.
    eval_exhausted: HashMap<u64, Vec<AstRef<'c>>>,
    /// Values every model must give: `t -> c` for each constraint `t == c` (c concrete), and
    /// `b -> true` / `b -> false` for each Boolean constraint `b` / `!b` (through `And`).
    implied: HashMap<u64, AstRef<'c>>,
    /// Variables of the terms in `implied`.
    implied_vars: BTreeSet<InternedString>,
    /// Per variable (hash): bit ranges `(hi, lo, value)` pinned by `x[hi:lo] == value`, so that
    /// narrower extracts of `x` inside a range resolve too.
    implied_bits: HashMap<u64, Vec<(u32, u32, AstRef<'c>)>>,
    /// Number of constraints already folded into `implied` (constraints are append-only
    /// between `clear`/`simplify`).
    implied_len: usize,
}

impl<'c, S: Solver<'c>> ModelCacheMixin<'c, S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            sat: None,
            models: Vec::new(),
            eval_exhausted: HashMap::new(),
            implied: HashMap::new(),
            implied_vars: BTreeSet::new(),
            implied_bits: HashMap::new(),
            implied_len: 0,
        }
    }

    fn reset_implied(&mut self) {
        self.implied.clear();
        self.implied_vars.clear();
        self.implied_bits.clear();
        self.implied_len = 0;
    }

    fn imply(&mut self, term: &AstRef<'c>, value: AstRef<'c>) {
        if term.concrete() {
            return;
        }
        self.implied_vars.extend(term.variables().iter().cloned());
        self.implied.entry(term.hash()).or_insert(value);
    }

    fn harvest(&mut self, c: &AstRef<'c>) -> Result<(), ClarirsError> {
        match c.op() {
            AstOp::And(args) if c.ast_type().is_bool() => {
                for a in args {
                    self.harvest(a)?;
                }
                return Ok(());
            }
            AstOp::Eq(a, b) => {
                let (term, value) = if b.concrete() { (a, b) } else { (b, a) };
                if value.concrete() {
                    self.imply(term, value.clone());
                    if let AstOp::Extract(v, hi, lo) = term.op()
                        && matches!(v.op(), AstOp::BVS(..))
                    {
                        self.implied_bits.entry(v.hash()).or_default().push((*hi, *lo, value.clone()));
                    }
                }
            }
            AstOp::Not(a) if a.ast_type().is_bool() => {
                let f = self.context().false_()?;
                self.imply(a, f);
            }
            _ => {}
        }
        let t = self.context().true_()?;
        self.imply(c, t);
        Ok(())
    }

    fn fold_constraints(&mut self, constraints: &[AstRef<'c>]) -> Result<(), ClarirsError> {
        if constraints.len() < self.implied_len {
            self.reset_implied();
        }
        while self.implied_len < constraints.len() {
            let c = constraints[self.implied_len].clone();
            self.harvest(&c)?;
            self.implied_len += 1;
        }
        Ok(())
    }

    /// `expr`'s value when the constraints pin it: substitute the implied values and
    /// simplify (other variables may cancel once the pinned ones are constants).
    fn implied_value(
        &mut self,
        expr: &AstRef<'c>,
        constraints: &[AstRef<'c>],
    ) -> Result<Option<AstRef<'c>>, ClarirsError> {
        self.fold_constraints(constraints)?;
        if expr.concrete()
            || self.implied.is_empty()
            || expr.variables().is_disjoint(&self.implied_vars)
        {
            return Ok(None);
        }
        // narrower extracts of a variable inside a pinned bit range
        let mut extra: Vec<(u64, AstRef<'c>)> = Vec::new();
        if !self.implied_bits.is_empty() {
            let mut stack = vec![expr.clone()];
            let mut seen: HashSet<u64> = HashSet::new();
            while let Some(node) = stack.pop() {
                if node.concrete() || !seen.insert(node.hash()) {
                    continue;
                }
                if let AstOp::Extract(v, h2, l2) = node.op()
                    && let Some(ranges) = self.implied_bits.get(&v.hash())
                    && !self.implied.contains_key(&node.hash())
                    && let Some((_, lo, value)) = ranges.iter().find(|(hi, lo, _)| lo <= l2 && h2 <= hi)
                {
                    let slice = self.context().extract(value, h2 - lo, l2 - lo)?.simplify()?;
                    extra.push((node.hash(), slice));
                    continue;
                }
                stack.extend(node.child_iter());
            }
        }
        let replaced = if extra.is_empty() {
            expr.replace_many(&self.implied)?
        } else {
            let mut map = self.implied.clone();
            map.extend(extra);
            expr.replace_many(&map)?
        };
        if replaced.hash() == expr.hash() {
            return Ok(None);
        }
        let value = replaced.simplify()?;
        Ok(match value.op() {
            AstOp::BoolV(..) | AstOp::BVV(..) => Some(value),
            _ => None,
        })
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

impl<'c, S: Solver<'c>> ModelCacheMixin<'c, S> {
    /// eval_n; with `unique`, a verified model completed two ways may stand in for the backend's two
    /// solutions (see [`Solver::eval_unique`]). Cache bookkeeping is the same either way.
    fn eval_n_impl(
        &mut self,
        expr: &AstRef<'c>,
        n: u32,
        unique: bool,
    ) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        if self.sat == Some(false) {
            return Ok(Vec::new());
        }

        if let Some(all) = self.eval_exhausted.get(&expr.hash()) {
            return Ok(all.iter().take(n as usize).cloned().collect());
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

        // The constraints may pin the value outright (e.g. a deep expression over x when
        // x[31:0] == c is asserted and only those bits matter): then it is the only
        // solution, provided the constraints are satisfiable. The model cache is still
        // warmed below, exactly as after a backend solve.
        let results = if let Some(value) = self.implied_value(expr, &constraints)? {
            if self.satisfiable()? { vec![value] } else { Vec::new() }
        } else {
            // The cache could not fully answer the query; the inner solver is
            // authoritative. Warm the cache with a fresh model for next time.
            let completed = if unique { self.two_completions(expr, &constraints).unwrap_or(None) } else { None };
            match completed {
                Some(two) => two,
                None => self.inner.eval_n(expr, n)?,
            }
        };
        if results.len() < n as usize {
            self.eval_exhausted.insert(expr.hash(), results.clone());
        }
        if !results.is_empty() {
            // A solution exists, so the constraints are satisfiable.
            self.sat = Some(true);
            self.cache_model();
        }
        Ok(results)
    }

    /// Two different values of `expr` under assignments that satisfy the constraints: a cached model
    /// (already verified against `constraints`) with every variable no constraint mentions set to all
    /// zeros, then all ones. None when that does not yield two distinct constants.
    fn two_completions(
        &self,
        expr: &AstRef<'c>,
        constraints: &[AstRef<'c>],
    ) -> Result<Option<Vec<AstRef<'c>>>, ClarirsError> {
        let empty = HashMap::new();
        let assignments = match self.models.first() {
            Some(model) => &model.assignments,
            None if constraints.is_empty() => &empty,
            None => return Ok(None),
        };
        let ctx = expr.context();
        let mut low = assignments.clone();
        let mut high = assignments.clone();
        let mut free = 0;
        for var in collect_vars(expr)? {
            if assignments.contains_key(&var.hash()) {
                continue;
            }
            let (name, lo, hi) = match var.op() {
                AstOp::BVS(name, size) => (name, ctx.bvv(BitVec::zeros(*size))?, ctx.bvv(BitVec::ones(*size))?),
                AstOp::BoolS(name) => (name, ctx.false_()?, ctx.true_()?),
                _ => return Ok(None),
            };
            // a constrained variable missed by the model (e.g. under other annotations) is not free
            if constraints.iter().any(|c| c.variables().contains(name)) {
                return Ok(None);
            }
            low.insert(var.hash(), lo);
            high.insert(var.hash(), hi);
            free += 1;
        }
        if free == 0 {
            return Ok(None);
        }
        let a = expr.replace_many(&low)?.simplify()?;
        let b = expr.replace_many(&high)?.simplify()?;
        let distinct = match (a.op(), b.op()) {
            (AstOp::BVV(x), AstOp::BVV(y)) => x != y,
            (AstOp::BoolV(x), AstOp::BoolV(y)) => x != y,
            _ => false,
        };
        Ok(if distinct { Some(vec![a, b]) } else { None })
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
        self.eval_exhausted.clear();
        self.inner.add(constraint)
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        self.sat = None;
        self.models.clear();
        self.eval_exhausted.clear();
        self.reset_implied();
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
        self.eval_exhausted.clear();
        self.reset_implied();
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
        self.eval_n_impl(expr, n, false)
    }

    fn eval_unique(&mut self, expr: &AstRef<'c>) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        self.eval_n_impl(expr, 2, true)
    }

    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        if self.sat == Some(false) {
            return Err(ClarirsError::Unsat);
        }
        // Forward as a batch so the backend draws every value from one model in
        // a single solve, rather than the per-expression default (one solve per
        // expression). Only the satisfiability flag is updated here.
        match self.inner.batch_eval(exprs) {
            Ok(results) => {
                self.sat = Some(true);
                Ok(results)
            }
            Err(ClarirsError::Unsat) => {
                self.sat = Some(false);
                Err(ClarirsError::Unsat)
            }
            Err(e) => Err(e),
        }
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
    fn test_exhausted_eval_n_is_not_resolved() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = CountingSolver::new(ConcreteSolver::new(&ctx));
        let eval_calls = inner.eval_calls.clone();
        let mut solver = ModelCacheMixin::new(inner);
        let expr = ctx.add(
            &ctx.bvv(BitVec::from((1, 8)))?,
            &ctx.bvv(BitVec::from((2, 8)))?,
        )?;

        // Fewer values than asked: every solution is known, so the repeat is answered here.
        assert_eq!(solver.eval_n(&expr, 3)?.len(), 1);
        let calls = eval_calls.get();
        assert_eq!(solver.eval_n(&expr, 3)?.len(), 1);
        assert_eq!(eval_calls.get(), calls);

        // New constraints invalidate the record.
        solver.add(&ctx.true_()?)?;
        solver.eval_n(&expr, 3)?;
        assert!(eval_calls.get() > calls);
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

    /// Keeps the constraints it is given (ConcreteSolver drops them) and counts eval_n calls.
    #[derive(Clone, Debug)]
    struct StoringSolver<'c> {
        inner: CountingSolver<'c, ConcreteSolver<'c>>,
        constraints: Vec<AstRef<'c>>,
    }

    impl<'c> HasContext<'c> for StoringSolver<'c> {
        fn context(&self) -> &'c Context<'c> {
            self.inner.context()
        }
    }

    impl<'c> Solver<'c> for StoringSolver<'c> {
        fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
            self.constraints.push(constraint.clone());
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
            Ok(true)
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
            // count only the two-solution queries, not cache_model's single evals
            if n == 2 {
                self.inner.eval_n(expr, n)
            } else {
                self.inner.inner.eval_n(expr, n)
            }
        }
    }

    fn storing_cache<'c>(
        ctx: &'c Context<'c>,
    ) -> (ModelCacheMixin<'c, StoringSolver<'c>>, Rc<Cell<usize>>) {
        let inner = CountingSolver::new(ConcreteSolver::new(ctx));
        let calls = inner.eval_calls.clone();
        let solver = ModelCacheMixin::new(StoringSolver {
            inner,
            constraints: Vec::new(),
        });
        (solver, calls)
    }

    #[test]
    fn test_eval_unique_free_variable_without_backend() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let (mut solver, calls) = storing_cache(&ctx);
        let x = ctx.bvs("x", 8)?;
        let y = ctx.bvs("y", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;

        // no constraints: any assignment is a model
        let r = solver.eval_unique(&ctx.add(&x, &ctx.bvv(BitVec::from((1, 8)))?)?)?;
        assert_eq!(r.len(), 2);
        assert_ne!(r[0], r[1]);
        assert_eq!(calls.get(), 0);
        assert_eq!(solver.sat, Some(true));

        // a verified model for the constrained y, x still free
        solver.add(&ctx.eq_(&y, &five)?)?;
        let mut assignments = HashMap::new();
        assignments.insert(y.hash(), five.clone());
        solver.models.push(Model::new(assignments));
        assert_eq!(solver.eval_unique(&ctx.add(&x, &y)?)?.len(), 2);
        assert_eq!(calls.get(), 0);
        assert!(solver.eval_exhausted.is_empty());
        Ok(())
    }

    #[test]
    fn test_eval_unique_falls_back_to_backend() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let (mut solver, calls) = storing_cache(&ctx);
        let x = ctx.bvs("x", 8)?;
        let y = ctx.bvs("y", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;
        // y < 6, not y == 5: an equality would pin y + 1 without the backend
        solver.add(&ctx.ult(&y, &ctx.bvv(BitVec::from((6, 8)))?)?)?;
        let mut assignments = HashMap::new();
        assignments.insert(y.hash(), five.clone());
        solver.models.push(Model::new(assignments));

        // no free variable: the model alone gives one value, the backend decides
        let _ = solver.eval_unique(&ctx.add(&y, &ctx.bvv(BitVec::from((1, 8)))?)?);
        assert_eq!(calls.get(), 1);
        // both completions agree (x <= 0xff always holds)
        let _ = solver.eval_unique(&ctx.ule(&x, &ctx.bvv(BitVec::from((0xff, 8)))?)?);
        assert_eq!(calls.get(), 2);
        // y under an annotation is the constrained y, not a free variable
        let y_anno = y.clone().annotate(std::iter::once(Annotation::new(
            AnnotationType::Uninitialized,
            true,
            true,
        )))?;
        let _ = solver.eval_unique(&ctx.add(&x, &y_anno)?);
        assert_eq!(calls.get(), 3);
        // without a model there is nothing to complete
        solver.models.clear();
        let _ = solver.eval_unique(&ctx.add(&x, &y)?);
        assert_eq!(calls.get(), 4);
        Ok(())
    }

    /// Keeps constraints, answers `satisfiable` with a fixed verdict and counts `eval_n`
    /// calls, which it cannot answer.
    #[derive(Clone, Debug)]
    struct StubSolver<'c> {
        ctx: &'c Context<'c>,
        constraints: Vec<AstRef<'c>>,
        sat: bool,
        eval_calls: Rc<Cell<usize>>,
        model: HashMap<u64, AstRef<'c>>,
    }

    impl<'c> HasContext<'c> for StubSolver<'c> {
        fn context(&self) -> &'c Context<'c> {
            self.ctx
        }
    }

    impl<'c> Solver<'c> for StubSolver<'c> {
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
            Ok(self.sat)
        }
        fn is_true(&mut self, _: &AstRef<'c>) -> Result<bool, ClarirsError> {
            Ok(false)
        }
        fn is_false(&mut self, _: &AstRef<'c>) -> Result<bool, ClarirsError> {
            Ok(false)
        }
        fn has_true(&mut self, _: &AstRef<'c>) -> Result<bool, ClarirsError> {
            Ok(true)
        }
        fn has_false(&mut self, _: &AstRef<'c>) -> Result<bool, ClarirsError> {
            Ok(true)
        }
        fn min_unsigned(&mut self, e: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            Ok(e.clone())
        }
        fn max_unsigned(&mut self, e: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            Ok(e.clone())
        }
        fn min_signed(&mut self, e: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            Ok(e.clone())
        }
        fn max_signed(&mut self, e: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
            Ok(e.clone())
        }
        fn eval_n(&mut self, _: &AstRef<'c>, _: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
            self.eval_calls.set(self.eval_calls.get() + 1);
            Err(ClarirsError::UnsupportedOperation("stub".to_string()))
        }
        fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
            exprs
                .iter()
                .map(|e| {
                    self.model
                        .get(&e.hash())
                        .cloned()
                        .ok_or(ClarirsError::UnsupportedOperation("stub".to_string()))
                })
                .collect()
        }
    }

    fn stub<'c>(ctx: &'c Context<'c>, sat: bool) -> (ModelCacheMixin<'c, StubSolver<'c>>, Rc<Cell<usize>>) {
        let calls = Rc::new(Cell::new(0));
        let inner = StubSolver { ctx, constraints: Vec::new(), sat, eval_calls: calls.clone(), model: HashMap::new() };
        (ModelCacheMixin::new(inner), calls)
    }

    fn bv<'c>(ctx: &'c Context<'c>, v: u64, w: u32) -> Result<AstRef<'c>, ClarirsError> {
        ctx.bvv(BitVec::from((v, w)))
    }

    #[test]
    fn test_implied_value_from_extract_equality() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let (mut solver, calls) = stub(&ctx, true);
        let x = ctx.bvs("x", 64)?;
        let lo = ctx.extract(&x, 31, 0)?;
        solver.add(&ctx.eq_(&lo, &bv(&ctx, 0x7fff0000, 32)?)?)?;
        // ((x[31:0] ^ 0x1234) + 7)[15:0]: x's high half never matters
        let expr = ctx.extract(&ctx.add(&ctx.xor2(&lo, &bv(&ctx, 0x1234, 32)?)?, &bv(&ctx, 7, 32)?)?, 15, 0)?;
        assert_eq!(solver.eval_n(&expr, 3)?, vec![bv(&ctx, 0x123b, 16)?]);
        assert_eq!(calls.get(), 0);
        // the high half is free: the backend decides
        let hi = ctx.extract(&x, 63, 32)?;
        assert!(solver.eval_n(&hi, 3).is_err());
        assert_eq!(calls.get(), 1);
        Ok(())
    }

    #[test]
    fn test_implied_value_from_boolean_constraints() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let (mut solver, calls) = stub(&ctx, true);
        let a = ctx.bools("a")?;
        let b = ctx.bools("b")?;
        let y = ctx.bvs("y", 8)?;
        solver.add(&ctx.and2(&a, &ctx.eq_(&y, &bv(&ctx, 3, 8)?)?)?)?;
        solver.add(&ctx.not(&b)?)?;
        let expr = ctx.ite(&a, &ctx.ite(&b, &bv(&ctx, 1, 8)?, &y)?, &bv(&ctx, 2, 8)?)?;
        assert_eq!(solver.eval_n(&expr, 2)?, vec![bv(&ctx, 3, 8)?]);
        assert_eq!(calls.get(), 0);
        Ok(())
    }

    #[test]
    fn test_implied_value_needs_satisfiable_constraints() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let (mut solver, calls) = stub(&ctx, false);
        let x = ctx.bvs("x", 8)?;
        solver.add(&ctx.eq_(&x, &bv(&ctx, 1, 8)?)?)?;
        let expr = ctx.add(&x, &bv(&ctx, 1, 8)?)?;
        assert!(solver.eval_n(&expr, 2)?.is_empty());
        assert_eq!(calls.get(), 0);
        Ok(())
    }

    /// Every x with x[11:0] == c gives the shortcut's value (exhaustive over the free bits).
    #[test]
    fn test_implied_value_brute_force() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 16)?;
        let pinned = ctx.extract(&x, 11, 0)?;
        let parts = [ctx.extract(&x, 7, 0)?, ctx.extract(&x, 11, 4)?, ctx.extract(&x, 15, 8)?];
        let mut seed: u64 = 0x9e3779b97f4a7c15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let (mut fired, mut declined) = (0, 0);
        for _ in 0..400 {
            let c = next() & 0xfff;
            let mut e = parts[(next() % 2) as usize].clone();
            for _ in 0..(next() % 6 + 1) {
                let k = bv(&ctx, next() & 0xff, 8)?;
                let other = parts[(next() % 3) as usize].clone();
                e = match next() % 6 {
                    0 => ctx.add(&e, &k)?,
                    1 => ctx.xor2(&e, &other)?,
                    2 => ctx.and2(&e, &k)?,
                    3 => ctx.mul(&e, &other)?,
                    4 => ctx.or2(&e, &k)?,
                    _ => ctx.ite(&ctx.ult(&other, &k)?, &e, &k)?,
                };
            }
            let (mut solver, _) = stub(&ctx, true);
            solver.add(&ctx.eq_(&pinned, &bv(&ctx, c, 12)?)?)?;
            let Ok(vals) = solver.eval_n(&e, 2) else {
                declined += 1;
                continue;
            };
            fired += 1;
            assert_eq!(vals.len(), 1);
            for h in 0..16u64 {
                let mut m = HashMap::new();
                m.insert(x.hash(), bv(&ctx, (h << 12) | c, 16)?);
                assert_eq!(e.replace_many(&m)?.simplify()?, vals[0]);
            }
        }
        assert!(fired > 100 && declined > 20);
        Ok(())
    }

}
