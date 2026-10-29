use std::collections::HashMap;

use crate::prelude::*;

/// A solver mixin that applies expression replacements before delegating to
/// the inner solver. This mirrors claripy's `ReplacementFrontend`.
///
/// When constraints of the form `x == <concrete>` are added, the replacement
/// solver automatically extracts the mapping and uses it to simplify future
/// queries. Explicit replacements can also be added via
/// [`add_replacement`](Self::add_replacement).
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
    /// full hash -> annotation-free hash, for every replacement whose key carried
    /// annotations. Lets `remove_replacements` drop both entries.
    bare_aliases: HashMap<u64, u64>,
    /// Running hash of `original_constraints` (order-sensitive) and of `replacements`
    /// (order-free sum over entries), maintained on every mutation so `signature()` is O(1).
    constraints_hash: u64,
    replacements_hash: u64,
    _marker: std::marker::PhantomData<&'c ()>,
}

/// splitmix64 finalizer.
fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

fn entry_hash(key: u64, value: &AstRef<'_>) -> u64 {
    mix(key ^ mix(value.hash()))
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
            bare_aliases: HashMap::new(),
            constraints_hash: 0,
            replacements_hash: 0,
            _marker: std::marker::PhantomData,
        }
    }

    /// (hash of the constraint sequence, hash of the replacement map): everything a query's
    /// answer depends on besides the query itself. Equal signatures mean equal solver content.
    pub fn signature(&self) -> (u64, u64) {
        (self.constraints_hash, self.replacements_hash)
    }

    fn set_replacement(&mut self, key: u64, new: AstRef<'c>) {
        if let Some(old) = self.replacements.insert(key, new.clone()) {
            self.replacements_hash = self.replacements_hash.wrapping_sub(entry_hash(key, &old));
        }
        self.replacements_hash = self.replacements_hash.wrapping_add(entry_hash(key, &new));
        self.replacement_cache.insert(key, new);
    }

    fn unset_replacement(&mut self, key: u64) {
        if let Some(old) = self.replacements.remove(&key) {
            self.replacements_hash = self.replacements_hash.wrapping_sub(entry_hash(key, &old));
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Whether replacements are automatically extracted from `x == <concrete>`
    /// style constraints as they are added.
    pub fn auto_replace(&self) -> bool {
        self.auto_replace
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Add an explicit replacement mapping: occurrences of `old` will be
    /// replaced with `new` in all future queries.
    pub fn add_replacement(&mut self, old: AstRef<'c>, new: AstRef<'c>) {
        let hash = old.hash();
        self.set_replacement(hash, new.clone());
        // Annotations are metadata, not identity: register the bare form too, so a
        // replacement learned for an annotated `x` fires on plain `x` (lookups on an
        // annotated key are handled by `replace_many_loose`).
        let bare = old.hash_without_annotations();
        if bare != hash {
            self.set_replacement(bare, new);
            self.bare_aliases.insert(hash, bare);
        }
    }

    /// Remove specific replacements by their hashes.
    pub fn remove_replacements(&mut self, hashes: &[u64]) {
        for hash in hashes {
            self.unset_replacement(*hash);
            if let Some(bare) = self.bare_aliases.remove(hash) {
                self.unset_replacement(bare);
            }
        }
        // Rebuild cache from canonical replacements
        self.replacement_cache = self.replacements.clone();
    }

    /// Clear all replacements.
    pub fn clear_replacements(&mut self) {
        self.replacements.clear();
        self.replacement_cache.clear();
        self.bare_aliases.clear();
        self.replacements_hash = 0;
    }

    /// Copy every replacement of `other` into this solver.
    pub fn import_replacements(&mut self, other: &HashMap<u64, AstRef<'c>>) {
        for (hash, new) in other {
            self.set_replacement(*hash, new.clone());
        }
    }

    /// The replacement registered for `ast`, if any, ignoring annotations.
    pub fn get_replacement(&self, ast: &AstRef<'c>) -> Option<AstRef<'c>> {
        self.replacement_cache
            .get(&ast.hash())
            .or_else(|| self.replacement_cache.get(&ast.hash_without_annotations()))
            .cloned()
    }

    /// Get the current replacement map (hash → AstRef).
    pub fn replacements(&self) -> &HashMap<u64, AstRef<'c>> {
        &self.replacements
    }

    /// Apply known replacements to an AstRef.
    ///
    /// `Add` is n-ary and flattened, so a caller that registered `a + b` finds no such
    /// node inside `Add[a, b, c]`. Mirror what they meant: when the first two operands
    /// of the top-level sum have a replacement, apply it and keep the rest.
    pub fn apply_replacements(&self, ast: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let ast = if let AstOp::Add(args) = ast.op()
            && args.len() > 2
        {
            let prefix = ast.context().add(&args[0], &args[1])?;
            match self.get_replacement(&prefix) {
                Some(replaced) => {
                    let mut rest = Vec::with_capacity(args.len() - 1);
                    rest.push(replaced);
                    rest.extend(args[2..].iter().cloned());
                    ast.context().add_many(rest)?
                }
                None => ast.clone(),
            }
        } else {
            ast.clone()
        };
        ast.replace_many_loose(&self.replacement_cache)
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
        self.constraints_hash = mix(self.constraints_hash.rotate_left(5) ^ constraint.hash());
        let replaced = self.apply_replacements(constraint)?;
        self.inner.add(&replaced)
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        self.original_constraints.clear();
        self.constraints_hash = 0;
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

    fn eval_unique(&mut self, expr: &AstRef<'c>) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.eval_unique(&replaced)
    }

    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let replaced = exprs
            .iter()
            .map(|e| self.apply_replacements(e))
            .collect::<Result<Vec<_>, _>>()?;
        self.inner.batch_eval(&replaced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::AstFactory;

    fn anno() -> Annotation {
        Annotation::new(AnnotationType::Uninitialized, true, true)
    }

    #[test]
    fn test_replacement_ignores_annotations_on_lookup() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = ReplacementSolver::new(ConcreteSolver::new(&ctx));
        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;
        solver.add_replacement(x.clone(), five.clone());

        let annotated = x.clone().annotate(std::iter::once(anno()))?;
        assert_ne!(annotated.hash(), x.hash());
        assert_eq!(solver.eval(&annotated)?, five);
        assert_eq!(solver.get_replacement(&annotated), Some(five));
        Ok(())
    }

    #[test]
    fn test_replacement_registered_on_annotated_fires_on_bare() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = ReplacementSolver::new(ConcreteSolver::new(&ctx));
        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;
        let annotated = x.clone().annotate(std::iter::once(anno()))?;
        solver.add_replacement(annotated.clone(), five.clone());

        assert_eq!(solver.eval(&x)?, five);
        solver.remove_replacements(&[annotated.hash()]);
        assert!(solver.replacements().is_empty());
        Ok(())
    }

    #[test]
    fn test_replacement_of_flattened_add_prefix() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = ReplacementSolver::new(ConcreteSolver::new(&ctx));
        let x = ctx.bvs("x", 8)?;
        let y = ctx.bvs("y", 8)?;
        let z = ctx.bvs("z", 8)?;
        let seven = ctx.bvv(BitVec::from((7, 8)))?;
        solver.add_replacement(ctx.add(&x, &y)?, seven.clone());

        let sum = ctx.add_many([x.clone(), y.clone(), z.clone()])?;
        assert!(matches!(sum.op(), AstOp::Add(a) if a.len() == 3));
        let replaced = solver.apply_replacements(&sum)?;
        assert!(replaced.variables().is_disjoint(x.variables()));
        assert!(replaced.variables().is_superset(z.variables()));
        Ok(())
    }

    #[test]
    fn test_import_replacements() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut a = ReplacementSolver::new(ConcreteSolver::new(&ctx));
        let mut b = ReplacementSolver::new(ConcreteSolver::new(&ctx));
        let x = ctx.bvs("x", 8)?;
        let y = ctx.bvs("y", 8)?;
        let one = ctx.bvv(BitVec::from((1, 8)))?;
        let two = ctx.bvv(BitVec::from((2, 8)))?;
        a.add_replacement(x.clone(), one.clone());
        b.add_replacement(y.clone(), two.clone());
        a.import_replacements(b.replacements());
        assert_eq!(a.eval(&ctx.add(&x, &y)?)?, ctx.bvv(BitVec::from((3, 8)))?);
        Ok(())
    }

    #[test]
    fn test_replacement_solver_basic() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;

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
        let five = ctx.bvv(BitVec::from((5, 8)))?;

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
        let five = ctx.bvv(BitVec::from((5, 8)))?;
        let three = ctx.bvv(BitVec::from((3, 8)))?;

        // Replace x with 5
        solver.add_replacement(x.clone(), five.clone());

        // Evaluating x + 3 should return 8
        let expr = ctx.add(&x, &three)?;
        let result = solver.eval(&expr)?;
        let expected = ctx.bvv(BitVec::from((8, 8)))?;
        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_clear() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;

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
    fn test_replacement_solver_auto_replace_disabled() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        // auto_replace = false: `x == 5` should NOT register a replacement.
        let mut solver = ReplacementSolver::new_with_options(inner, false);
        assert!(!solver.auto_replace());

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;

        let eq_constraint = ctx.eq_(&x, &five)?;
        solver.add(&eq_constraint)?;

        // No replacement was extracted, so the map stays empty.
        assert!(solver.replacements().is_empty());

        // Explicit replacements still work regardless of auto_replace.
        solver.add_replacement(x.clone(), five.clone());
        assert_eq!(solver.eval(&x)?, five);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_reports_original_constraints() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let one = ctx.bvv(BitVec::from((1, 8)))?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;
        let six = ctx.bvv(BitVec::from((6, 8)))?;

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

    #[test]
    fn test_signature_tracks_content() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = ReplacementSolver::new_with_options(ConcreteSolver::new(&ctx), false);
        let x = ctx.bvs("x", 8)?;
        let y = ctx.bvs("y", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;
        let six = ctx.bvv(BitVec::from((6, 8)))?;

        let empty = solver.signature();
        solver.add(&ctx.eq_(&x, &five)?)?;
        let one_constraint = solver.signature();
        assert_ne!(empty, one_constraint);

        solver.add_replacement(y.clone(), five.clone());
        let repl_five = solver.signature();
        assert_ne!(one_constraint, repl_five);
        // overwriting a key keeps the count but changes the content
        solver.add_replacement(y.clone(), six.clone());
        assert_eq!(solver.replacements().len(), 1);
        assert_ne!(repl_five, solver.signature());
        solver.add_replacement(y.clone(), five.clone());
        assert_eq!(repl_five, solver.signature());

        // order-free: the same map reached in a different order hashes the same
        let mut other = ReplacementSolver::new_with_options(ConcreteSolver::new(&ctx), false);
        other.add(&ctx.eq_(&x, &five)?)?;
        other.add_replacement(x.clone(), six.clone());
        other.add_replacement(y.clone(), five.clone());
        solver.add_replacement(x.clone(), six.clone());
        assert_eq!(solver.signature(), other.signature());

        solver.remove_replacements(&[x.hash()]);
        assert_eq!(solver.signature(), repl_five);
        solver.clear_replacements();
        assert_eq!(solver.signature(), one_constraint);
        solver.clear()?;
        assert_eq!(solver.signature(), empty);

        Ok(())
    }
}
