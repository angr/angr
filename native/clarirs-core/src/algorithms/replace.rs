#![allow(clippy::mutable_key_type)]

use std::cmp::Reverse;
use std::collections::HashMap;
use std::iter;
use std::mem::discriminant;
use std::sync::Arc;

use crate::{algorithms::walk, cache::GenericCache, prelude::*};

/// The operands of `op` when it is associative and commutative, so that the
/// order and grouping of its operands carry no meaning; `None` otherwise.
fn commutative_operands<'a, 'c>(op: &'a AstOp<'c>) -> Option<&'a [AstRef<'c>]> {
    match op {
        AstOp::And(v)
        | AstOp::Or(v)
        | AstOp::Xor(v)
        | AstOp::Add(v)
        | AstOp::Mul(v)
        | AstOp::Union(v)
        | AstOp::Intersection(v) => Some(v),
        _ => None,
    }
}

/// A set of `from -> to` substitutions for [`AstNode::replace_many`].
///
/// Besides whole-node matches, an entry whose `from` is an associative and
/// commutative op (`And`, `Or`, `Xor`, `Add`, `Mul`, `Union`,
/// `Intersection`) also matches a subset of the operands of a larger node
/// of the same op, in any order:
/// `(a + b + c).replace(a + c, d)` gives `b + d`. Those entries are indexed
/// on insertion, so a set built once can be applied to many expressions.
#[derive(Clone, Debug, Default)]
pub struct Replacements<'c> {
    by_from: HashMap<AstRef<'c>, AstRef<'c>>,
    /// The entries whose `from` is a commutative op, most operands first so
    /// that the most specific one wins, then by hash for determinism.
    patterns: Vec<(AstRef<'c>, AstRef<'c>)>,
}

impl<'c> Replacements<'c> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `from -> to`, replacing any entry for the same `from`.
    pub fn insert(&mut self, from: AstRef<'c>, to: AstRef<'c>) {
        self.patterns.retain(|(f, _)| *f != from);
        if commutative_operands(from.op()).is_some_and(|v| !v.is_empty()) {
            let key = |f: &AstRef<'c>| (Reverse(f.op().num_children()), f.hash());
            let at = self.patterns.partition_point(|(f, _)| key(f) < key(&from));
            self.patterns.insert(at, (from.clone(), to.clone()));
        }
        self.by_from.insert(from, to);
    }

    /// Removes the entry for `from`, returning its `to`.
    pub fn remove(&mut self, from: &AstRef<'c>) -> Option<AstRef<'c>> {
        self.patterns.retain(|(f, _)| f != from);
        self.by_from.remove(from)
    }

    /// Keeps only the entries for which `keep(from, to)` holds.
    pub fn retain(&mut self, mut keep: impl FnMut(&AstRef<'c>, &AstRef<'c>) -> bool) {
        self.patterns.retain(|(f, t)| keep(f, t));
        self.by_from.retain(|f, t| keep(f, t));
    }

    pub fn clear(&mut self) {
        self.patterns.clear();
        self.by_from.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.by_from.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_from.len()
    }

    /// The `to` of the entry for `from`.
    pub fn get(&self, from: &AstRef<'c>) -> Option<&AstRef<'c>> {
        self.by_from.get(from)
    }

    /// Every `(from, to)`, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&AstRef<'c>, &AstRef<'c>)> {
        self.by_from.iter()
    }
}

impl<'c> FromIterator<(AstRef<'c>, AstRef<'c>)> for Replacements<'c> {
    fn from_iter<I: IntoIterator<Item = (AstRef<'c>, AstRef<'c>)>>(iter: I) -> Self {
        let mut replacements = Self::new();
        replacements.extend(iter);
        replacements
    }
}

impl<'c> Extend<(AstRef<'c>, AstRef<'c>)> for Replacements<'c> {
    fn extend<I: IntoIterator<Item = (AstRef<'c>, AstRef<'c>)>>(&mut self, iter: I) {
        for (from, to) in iter {
            self.insert(from, to);
        }
    }
}

impl<'c> AstNode<'c> {
    /// Replaces every occurrence of `from` in this AST with `to`.
    ///
    /// When `from` is an associative and commutative op (`And`, `Or`, `Xor`,
    /// `Add`, `Mul`, `Union`, `Intersection`), it also matches, in any
    /// order, a subset of the operands of a larger node of the same op:
    /// `(a + b + c).replace(a + c, d)` gives `b + d`.
    pub fn replace<T: Clone + Into<AstRef<'c>>>(
        self: &Arc<Self>,
        from: &T,
        to: &T,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let from = from.clone().into();
        let to = to.clone().into();
        self.replace_many(&Replacements::from_iter([(from, to)]))
    }

    /// Applies every `from -> to` in `replacements` in a single pass. Each
    /// `from` matches as described on [`replace`](Self::replace); a matched
    /// node or operand is taken as it was, and nothing inside `to` is replaced.
    ///
    /// Every replacement must preserve the sort of what it replaces,
    /// including bitvector width and float format; a mismatch is a
    /// [`ClarirsError::TypeError`].
    pub fn replace_many(
        self: &Arc<Self>,
        replacements: &Replacements<'c>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        if replacements.is_empty() {
            return Ok(self.clone());
        }

        let ctx = self.context();
        // The multiset of `asts`, as hash -> number of occurrences.
        let multiset = |asts: &[AstRef<'c>]| {
            asts.iter().fold(HashMap::new(), |mut counts, ast| {
                *counts.entry(ast.hash()).or_insert(0usize) += 1;
                counts
            })
        };
        walk(
            self.clone(),
            |node| match replacements.get(node) {
                // Comparing the cached types covers width and float format.
                Some(replacement) if replacement.ast_type() != node.ast_type() => Err(
                    ClarirsError::TypeError("Replace types must match!".to_string()),
                ),
                replacement => Ok(replacement.cloned()),
            },
            // Rebuilds `node` from its replaced `children`, keeping the
            // annotations it has as claripy's `make_like` did, first substituting
            // every pattern that is the same commutative op as `node` and
            // whose operands are all among `node`'s original operands, as
            // often as they are. The `to`s follow the unmatched operands
            // (which keep their replaced forms); a lone operand is returned bare.
            |node, children| {
                let patterns = &replacements.patterns;
                let Some(operands) =
                    commutative_operands(node.op()).filter(|_| !patterns.is_empty())
                else {
                    return ctx.make_ast_annotated(
                        node.op().with_children(children),
                        node.annotations().clone(),
                    );
                };
                // Match each pattern as often as its operands fit in the unmatched ones.
                let (mut unmatched, substituted) = patterns
                    .iter()
                    .filter(|(from, _)| discriminant(from.op()) == discriminant(node.op()))
                    .try_fold(
                        (multiset(operands), Vec::new()),
                        |(mut unmatched, mut substituted), (from, to)| {
                            let needed =
                                multiset(commutative_operands(from.op()).unwrap_or_default());
                            let times = needed
                                .iter()
                                .map(|(hash, n)| unmatched.get(hash).unwrap_or(&0) / n)
                                .min()
                                .unwrap_or(0);
                            if times > 0 && to.ast_type() != node.ast_type() {
                                return Err(ClarirsError::TypeError(
                                    "Replace types must match!".to_string(),
                                ));
                            }
                            for (hash, n) in &needed {
                                unmatched.entry(*hash).and_modify(|left| *left -= times * n);
                            }
                            substituted.extend(iter::repeat_n(to.clone(), times));
                            Ok((unmatched, substituted))
                        },
                    )?;
                if substituted.is_empty() {
                    return ctx.make_ast_annotated(
                        node.op().with_children(children),
                        node.annotations().clone(),
                    );
                }
                // The unmatched operands, in their replaced forms, then the substitutes.
                let new_children: Vec<_> = operands
                    .iter()
                    .zip(children)
                    .filter(|(operand, _)| match unmatched.get_mut(&operand.hash()) {
                        Some(left) if *left > 0 => {
                            *left -= 1;
                            true
                        }
                        _ => false,
                    })
                    .map(|(_, child)| child.clone())
                    .chain(substituted)
                    .collect();
                match new_children.as_slice() {
                    [only] => Ok(only.clone()),
                    _ => ctx.make_ast_annotated(
                        node.op().with_children(&new_children),
                        node.annotations().clone(),
                    ),
                }
            },
            &GenericCache::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let [a, b, c] = ["a", "b", "c"].map(|n| ctx.bvs(n, 32).unwrap());
        let expr = ctx.add(ctx.mul(&a, &b)?, &a)?;

        assert_eq!(expr.replace(&a, &c)?, ctx.add(ctx.mul(&c, &b)?, &c)?);
        assert_eq!(expr.replace(&ctx.mul(&a, &b)?, &c)?, ctx.add(&c, &a)?);
        // Nothing inside `to` is replaced.
        assert_eq!(
            expr.replace(&a, &ctx.neg(&a)?)?,
            ctx.add(ctx.mul(ctx.neg(&a)?, &b)?, ctx.neg(&a)?)?
        );
        assert_eq!(expr.replace(&c, &a)?, expr);
        Ok(())
    }

    #[test]
    fn test_replace_keeps_annotations() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let y = ctx.bvs("y", 32)?;
        let one = ctx.bvv(BitVec::from((1u64, 32)))?;
        let sticky = Annotation::new(AnnotationType::Uninitialized, false, false);
        let floating = Annotation::new(AnnotationType::SimplificationAvoidance, false, true);

        // A leaf that is not replaced keeps its annotations.
        let ax = x.clone().annotate([sticky.clone()])?;
        let replaced = ctx.add(&ax, &y)?.replace(&y, &one)?;
        assert_eq!(replaced, ctx.add(&ax, &one)?);
        assert_eq!(replaced.get_child(0).unwrap().annotations().len(), 1);
        // So does a leaf that is the whole expression.
        assert_eq!(ax.replace(&y, &one)?, ax);

        // A rebuilt inner node keeps the annotations of its own.
        let inner = ctx.add(&x, &y)?.annotate([sticky.clone()])?;
        assert_eq!(
            ctx.mul(&inner, &x)?.replace(&y, &one)?,
            ctx.mul(ctx.add(&x, &one)?.annotate([sticky.clone()])?, &x)?
        );

        // A relocatable annotation taken from a child is kept as well.
        let ay = y.clone().annotate([floating.clone()])?;
        let expr = ctx.add(&ay, &x)?;
        assert!(expr.annotations().contains(&floating));
        assert_eq!(expr.replace(&x, &one)?, ctx.add(&ay, &one)?);
        assert!(expr.replace(&x, &one)?.annotations().contains(&floating));

        // Operand-subset matches keep the node's own annotations too.
        let abc = ctx
            .add_many([x.clone(), y.clone(), one.clone()])?
            .annotate([sticky.clone()])?;
        assert_eq!(
            abc.replace(&ctx.add(&x, &one)?, &y)?,
            ctx.add(&y, &y)?.annotate([sticky])?
        );
        Ok(())
    }

    #[test]
    fn test_replace_type_mismatch() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32)?;
        let expr = ctx.add(&a, &a)?;
        let narrow = ctx.bvs("n", 8)?;
        let boolean = ctx.bools("p")?;

        // Width and sort are both checked, by `replace` and `replace_many`,
        // for whole-node and operand matches alike.
        for wrong in [&narrow, &boolean] {
            assert!(matches!(
                expr.replace(&a, wrong),
                Err(ClarirsError::TypeError(_))
            ));
            assert!(matches!(
                expr.replace_many(&Replacements::from_iter([(a.clone(), wrong.clone())])),
                Err(ClarirsError::TypeError(_))
            ));
            assert!(matches!(
                ctx.add_many([a.clone(), a.clone(), a.clone()])?
                    .replace(&expr, wrong),
                Err(ClarirsError::TypeError(_))
            ));
        }
        // The check applies only to replacements that match.
        assert_eq!(expr.replace(&narrow, &boolean)?, expr);
        Ok(())
    }

    #[test]
    fn test_replace_operand_subset() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let [a, b, c, d, e] = ["a", "b", "c", "d", "e"].map(|n| ctx.bvs(n, 32).unwrap());
        let from = ctx.add(&a, &c)?;
        let abc = ctx.add_many([a.clone(), b.clone(), c.clone()])?;

        // (a + b + c).replace(a + c, d) -> b + d, in any operand order.
        assert_eq!(abc.replace(&from, &d)?, ctx.add(&b, &d)?);
        assert_eq!(abc.replace(&ctx.add(&c, &a)?, &d)?, ctx.add(&b, &d)?);
        assert_eq!(ctx.add(&c, &a)?.replace(&from, &d)?, d);
        assert_eq!(
            ctx.and([a.clone(), b.clone(), c.clone()])?
                .replace(&ctx.and2(&c, &b)?, &d)?,
            ctx.and2(&a, &d)?
        );
        // Every matching set of operands is replaced; repeats must be there
        // as often as in the pattern.
        assert_eq!(
            ctx.add_many([a.clone(), c.clone(), b.clone(), a.clone(), c.clone()])?
                .replace(&from, &d)?,
            ctx.add_many([b.clone(), d.clone(), d.clone()])?
        );
        assert_eq!(
            abc.replace(&ctx.add_many([a.clone(), a.clone(), c.clone()])?, &d)?,
            abc
        );
        // A missing operand, another op, a nested node of the same op, or a
        // non-commutative op leave the expression alone.
        assert_eq!(abc.replace(&ctx.add(&a, &e)?, &d)?, abc);
        assert_eq!(abc.replace(&ctx.mul(&a, &c)?, &d)?, abc);
        let nested = ctx.add(ctx.add(&a, &b)?, &c)?;
        assert_eq!(nested.replace(&from, &d)?, nested);
        let concat = ctx.concat([a.clone(), b.clone(), c.clone()])?;
        assert_eq!(
            concat.replace(&ctx.concat2(&a, &c)?, &ctx.bvs("w", 64)?)?,
            concat
        );
        // Matches inside other ops; the unmatched operands still get their
        // own replacements, a matched operand is taken as it was.
        let replacements =
            Replacements::from_iter([(from.clone(), d.clone()), (b.clone(), e.clone())]);
        let expr = ctx.mul(
            ctx.add_many([a.clone(), ctx.neg(&from)?, c.clone()])?,
            ctx.add_many([b.clone(), abc.clone()])?,
        )?;
        assert_eq!(
            expr.replace_many(&replacements)?,
            ctx.mul(ctx.add(ctx.neg(&d)?, &d)?, ctx.add(&e, ctx.add(&e, &d)?)?)?
        );
        // The pattern with more operands takes precedence.
        let replacements =
            Replacements::from_iter([(from.clone(), d.clone()), (abc.clone(), e.clone())]);
        assert_eq!(
            ctx.add_many([a.clone(), b.clone(), c.clone(), c.clone()])?
                .replace_many(&replacements)?,
            ctx.add(&c, &e)?
        );
        Ok(())
    }
}
