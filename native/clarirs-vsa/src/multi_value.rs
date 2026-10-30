//! Bitvectors that stand for several alternative values: a `Union` of the
//! alternatives, or a `Concat` of pieces whose alternatives are tracked on
//! their own, such as `Concat(Union(a, b), c)`.

use std::collections::HashSet;

use clarirs_core::algorithms::walk;
use clarirs_core::cache::GenericCache;
use clarirs_core::prelude::*;

/// How many alternatives a value is expanded into before they are treated as
/// unknown.
pub const UNION_EXPANSION_LIMIT: usize = 256;

/// The values `ast` can take once every Union in it is expanded, simplified
/// and without duplicates, or `None` past [`UNION_EXPANSION_LIMIT`]. Every
/// occurrence of one Union node takes the same choice (`x * x` for
/// `x = Union(a, b)` gives `[a * a, b * b]`); distinct Union nodes are
/// independent.
fn expand_unions<'c>(ast: &AstRef<'c>) -> Result<Option<Vec<AstRef<'c>>>, ClarirsError> {
    // a Union is always symbolic
    if !ast.symbolic() {
        return Ok(Some(vec![ast.clone()]));
    }
    let mut pending = vec![ast.clone()];
    let mut done: Vec<AstRef<'c>> = Vec::new();
    let mut seen = HashSet::new();
    while let Some(expr) = pending.pop() {
        let union_node = walk(
            expr.clone(),
            |node| Ok(matches!(node.op(), AstOp::Union(..)).then(|| Some(node.clone()))),
            |_, children| Ok(children.iter().find_map(Clone::clone)),
            &GenericCache::default(),
        )?;
        if let Some(union_node) = union_node
            && let AstOp::Union(members) = union_node.op()
        {
            for member in members.iter().rev() {
                pending.push(expr.replace(&union_node, member)?);
            }
        } else {
            let simplified = expr.simplify()?;
            if seen.insert(simplified.hash()) {
                done.push(simplified);
            }
        }
        if done.len() + pending.len() > UNION_EXPANSION_LIMIT {
            return Ok(None);
        }
    }
    Ok(Some(done))
}

/// Reading values that stand for several alternatives.
pub trait MultiValue<'c> {
    /// The alternatives of this value, or `None` when it is made of several
    /// independently tracked pieces or has more than
    /// [`UNION_EXPANSION_LIMIT`] alternatives.
    fn mv_eval(&self) -> Result<Option<Vec<AstRef<'c>>>, ClarirsError>;
}

impl<'c> MultiValue<'c> for AstRef<'c> {
    fn mv_eval(&self) -> Result<Option<Vec<AstRef<'c>>>, ClarirsError> {
        if !self.symbolic() {
            return Ok(Some(vec![self.clone()]));
        }
        // the pieces are the operands of a Concat, and the operand and zero
        // padding of a ZeroExt, which is how the simplifier writes Concat(0, x)
        let mut pieces = Vec::new();
        let mut padded = false;
        let mut stack = vec![self.clone()];
        while let Some(piece) = stack.pop() {
            match piece.op() {
                AstOp::Concat(args) => stack.extend(args.iter().cloned()),
                AstOp::ZeroExt(inner, amount) if amount % 8 == 0 => {
                    padded = true;
                    stack.push(inner.clone());
                }
                _ => pieces.push(piece),
            }
        }
        if pieces.len() == 1 && !padded {
            return expand_unions(self);
        }
        // several pieces make a single value when every piece is one
        for piece in &pieces {
            if !matches!(expand_unions(piece)?, Some(values) if values.len() == 1) {
                return Ok(None);
            }
        }
        Ok(Some(vec![self.clone()]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bvv<'c>(ctx: &'c Context<'c>, value: u64) -> AstRef<'c> {
        ctx.bvv(BitVec::from((value, 32))).unwrap()
    }

    fn union<'c>(ctx: &'c Context<'c>, values: &[u64]) -> AstRef<'c> {
        ctx.union(values.iter().map(|v| bvv(ctx, *v))).unwrap()
    }

    fn eval(ast: &AstRef<'_>) -> Option<Vec<u64>> {
        ast.mv_eval().unwrap().map(|values| {
            values
                .iter()
                .map(|v| match v.op() {
                    AstOp::BVV(value) => value.to_u64().unwrap(),
                    _ => panic!("not a constant: {v:?}"),
                })
                .collect()
        })
    }

    #[test]
    fn test_single_values() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        for value in [bvv(&ctx, 1), x.clone(), ctx.add(&x, bvv(&ctx, 1))?] {
            assert_eq!(value.mv_eval()?, Some(vec![value.clone()]));
        }
        Ok(())
    }

    #[test]
    fn test_alternatives() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        assert_eq!(eval(&union(&ctx, &[1, 2])), Some(vec![1, 2]));
        // under an operation
        assert_eq!(
            eval(&ctx.add(union(&ctx, &[1, 2]), bvv(&ctx, 3))?),
            Some(vec![4, 5])
        );
        // the same Union node takes the same choice; distinct nodes are independent
        let a = union(&ctx, &[1, 5]);
        assert_eq!(eval(&ctx.mul(&a, &a)?), Some(vec![1, 25]));
        assert_eq!(
            eval(&ctx.add(&a, union(&ctx, &[10, 20]))?),
            Some(vec![11, 21, 15, 25])
        );
        // nested
        let inner = ctx.add(&x, union(&ctx, &[1, 2]))?;
        let outer = ctx.union([inner, bvv(&ctx, 7)])?;
        assert_eq!(outer.mv_eval()?.map(|v| v.len()), Some(3));
        Ok(())
    }

    #[test]
    fn test_pieces() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let mv = union(&ctx, &[1, 2]);
        assert_eq!(ctx.concat([x.clone(), mv.clone()])?.mv_eval()?, None);
        let padded = ctx.concat([bvv(&ctx, 0), mv])?.simplify()?;
        assert!(matches!(padded.op(), AstOp::ZeroExt(..)));
        assert_eq!(padded.mv_eval()?, None);
        let joined = ctx.concat([x, bvv(&ctx, 1)])?.simplify()?;
        assert_eq!(joined.mv_eval()?, Some(vec![joined.clone()]));
        Ok(())
    }

    #[test]
    fn test_too_many_alternatives() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let values: Vec<u64> = (0..17).collect();
        let strided: Vec<u64> = values.iter().map(|v| v * 17).collect();
        // 17 * 17 distinct sums
        let expr = ctx.add(union(&ctx, &values), union(&ctx, &strided))?;
        assert_eq!(expr.mv_eval()?, None);
        Ok(())
    }

    #[test]
    fn test_member_annotations_are_kept() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let tag = Annotation::new(AnnotationType::Uninitialized, false, true);
        let a = ctx.bvs("a", 32)?.annotate([tag.clone()])?;
        let mv = ctx.union([a, ctx.bvs("b", 32)?])?;
        let result = ctx.add(&mv, bvv(&ctx, 1))?.mv_eval()?.unwrap();
        assert!(result[0].annotations().contains(&tag));
        Ok(())
    }
}
