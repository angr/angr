//! Linear term cancellation over bitvector Add/Sub/Neg (and Mul by a constant).
//!
//! A chain is flattened into `sum(coeff_i * term_i) + c` with coefficients mod 2^n, equal terms
//! are merged, and the chain is rebuilt only when that removes a symbolic term occurrence.
//! Terms are identified by their hash-consed node, annotations included: analyses use
//! annotations to tell apart otherwise equal leaves (e.g. variable recovery's annotated `top`).

use ahash::AHashMap;

use crate::prelude::*;

/// Upper bound on nodes visited per flattened chain; keeps the pass linear in the DAG size.
const MAX_VISITS: usize = 256;

struct Term<'c> {
    rep: AstRef<'c>,
    coeff: BitVec,
}

/// Whether `node` must never be merged or eliminated: it carries an annotation that is neither
/// eliminatable nor relocatable, or it is a VSA set (where `x - x` is not 0).
fn pinned(node: &AstRef<'_>) -> bool {
    node.op().is_inherently_symbolic()
        || node
            .annotations()
            .iter()
            .any(|a| !a.eliminatable() && !a.relocatable())
}

fn sum<'c>(ctx: &'c Context<'c>, mut args: Vec<AstRef<'c>>) -> Result<AstRef<'c>, ClarirsError> {
    if args.len() == 1 {
        Ok(args.pop().unwrap())
    } else {
        ctx.add_many(args)
    }
}

/// Cancel terms in the sum `sum(coeff_i * roots_i)` of width `size`. Returns `None` unless some
/// symbolic term occurrence disappears.
pub(super) fn cancel_terms<'c>(
    ctx: &'c Context<'c>,
    size: u32,
    roots: Vec<(AstRef<'c>, BitVec)>,
) -> Result<Option<AstRef<'c>>, ClarirsError> {
    // Fast path: without a nested chain among the roots, only a repeated root can cancel.
    let nested = roots.iter().any(|(r, _)| {
        matches!(
            r.op(),
            AstOp::Add(_) | AstOp::Sub(..) | AstOp::Neg(_) | AstOp::Mul(_)
        )
    });
    if !nested {
        let mut symbolic = roots
            .iter()
            .filter(|(r, _)| !matches!(r.op(), AstOp::BVV(_)));
        let repeated = match roots.len() {
            0..=2 => match (symbolic.next(), symbolic.next()) {
                (Some((a, _)), Some((b, _))) => a.hash() == b.hash(),
                _ => false,
            },
            _ => {
                let mut seen = ahash::AHashSet::with_capacity(roots.len());
                !symbolic.all(|(r, _)| seen.insert(r.hash()))
            }
        };
        if !repeated {
            return Ok(None);
        }
    }

    let mut stack = roots;
    stack.reverse();
    let mut terms: Vec<Term<'c>> = Vec::new();
    let mut index: AHashMap<u64, usize> = AHashMap::new();
    let mut constant = BitVec::zeros(size);
    let mut occurrences = 0usize;
    let mut visits = 0usize;

    while let Some((node, coeff)) = stack.pop() {
        visits += 1;
        if visits > MAX_VISITS {
            return Ok(None);
        }
        // Flattening drops the node; only relocatable annotations survive that (on the root).
        if node.annotations().iter().all(|a| a.relocatable()) {
            match node.op() {
                AstOp::Add(args) => {
                    stack.extend(args.iter().rev().map(|a| (a.clone(), coeff.clone())));
                    continue;
                }
                AstOp::Sub(a, b) => {
                    stack.push((b.clone(), (-coeff.clone())?));
                    stack.push((a.clone(), coeff));
                    continue;
                }
                AstOp::Neg(a) => {
                    stack.push((a.clone(), (-coeff)?));
                    continue;
                }
                AstOp::Mul(args) if args.len() == 2 => match (args[0].op(), args[1].op()) {
                    (_, AstOp::BVV(k)) if args[1].annotations().is_empty() => {
                        stack.push((args[0].clone(), (coeff * k.clone())?));
                        continue;
                    }
                    (AstOp::BVV(k), _) if args[0].annotations().is_empty() => {
                        stack.push((args[1].clone(), (coeff * k.clone())?));
                        continue;
                    }
                    _ => {}
                },
                AstOp::BVV(v) => {
                    constant = (constant + (coeff * v.clone())?)?;
                    continue;
                }
                _ => {}
            }
        }

        occurrences += 1;
        if pinned(&node) {
            terms.push(Term { rep: node, coeff });
            continue;
        }
        match index.entry(node.hash()) {
            std::collections::hash_map::Entry::Occupied(e) => {
                let term = &mut terms[*e.get()];
                term.coeff = (term.coeff.clone() + coeff)?;
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(terms.len());
                terms.push(Term { rep: node, coeff });
            }
        }
    }

    terms.retain(|t| !t.coeff.is_zero());
    if terms.len() >= occurrences {
        return Ok(None);
    }

    // Rebuild as (P + c) - N in first-occurrence order; a coefficient whose negation is smaller
    // (sign bit set) goes to N.
    let mut pos: Vec<AstRef<'c>> = Vec::new();
    let mut neg: Vec<AstRef<'c>> = Vec::new();
    for Term { rep, coeff } in terms {
        if coeff.is_one() {
            pos.push(rep);
            continue;
        }
        let negated = (-coeff.clone())?;
        if negated.is_one() {
            neg.push(rep);
        } else if coeff.sign() {
            neg.push(ctx.mul_many([rep, ctx.bvv(negated)?])?);
        } else {
            pos.push(ctx.mul_many([rep, ctx.bvv(coeff)?])?);
        }
    }
    if !constant.is_zero() {
        pos.push(ctx.bvv(constant)?);
    }

    let result = match (pos.is_empty(), neg.is_empty()) {
        (true, true) => ctx.bvv(BitVec::zeros(size))?,
        (false, true) => sum(ctx, pos)?,
        (true, false) => ctx.neg(sum(ctx, neg)?)?,
        (false, false) => ctx.sub(sum(ctx, pos)?, sum(ctx, neg)?)?,
    };
    Ok(Some(result))
}
