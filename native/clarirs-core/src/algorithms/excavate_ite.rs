use std::sync::Arc;

use crate::{
    algorithms::{reconstruct::reconstruct_node, walk_post_order},
    ast::op::AstOp,
    prelude::*,
};

impl<'c> AstNode<'c> {
    /// Excavates if-then-else expressions to the top level of the AST.
    ///
    /// Returns a semantically equivalent AST where nested ITE expressions have
    /// been "excavated" (moved up) to the top level where possible. For
    /// example, `a + (if cond then b else c)` becomes
    /// `if cond then (a + b) else (a + c)`.
    pub fn excavate_ite(self: &Arc<Self>) -> Result<AstRef<'c>, ClarirsError> {
        walk_post_order(
            self.clone(),
            |node, children| excavate_node(&node, children),
            &self.context().excavate_ite_cache,
        )
    }
}

/// Hoists `ITE`s out of a single node whose children have already been
/// excavated. Because every operation now shares one op enum and children are
/// rebuilt uniformly via [`reconstruct_node`], the per-sort distribution rules
/// (`op(.., ITE(c, t, e), ..) -> ITE(c, op(.., t, ..), op(.., e, ..))`) collapse
/// into this single routine.
///
/// Exactly one condition is hoisted per node: the one carried by the node's
/// first `ITE` child. The remaining children are folded into both branches --
/// taken apart if they are `ITE`s on that same condition (or on its negation),
/// passed through untouched otherwise. A child that is an `ITE` on some
/// *unrelated* condition cannot be folded that way, and distributing over it as
/// well would build the full 2^n decision tree, so the node is left alone
/// instead. This matches what the reference Python implementation does, and is
/// what keeps the pass linear in the size of the AST.
///
/// An `ITE` is already in excavated form, so its branches are left in place.
fn excavate_node<'c>(
    ast: &AstRef<'c>,
    children: &[AstRef<'c>],
) -> Result<AstRef<'c>, ClarirsError> {
    let ctx = ast.context();

    // Annotated nodes are opaque: rebuilding one through the context would drop
    // its annotations, so hand it back untouched.
    if !ast.annotations().is_empty() {
        return Ok(ast.clone());
    }

    if matches!(ast.op(), AstOp::ITE(..)) {
        return reconstruct_node(ctx, ast, children);
    }

    let idx = match children
        .iter()
        .position(|c| matches!(c.op(), AstOp::ITE(..)))
    {
        Some(idx) => idx,
        None => return reconstruct_node(ctx, ast, children),
    };

    let cond = match children[idx].op() {
        AstOp::ITE(cond, _, _) => cond.clone(),
        _ => unreachable!(),
    };
    let not_cond = ctx.not(&cond)?;

    let mut then_children = Vec::with_capacity(children.len());
    let mut else_children = Vec::with_capacity(children.len());
    for child in children {
        match child.op() {
            AstOp::ITE(c, then_, else_) if c.hash() == cond.hash() => {
                then_children.push(then_.clone());
                else_children.push(else_.clone());
            }
            AstOp::ITE(c, then_, else_) if c.hash() == not_cond.hash() => {
                then_children.push(else_.clone());
                else_children.push(then_.clone());
            }
            // An `ITE` on an unrelated condition: give up rather than expand.
            AstOp::ITE(..) => return reconstruct_node(ctx, ast, children),
            _ => {
                then_children.push(child.clone());
                else_children.push(child.clone());
            }
        }
    }

    let then_branch = reconstruct_node(ctx, ast, &then_children)?;
    let else_branch = reconstruct_node(ctx, ast, &else_children)?;
    ctx.ite(cond, then_branch, else_branch)
}

#[cfg(test)]
mod tests;
