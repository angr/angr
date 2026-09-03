//! Shared helper for reconstructing an AST node from its transformed children.
//! Used by the `replace` algorithm.

use crate::{ast::op::AstOp, prelude::*};

/// Rebuilds `ast`'s op with `children` substituted in, without interning.
/// Returns `None` for leaves. The structural half of [`reconstruct_node`].
pub fn rebuild_op<'c>(ast: &AstRef<'c>, children: &[AstRef<'c>]) -> Option<AstOp<'c>> {
    ast.op().with_children(children)
}

/// Reconstructs a node from its operation and transformed children.
///
/// Leaf nodes are returned as-is. Non-leaf nodes are rebuilt by replacing the
/// op's children with the transformed ones and re-interning via the context;
/// the node's type is re-inferred from the (same-typed) children.
pub fn reconstruct_node<'c>(
    ctx: &'c Context<'c>,
    ast: &AstRef<'c>,
    children: &[AstRef<'c>],
) -> Result<AstRef<'c>, ClarirsError> {
    match rebuild_op(ast, children) {
        Some(op) => ctx.make_ast(op),
        None => Ok(ast.clone()),
    }
}
