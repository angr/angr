use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    algorithms::{pre_order::walk_pre_order, reconstruct::reconstruct_node},
    prelude::*,
};

impl<'c> AstNode<'c> {
    /// Replaces every occurrence of `from` in this AST with `to`.
    pub fn replace<T: Clone + Into<AstRef<'c>>>(
        self: &Arc<Self>,
        from: &T,
        to: &T,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let from = from.clone().into();
        let to = to.clone().into();

        // The replacement must preserve the sort, including bitvector width
        // and float format; comparing the cached types covers all of that.
        if from.ast_type() != to.ast_type() {
            return Err(ClarirsError::TypeError(
                "Replace types must match!".to_string(),
            ));
        }

        let ctx = self.context();
        walk_pre_order(
            self.clone(),
            |ast| {
                if *ast == from {
                    Ok(Some(to.clone()))
                } else {
                    Ok(None)
                }
            },
            |ast, children| reconstruct_node(ctx, &ast, children),
        )
    }

    /// Replaces subtrees by hash, using the given hash-to-replacement map.
    pub fn replace_many(
        self: &Arc<Self>,
        replacements: &HashMap<u64, AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        if replacements.is_empty() {
            return Ok(self.clone());
        }

        let ctx = self.context();
        walk_pre_order(
            self.clone(),
            |node| {
                if let Some(replacement) = replacements.get(&node.hash()) {
                    Ok(Some(replacement.clone()))
                } else {
                    Ok(None)
                }
            },
            |node, children| reconstruct_node(ctx, &node, children),
        )
    }
}
