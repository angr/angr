#![allow(clippy::mutable_key_type)]

use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    algorithms::{reconstruct::reconstruct_node, walk},
    cache::GenericCache,
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
        self.replace_many(&HashMap::from([(from, to)]))
    }

    /// Replaces every `from` subtree in `replacements` with its `to`.
    ///
    /// Every replacement must preserve the sort of the node it replaces,
    /// including bitvector width and float format; a mismatch is a
    /// [`ClarirsError::TypeError`].
    pub fn replace_many(
        self: &Arc<Self>,
        replacements: &HashMap<AstRef<'c>, AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        if replacements.is_empty() {
            return Ok(self.clone());
        }

        let ctx = self.context();
        walk(
            self.clone(),
            |node| match replacements.get(node) {
                // Comparing the cached types covers width and float format.
                Some(replacement) if replacement.ast_type() != node.ast_type() => Err(
                    ClarirsError::TypeError("Replace types must match!".to_string()),
                ),
                replacement => Ok(replacement.cloned()),
            },
            |node, children| reconstruct_node(ctx, &node, children),
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
    fn test_replace_type_mismatch() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32)?;
        let expr = ctx.add(&a, &a)?;
        let narrow = ctx.bvs("n", 8)?;
        let boolean = ctx.bools("p")?;

        // Width and sort are both checked, by `replace` and `replace_many`.
        for wrong in [&narrow, &boolean] {
            assert!(matches!(
                expr.replace(&a, wrong),
                Err(ClarirsError::TypeError(_))
            ));
            assert!(matches!(
                expr.replace_many(&HashMap::from([(a.clone(), wrong.clone())])),
                Err(ClarirsError::TypeError(_))
            ));
        }
        // The check applies only to replacements that match.
        assert_eq!(expr.replace(&narrow, &boolean)?, expr);
        Ok(())
    }
}
