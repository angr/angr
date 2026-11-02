use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    algorithms::{reconstruct::reconstruct_node, walk},
    cache::GenericCache,
    prelude::*,
};

/// Results of a replacement walk by node hash; `None` means the node itself.
pub type ReplaceMemo<'c> = ahash::HashMap<u64, Option<AstRef<'c>>>;

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
        walk(
            self.clone(),
            |ast| {
                if *ast == from {
                    Ok(Some(to.clone()))
                } else {
                    Ok(None)
                }
            },
            |ast, children| reconstruct_node(ctx, &ast, children),
            &GenericCache::default(),
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
        walk(
            self.clone(),
            |node| {
                if let Some(replacement) = replacements.get(&node.hash()) {
                    Ok(Some(replacement.clone()))
                } else {
                    Ok(None)
                }
            },
            |node, children| reconstruct_node(ctx, &node, children),
            &GenericCache::default(),
        )
    }

    /// [`replace_many`](Self::replace_many) (or, with `loose`,
    /// [`replace_many_loose`](Self::replace_many_loose)) with `memo` holding the walk's results
    /// across calls. Every node the walk visits gets an entry, so an entry can only depend on a
    /// node that has one too. The caller keeps `memo` valid for `replacements`. A node the walk
    /// returns unchanged is recorded as `None`, so the memo does not keep it alive.
    pub fn replace_many_memo(
        self: &Arc<Self>,
        replacements: &HashMap<u64, AstRef<'c>>,
        memo: &mut ReplaceMemo<'c>,
        loose: bool,
    ) -> Result<AstRef<'c>, ClarirsError> {
        if replacements.is_empty() {
            return Ok(self.clone());
        }
        let ctx = self.context();
        let known = |memo: &ReplaceMemo<'c>, node: &AstRef<'c>| {
            memo.get(&node.hash()).map(|r| r.clone().unwrap_or_else(|| node.clone()))
        };
        let record = |memo: &mut ReplaceMemo<'c>, node: &AstRef<'c>, result: &AstRef<'c>| {
            let entry = if result.hash() == node.hash() { None } else { Some(result.clone()) };
            memo.insert(node.hash(), entry);
        };
        // (node, results of its finished children)
        let mut stack: Vec<(AstRef<'c>, Vec<AstRef<'c>>)> = vec![(self.clone(), Vec::new())];
        let mut last: Option<AstRef<'c>> = None;
        while let Some((node, mut done)) = stack.pop() {
            if let Some(result) = last.take() {
                done.push(result);
            } else if done.is_empty() {
                if let Some(result) = known(memo, &node) {
                    last = Some(result);
                    continue;
                }
                let found = match replacements.get(&node.hash()) {
                    None if loose => replacements.get(&node.hash_without_annotations()),
                    found => found,
                };
                if let Some(replacement) = found {
                    record(memo, &node, replacement);
                    last = Some(replacement.clone());
                    continue;
                }
            }
            let n = node.child_iter().len();
            if done.len() < n {
                let child = node.get_child(done.len()).unwrap();
                stack.push((node, done));
                stack.push((child, Vec::new()));
            } else {
                let result = match known(memo, &node) {
                    Some(result) => result,
                    None => {
                        let result = reconstruct_node(ctx, &node, &done)?;
                        record(memo, &node, &result);
                        result
                    }
                };
                last = Some(result);
            }
        }
        last.ok_or(ClarirsError::EmptyTraversal)
    }

    /// [`replace_many`](Self::replace_many), but a node carrying annotations also matches
    /// a replacement registered for its bare form and vice versa. The replacement solver
    /// uses this: annotations are metadata about where a value came from, not part of
    /// its identity, and a concretization learned for `x` must fire on `x{region}`.
    pub fn replace_many_loose(
        self: &Arc<Self>,
        replacements: &HashMap<u64, AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        if replacements.is_empty() {
            return Ok(self.clone());
        }

        let ctx = self.context();
        walk(
            self.clone(),
            |node| {
                if let Some(replacement) = replacements
                    .get(&node.hash())
                    .or_else(|| replacements.get(&node.hash_without_annotations()))
                {
                    Ok(Some(replacement.clone()))
                } else {
                    Ok(None)
                }
            },
            |node, children| reconstruct_node(ctx, &node, children),
            &GenericCache::default(),
        )
    }
}
