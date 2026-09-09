use crate::cache::Cache;
use crate::prelude::*;

/// Walks the AST depth-first with an explicit stack, calling `pre_visit` when
/// a node is first reached and `post_visit` once all of its children have been
/// visited (children before parents).
///
/// `pre_visit` returns `Some(result)` to short-circuit: the subtree is skipped,
/// `post_visit` is not called for the node, and `result` stands in for it.
/// Returning `None` descends into the children, whose results are passed to
/// `post_visit` in child order.
///
/// Every result is stored in `cache` under the node's hash, and a node whose
/// hash is already cached is not visited at all, so shared subtrees (ASTs are
/// DAGs) are processed once per cache lifetime. Pass `&()` to disable caching.
pub fn walk<'c, T>(
    ast: AstRef<'c>,
    mut pre_visit: impl FnMut(&AstRef<'c>) -> Result<Option<T>, ClarirsError>,
    mut post_visit: impl FnMut(AstRef<'c>, &[T]) -> Result<T, ClarirsError>,
    cache: &impl Cache<u64, T>,
) -> Result<T, ClarirsError> {
    struct NodeState<'c, T> {
        node: AstRef<'c>,
        num_children: usize,
        child_results: Vec<T>,
    }

    impl<'c, T> NodeState<'c, T> {
        fn new(node: AstRef<'c>) -> Self {
            let num_children = node.child_iter().len();
            NodeState {
                node,
                num_children,
                child_results: Vec::with_capacity(num_children),
            }
        }
    }

    let mut stack = vec![NodeState::new(ast)];
    let mut last_result: Option<T> = None;

    while let Some(mut state) = stack.pop() {
        // Collect result from a completed child
        if let Some(result) = last_result.take() {
            state.child_results.push(result);
        }

        let children_done = state.child_results.len();

        if children_done == 0 {
            // First visit — check cache, then pre_visit
            if let Some(cached) = cache.get(&state.node.hash()) {
                last_result = Some(cached);
                continue;
            }
            if let Some(result) = pre_visit(&state.node)? {
                cache.insert(state.node.hash(), &result);
                last_result = Some(result);
                continue;
            }
        }

        if children_done < state.num_children {
            // Descend into the next child
            let child = state.node.get_child(children_done).unwrap();
            stack.push(state);
            stack.push(NodeState::new(child));
        } else {
            // All children done — call post_visit
            let result = cache.get_or_insert(state.node.hash(), || {
                post_visit(state.node.clone(), &state.child_results)
            })?;
            last_result = Some(result);
        }
    }

    last_result.ok_or(ClarirsError::EmptyTraversal)
}

#[cfg(test)]
mod tests {
    use crate::cache::GenericCache;

    use super::*;

    #[test]
    fn test_walk_visits_all_nodes() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        let ast = ctx.add(
            &ctx.bvs("a", 64)?,
            &ctx.mul(&ctx.bvs("b", 64)?, &ctx.bvs("c", 64)?)?,
        )?;
        let var_ast = ast.clone();
        let mut visited = Vec::new();

        walk(
            var_ast,
            |node| {
                visited.push(node.clone());
                Ok(None)
            },
            |_, _| Ok(()),
            &(),
        )
        .unwrap();

        assert_eq!(visited.len(), 5);

        Ok(())
    }

    #[test]
    fn test_walk_post_visit_order() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let add = ctx.add(&x, &y)?;

        let mut visited = Vec::new();
        walk(
            add.clone(),
            |_| Ok(None),
            |node, children| {
                let node_type = match node.op() {
                    AstOp::BVS(s, _) => format!("var({s})"),
                    AstOp::Add(_) => "add".to_string(),
                    op => format!("other({op:?})"),
                };
                let info = format!("{} with {} children", node_type, children.len());
                visited.push(info.clone());
                Ok(info)
            },
            &(),
        )?;

        assert_eq!(
            visited,
            vec![
                "var(x) with 0 children",
                "var(y) with 0 children",
                "add with 2 children"
            ]
        );
        Ok(())
    }

    #[test]
    fn test_walk_propagates_error() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;

        let result = walk(
            x.clone(),
            |_| Ok(None),
            |_node, _children| -> Result<String, ClarirsError> {
                Err(ClarirsError::InvalidArguments("test error".to_string()))
            },
            &(),
        );

        assert!(matches!(result, Err(ClarirsError::InvalidArguments(_))));
        Ok(())
    }

    #[test]
    fn test_walk_reuses_cache() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let add1 = ctx.add(&x, &y)?;
        let add2 = ctx.add(&x, &y)?;
        let mul = ctx.mul(&add1, &add2)?;

        let cache = GenericCache::default();

        let mut first_visited = Vec::new();
        walk(
            mul.clone(),
            |_| Ok(None),
            |node, _| {
                first_visited.push(node.clone());
                Ok(())
            },
            &cache,
        )?;

        let mut second_visited = Vec::new();
        walk(
            mul.clone(),
            |_| Ok(None),
            |node, _| {
                second_visited.push(node.clone());
                Ok(())
            },
            &cache,
        )?;

        // The shared add(x, y) is processed once; the second walk hits the cache at the root.
        assert_eq!(first_visited, vec![x, y, add1, mul]);
        assert!(second_visited.is_empty());
        Ok(())
    }

    #[test]
    fn test_walk_leaf() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;

        let result = walk(
            x.clone(),
            |_| Ok(None),
            |node, _children| Ok(node),
            &GenericCache::default(),
        )?;

        assert_eq!(result, x);
        Ok(())
    }

    #[test]
    fn test_walk_short_circuit() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let add = ctx.add(&x, &y)?;
        let replacement = ctx.bvv(BitVec::from((99, 64)))?;

        let result = walk(
            add.clone(),
            |_| Ok(Some(replacement.clone())),
            |_, _| panic!("post_visit should not be called"),
            &GenericCache::default(),
        )?;

        assert_eq!(result, replacement);
        Ok(())
    }

    #[test]
    fn test_walk_visits_children_once() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let add = ctx.add(&x, &y)?;

        let mut pre_visit_count = 0;
        let mut post_visit_count = 0;
        walk(
            add.clone(),
            |_| {
                pre_visit_count += 1;
                Ok(None)
            },
            |node, _children| {
                post_visit_count += 1;
                Ok(node)
            },
            &GenericCache::default(),
        )?;

        assert_eq!(pre_visit_count, 3);
        assert_eq!(post_visit_count, 3);
        Ok(())
    }

    #[test]
    fn test_walk_selective_short_circuit() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let z = ctx.bvs("z", 64)?;
        let add = ctx.add(&x, &y)?;

        // Replace x with z in add(x, y)
        let result = walk(
            add.clone(),
            |node| {
                if *node == x {
                    Ok(Some(z.clone()))
                } else {
                    Ok(None)
                }
            },
            |node, children| {
                if children.is_empty() {
                    Ok(node)
                } else {
                    Ok(ctx.add(&children[0], &children[1])?)
                }
            },
            &GenericCache::default(),
        )?;

        assert_eq!(result, ctx.add(&z, &y)?);
        Ok(())
    }

    #[test]
    fn test_walk_shared_subtrees_cached() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let add = ctx.add(&x, &y)?;
        let mul = ctx.mul(&add, &add)?;

        let mut pre_visit_count = 0;
        walk(
            mul.clone(),
            |_| {
                pre_visit_count += 1;
                Ok(None)
            },
            |node, _children| Ok(node),
            &GenericCache::default(),
        )?;

        // mul, add(x, y) once (the second occurrence is cached), x and y.
        assert_eq!(pre_visit_count, 4);
        Ok(())
    }
}
