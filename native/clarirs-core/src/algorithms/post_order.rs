use crate::cache::Cache;
use crate::prelude::*;
use std::collections::VecDeque;

/// Walks the AST in post-order (children before parents), providing transformed
/// children to each callback.
///
/// The callback is called for each node after its children have been visited
/// and transformed.
/// It receives:
/// - The original node
/// - The transformed versions of its children
///
/// And returns either:
/// - Ok(transformed_node) to continue traversal
/// - Err(error) to stop traversal with an error
///
/// If a cache is provided, previously processed subtrees will use cached
/// results instead of recomputing them, which can significantly improve
/// performance for trees with repeated subtrees. If you do not want to use a
/// cache, pass `&()` as the cache.
pub fn walk_post_order<'c, T>(
    ast: AstRef<'c>,
    mut callback: impl FnMut(AstRef<'c>, &[T]) -> Result<T, ClarirsError>,
    cache: &impl Cache<u64, T>,
) -> Result<T, ClarirsError> {
    // For each node, we need to track:
    // 1. The node itself
    // 2. Whether all its children have been processed
    // 3. The transformed results of its children
    struct NodeState<'c, T> {
        node: AstRef<'c>,
        children_processed: usize,
        num_children: usize,
        child_results: Vec<T>,
    }

    let mut stack = Vec::new();
    let mut result_queue = VecDeque::new();

    // Start with the root node
    let num_children = ast.child_iter().len();
    stack.push(NodeState {
        node: ast,
        children_processed: 0,
        num_children,
        child_results: Vec::new(),
    });

    while let Some(mut state) = stack.pop() {
        if state.children_processed == state.num_children {
            // All children processed, process this node
            result_queue.push_back(cache.get_or_insert(state.node.hash(), || {
                callback(state.node.clone(), &state.child_results)
            })?);
        } else {
            // Process next child
            let child = state.node.get_child(state.children_processed).unwrap();
            state.children_processed += 1;

            // If the child's result is already cached (from an earlier walk or
            // from a shared subtree visited earlier in this walk), reuse it
            // instead of re-traversing the subtree. ASTs are DAGs, so a shared
            // subtree is reachable from multiple parents; reusing the cached
            // result avoids re-running the traversal once per parent.
            if let Some(cached) = cache.get(&child.hash()) {
                state.child_results.push(cached);
                stack.push(state);
                continue;
            }

            // Push parent back on stack
            stack.push(state);

            // Push child on stack
            let num_children = child.child_iter().len();
            stack.push(NodeState {
                node: child,
                children_processed: 0,
                num_children,
                child_results: Vec::new(),
            });
        }

        // If we just finished processing a child, add its result to its parent
        if !result_queue.is_empty()
            && !stack.is_empty()
            && let Some(parent) = stack.last_mut()
            && parent.children_processed > 0
        {
            parent.child_results.push(result_queue.pop_front().unwrap());
        }
    }

    // The final result should be the only one in the queue
    result_queue.pop_front().ok_or(ClarirsError::EmptyTraversal)
}

#[cfg(test)]
mod tests {
    use crate::cache::GenericCache;

    use super::*;

    #[test]
    fn test_walk_post_order() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let add = ctx.add(&x, &y)?;

        // Track visited nodes and transformations
        let mut visited = Vec::new();
        walk_post_order(
            add.clone(),
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

        // Verify traversal order and transformations
        assert_eq!(visited.len(), 3);
        assert!(visited[0].starts_with("var(x)"));
        assert_eq!(visited[0], "var(x) with 0 children");
        assert!(visited[1].starts_with("var(y)"));
        assert_eq!(visited[1], "var(y) with 0 children");
        assert!(visited[2].starts_with("add"));
        assert_eq!(visited[2], "add with 2 children");

        Ok(())
    }

    #[test]
    fn test_walk_post_order_with_error() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;

        let result = walk_post_order(
            x.clone(),
            |_node, _children| -> Result<String, ClarirsError> {
                Err(ClarirsError::InvalidArguments("test error".to_string()))
            },
            &(),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ClarirsError::InvalidArguments(_)
        ));
        Ok(())
    }

    #[test]
    fn test_walk_post_order_with_cache() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;

        // Create a common subexpression
        let add1 = ctx.add(&x, &y)?;
        let add2 = ctx.add(&x, &y)?;
        let mul = ctx.mul(&add1, &add2)?;

        // Create a cache
        let cache = GenericCache::default();

        // Create a counter to track actual callback invocations
        let mut first_visited = Vec::new();

        // First traversal populates the cache
        walk_post_order(
            mul.clone(),
            |node, _| {
                first_visited.push(node.clone());
                Ok(())
            },
            &cache,
        )?;

        let mut second_visited = Vec::new();

        // Second traversal should use the cache for common subexpressions
        walk_post_order(
            mul.clone(),
            |node, _| {
                second_visited.push(node.clone());
                Ok(())
            },
            &cache,
        )?;

        // Compute expected counts:
        // First run should process: x, y, add1, x, y, add2, mul => 7 nodes
        assert_eq!(first_visited, vec![x, y, add1, mul]);

        // Second run should process nothing new
        assert!(second_visited.is_empty());

        Ok(())
    }
}
