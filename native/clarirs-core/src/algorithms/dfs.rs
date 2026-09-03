use crate::prelude::*;

pub enum DfsResult {
    Continue,
    SkipChildren,
    Stop,
}

/// Walks the AST in depth-first order.
///
/// The callback is called for each node in the AST. If the callback returns
/// `DfsResult::Continue`, the children of the node are visited. If the callback
/// returns `DfsResult::SkipChildren`, the children of the node are not visited.
/// If the callback returns `DfsResult::Stop`, the traversal is stopped.
pub fn walk_dfs<'c>(
    ast: &AstRef<'c>,
    mut callback: impl FnMut(&AstRef<'c>) -> DfsResult,
) -> Result<(), ClarirsError> {
    let mut stack = vec![ast.clone()];

    while let Some(current) = stack.pop() {
        match callback(&current) {
            DfsResult::Continue => {
                for child in current.child_iter() {
                    stack.push(child.clone());
                }
            }
            DfsResult::SkipChildren => continue,
            DfsResult::Stop => break,
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_walk_dfs() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        let ast = ctx.add(
            &ctx.bvs("a", 64)?,
            &ctx.mul(&ctx.bvs("b", 64)?, &ctx.bvs("c", 64)?)?,
        )?;
        let var_ast = ast.clone();
        let mut visited = Vec::new();

        walk_dfs(&var_ast, |node| {
            visited.push(node.clone());
            DfsResult::Continue
        })
        .unwrap();

        assert_eq!(visited.len(), 5);

        Ok(())
    }
}
