use std::collections::{BTreeSet, HashSet};

use crate::prelude::*;

use super::dfs::{DfsResult, walk_dfs};

#[allow(clippy::mutable_key_type)]
pub fn collect_vars<'c>(ast: &AstRef<'c>) -> Result<HashSet<AstRef<'c>>, ClarirsError> {
    let mut vars: HashSet<AstRef<'c>> = HashSet::new();
    let mut interesting: BTreeSet<InternedString> = ast.variables().clone();

    walk_dfs(ast, |node| {
        if interesting.is_empty() {
            // We have all the variables we need
            return DfsResult::Stop;
        }

        if !node.symbolic() {
            // Variables are always symbolic
            return DfsResult::SkipChildren;
        }

        let intersect: Vec<InternedString> = node
            .variables()
            .intersection(&interesting)
            .cloned()
            .collect();

        match intersect.len() {
            0 => DfsResult::SkipChildren,
            1 if node.depth() == 1 => {
                // We found a variable
                vars.insert(node.clone());
                interesting.remove(&intersect[0]);
                DfsResult::Continue
            }
            _ => DfsResult::Continue,
        }
    })?;

    Ok(vars)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::mutable_key_type)]
    fn test_collect_vars() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        let ast = ctx.add(
            &ctx.bvs("a", 64)?,
            &ctx.mul(&ctx.bvs("b", 64)?, &ctx.bvs("c", 64)?)?,
        )?;
        let var_ast = ast.clone();

        let vars = collect_vars(&var_ast)?;

        assert_eq!(vars.len(), 3);

        Ok(())
    }

    #[test]
    #[allow(clippy::mutable_key_type)]
    fn test_collect_vars_with_repeated_vars() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        let ast = ctx.add(
            &ctx.bvs("a", 64)?,
            &ctx.mul(&ctx.bvs("a", 64)?, &ctx.bvs("c", 64)?)?,
        )?;
        let var_ast = ast.clone();

        let vars = collect_vars(&var_ast)?;

        assert_eq!(vars.len(), 2);

        Ok(())
    }
}
