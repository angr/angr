use std::collections::{BTreeSet, HashSet};

use crate::prelude::*;

use super::walk::walk;

#[allow(clippy::mutable_key_type)]
pub fn collect_vars<'c>(ast: &AstRef<'c>) -> Result<HashSet<AstRef<'c>>, ClarirsError> {
    let mut vars: HashSet<AstRef<'c>> = HashSet::new();
    let mut interesting: BTreeSet<InternedString> = ast.variables().clone();

    walk(
        ast.clone(),
        |node| {
            if interesting.is_empty() {
                // We have all the variables we need
                return Ok(Some(()));
            }

            if !node.symbolic() {
                // Variables are always symbolic
                return Ok(Some(()));
            }

            let intersect: Vec<InternedString> = node
                .variables()
                .intersection(&interesting)
                .cloned()
                .collect();

            match intersect.len() {
                0 => Ok(Some(())),
                1 if node.depth() == 1 => {
                    // We found a variable
                    vars.insert(node.clone());
                    interesting.remove(&intersect[0]);
                    Ok(None)
                }
                _ => Ok(None),
            }
        },
        |_, _| Ok(()),
        &(),
    )?;

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
