#![allow(clippy::mutable_key_type)]

use std::collections::HashMap;

use crate::prelude::*;

use super::collect_vars::collect_vars;

/// Checks if two ASTs are structurally matching by comparing their canonical forms.
///
/// Two ASTs are considered structurally matching if they have the same structure
/// and operations, even if their variable names are different.
///
/// # Example
/// ```
/// use clarirs_core::prelude::*;
/// use clarirs_core::algorithms::canonicalize::structurally_match;
///
/// let ctx = Context::new();
/// let ast1 = ctx.add(&ctx.bvs("x", 64)?, &ctx.bvs("y", 64)?)?;
/// let ast2 = ctx.add(&ctx.bvs("a", 64)?, &ctx.bvs("b", 64)?)?;
///
/// assert!(structurally_match(&ast1.clone(), &ast2.clone())?);
/// # Ok::<(), ClarirsError>(())
/// ```
pub fn structurally_match<'c>(ast1: &AstRef<'c>, ast2: &AstRef<'c>) -> Result<bool, ClarirsError> {
    let (_, _, canonical1) = canonicalize(ast1)?;
    let (_, _, canonical2) = canonicalize(ast2)?;
    Ok(canonical1 == canonical2)
}

/// Creates a canonical version of an AST by replacing variable names with
/// deterministic ones (v0, v1, v2, ...). This allows comparing two ASTs for
/// structural equality even if they have different variable names.
///
/// The function returns a tuple of the variable replacement map, the next
/// available canonical index, and the canonicalized AST. The replacement map is
/// keyed by each variable's hash and stores the canonical variable AST.
///
/// Variables are renamed in lexicographic order of their original names.
///
/// # Example
/// ```
/// use clarirs_core::prelude::*;
/// use clarirs_core::algorithms::canonicalize::canonicalize;
///
/// let ctx = Context::new();
/// let ast1 = ctx.add(&ctx.bvs("x", 64)?, &ctx.bvs("y", 64)?)?;
/// let ast2 = ctx.add(&ctx.bvs("a", 64)?, &ctx.bvs("b", 64)?)?;
///
/// let (_, _, canonical1) = canonicalize(&ast1.clone())?;
/// let (_, _, canonical2) = canonicalize(&ast2.clone())?;
///
/// // Both should be structurally identical after canonicalization
/// assert_eq!(canonical1, canonical2);
/// # Ok::<(), ClarirsError>(())
/// ```
pub fn canonicalize<'c>(
    ast: &AstRef<'c>,
) -> Result<(HashMap<u64, AstRef<'c>>, usize, AstRef<'c>), ClarirsError> {
    // Collect all variables in the AST
    let vars = collect_vars(ast)?;

    if vars.is_empty() {
        // No variables, return the original AST
        return Ok((HashMap::new(), 0, ast.clone()));
    }

    // Sort variable names to ensure deterministic ordering
    let mut var_names: Vec<InternedString> = vars
        .iter()
        .flat_map(|v| v.variables().iter().cloned())
        .collect();
    var_names.sort();
    var_names.dedup();

    // Create mapping from original names to canonical names
    let ctx_ref = ast.context();
    let var_mapping: HashMap<InternedString, InternedString> = var_names
        .iter()
        .enumerate()
        .map(|(i, name)| (name.clone(), ctx_ref.intern_string(format!("v{i}"))))
        .collect();

    // Build replacement map: original var AST -> canonical var AST
    let mut replacements: HashMap<AstRef<'c>, AstRef<'c>> = HashMap::new();
    let mut replacement_map: HashMap<u64, AstRef<'c>> = HashMap::new();
    let ctx = ast.context();

    for var in vars {
        let var_names_set = var.variables();
        // Each variable should have exactly one name since we collected leaf variables
        if let Some(original_name) = var_names_set.iter().next()
            && let Some(canonical_name) = var_mapping.get(original_name)
        {
            // Create the canonical variable with the same type and size as the original
            let canonical_var = match var.ast_type() {
                AstType::Bool => ctx.bools(canonical_name.as_str())?,
                AstType::BitVec(size) => ctx.bvs(canonical_name.as_str(), size)?,
                AstType::Float(sort) => ctx.fps(canonical_name.as_str(), sort)?,
                AstType::String => ctx.strings(canonical_name.as_str())?,
            };
            replacement_map.insert(var.hash(), canonical_var.clone());
            replacements.insert(var.clone(), canonical_var);
        }
    }

    // Apply all replacements to the AST
    let mut result = ast.clone();
    for (from, to) in &replacements {
        result = result.replace(from, to)?;
    }

    let counter = var_mapping.len();

    Ok((replacement_map, counter, result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_bitvec() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Create two structurally identical ASTs with different variable names
        let ast1 = ctx.add(&ctx.bvs("x", 64)?, &ctx.bvs("y", 64)?)?;
        let ast2 = ctx.add(&ctx.bvs("a", 64)?, &ctx.bvs("b", 64)?)?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();

        let (map1, counter1, canonical1) = canonicalize(&dyn_ast1)?;
        let (map2, counter2, canonical2) = canonicalize(&dyn_ast2)?;

        // Both should be structurally identical after canonicalization
        assert_eq!(canonical1, canonical2);
        assert_eq!(counter1, counter2);
        assert_eq!(map1.len(), counter1);
        assert_eq!(map2.len(), counter2);

        Ok(())
    }

    #[test]
    fn test_canonicalize_bool() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Create two structurally identical boolean ASTs with different variable names
        let ast1 = ctx.and2(&ctx.bools("p")?, &ctx.bools("q")?)?;
        let ast2 = ctx.and2(&ctx.bools("x")?, &ctx.bools("y")?)?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();

        let (map1, counter1, canonical1) = canonicalize(&dyn_ast1)?;
        let (map2, counter2, canonical2) = canonicalize(&dyn_ast2)?;

        assert_eq!(canonical1, canonical2);
        assert_eq!(counter1, counter2);
        assert_eq!(map1.len(), counter1);
        assert_eq!(map2.len(), counter2);

        Ok(())
    }

    #[test]
    fn test_canonicalize_complex() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Create more complex ASTs with the same structure
        // Both should have the same variable names in the same positions
        let x1 = ctx.bvs("a", 32)?;
        let y1 = ctx.bvs("b", 32)?;
        let z1 = ctx.bvs("c", 32)?;
        let ast1 = ctx.add(&ctx.mul(&x1, &y1)?, &z1)?;

        let x2 = ctx.bvs("x", 32)?;
        let y2 = ctx.bvs("y", 32)?;
        let z2 = ctx.bvs("z", 32)?;
        let ast2 = ctx.add(&ctx.mul(&x2, &y2)?, &z2)?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();

        let (_, counter1, canonical1) = canonicalize(&dyn_ast1)?;
        let (_, counter2, canonical2) = canonicalize(&dyn_ast2)?;

        // Both should canonicalize to: (v0 * v1) + v2
        assert_eq!(canonical1, canonical2);
        assert_eq!(counter1, counter2);

        Ok(())
    }

    #[test]
    fn test_canonicalize_no_vars() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Create AST with no variables
        let ast = ctx.add(
            &ctx.bvv(BitVec::from((5, 32)))?,
            &ctx.bvv(BitVec::from((10, 32)))?,
        )?;
        let dyn_ast = ast.clone();

        let (map, counter, canonical) = canonicalize(&dyn_ast)?;

        // Should be unchanged
        assert_eq!(dyn_ast, canonical);
        assert!(map.is_empty());
        assert_eq!(counter, 0);

        Ok(())
    }

    #[test]
    fn test_canonicalize_single_var() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        let ast = ctx.add(&ctx.bvs("x", 64)?, &ctx.bvv(BitVec::from((5, 64)))?)?;
        let dyn_ast = ast.clone();

        let (map, counter, canonical) = canonicalize(&dyn_ast)?;

        // Check that the variable was renamed to v0
        let canonical_expected = ctx.add(&ctx.bvs("v0", 64)?, &ctx.bvv(BitVec::from((5, 64)))?)?;
        let dyn_canonical_expected = canonical_expected.clone();

        assert_eq!(canonical, dyn_canonical_expected);
        assert_eq!(map.len(), 1);
        assert_eq!(counter, 1);

        Ok(())
    }

    #[test]
    fn test_canonicalize_order_independence() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Test that variables are renamed in lexicographic order
        // regardless of their order in the AST
        let ast1 = ctx.add(&ctx.bvs("z", 64)?, &ctx.bvs("a", 64)?)?;
        let ast2 = ctx.add(&ctx.bvs("a", 64)?, &ctx.bvs("z", 64)?)?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();

        let (_, counter1, canonical1) = canonicalize(&dyn_ast1)?;
        let (_, counter2, canonical2) = canonicalize(&dyn_ast2)?;

        // Both should canonicalize but may not be equal due to order
        // a -> v0, z -> v1
        let expected1 = ctx.add(&ctx.bvs("v1", 64)?, &ctx.bvs("v0", 64)?)?;
        let dyn_expected1 = expected1.clone();

        let expected2 = ctx.add(&ctx.bvs("v0", 64)?, &ctx.bvs("v1", 64)?)?;
        let dyn_expected2 = expected2.clone();

        assert_eq!(canonical1, dyn_expected1);
        assert_eq!(canonical2, dyn_expected2);
        assert_eq!(counter1, 2);
        assert_eq!(counter2, 2);

        Ok(())
    }

    // Tests for structurally_match function

    #[test]
    fn test_structurally_match_basic() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Create two structurally identical ASTs with different variable names
        let ast1 = ctx.add(&ctx.bvs("x", 64)?, &ctx.bvs("y", 64)?)?;
        let ast2 = ctx.add(&ctx.bvs("a", 64)?, &ctx.bvs("b", 64)?)?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();

        assert!(structurally_match(&dyn_ast1, &dyn_ast2)?);

        Ok(())
    }

    #[test]
    fn test_structurally_match_different_ops() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Create two ASTs with different operations
        let ast1 = ctx.add(&ctx.bvs("x", 64)?, &ctx.bvs("y", 64)?)?;
        let ast2 = ctx.mul(&ctx.bvs("a", 64)?, &ctx.bvs("b", 64)?)?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();

        assert!(!structurally_match(&dyn_ast1, &dyn_ast2)?);

        Ok(())
    }

    #[test]
    fn test_structurally_match_different_sizes() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Create two ASTs with different bitvector sizes
        let ast1 = ctx.add(&ctx.bvs("x", 64)?, &ctx.bvs("y", 64)?)?;
        let ast2 = ctx.add(&ctx.bvs("a", 32)?, &ctx.bvs("b", 32)?)?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();

        assert!(!structurally_match(&dyn_ast1, &dyn_ast2)?);

        Ok(())
    }

    #[test]
    fn test_structurally_match_complex() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Create complex nested ASTs with different variable names
        let x1 = ctx.bvs("p", 32)?;
        let y1 = ctx.bvs("q", 32)?;
        let z1 = ctx.bvs("r", 32)?;
        let ast1 = ctx.mul(&ctx.add(&x1, &y1)?, &z1)?;

        let x2 = ctx.bvs("alpha", 32)?;
        let y2 = ctx.bvs("beta", 32)?;
        let z2 = ctx.bvs("gamma", 32)?;
        let ast2 = ctx.mul(&ctx.add(&x2, &y2)?, &z2)?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();

        assert!(structurally_match(&dyn_ast1, &dyn_ast2)?);

        Ok(())
    }

    #[test]
    fn test_structurally_match_boolean() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Create two structurally identical boolean ASTs with different variable names
        let ast1 = ctx.or2(
            &ctx.and2(&ctx.bools("a")?, &ctx.bools("b")?)?,
            &ctx.bools("c")?,
        )?;
        let ast2 = ctx.or2(
            &ctx.and2(&ctx.bools("x")?, &ctx.bools("y")?)?,
            &ctx.bools("z")?,
        )?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();

        assert!(structurally_match(&dyn_ast1, &dyn_ast2)?);

        Ok(())
    }

    #[test]
    fn test_structurally_match_same_ast() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Same AST should match with itself
        let ast = ctx.add(&ctx.bvs("x", 64)?, &ctx.bvs("y", 64)?)?;
        let dyn_ast = ast.clone();

        assert!(structurally_match(&dyn_ast, &dyn_ast)?);

        Ok(())
    }

    #[test]
    fn test_structurally_match_constants() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // ASTs with constants and variables
        let ast1 = ctx.add(&ctx.bvs("x", 64)?, &ctx.bvv(BitVec::from((5, 64)))?)?;
        let ast2 = ctx.add(&ctx.bvs("y", 64)?, &ctx.bvv(BitVec::from((5, 64)))?)?;
        let ast3 = ctx.add(&ctx.bvs("z", 64)?, &ctx.bvv(BitVec::from((10, 64)))?)?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();
        let dyn_ast3 = ast3.clone();

        // Same constant values should match
        assert!(structurally_match(&dyn_ast1, &dyn_ast2)?);
        // Different constant values should not match
        assert!(!structurally_match(&dyn_ast1, &dyn_ast3)?);

        Ok(())
    }

    #[test]
    fn test_canonicalize_cross_type() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // Create Bool ASTs that contain BitVec variables (cross-type)
        // e.g. (x + y) == 5 where x,y are BVS and the result is Bool
        let ast1 = ctx.eq_(
            &ctx.add(&ctx.bvs("x", 32)?, &ctx.bvs("y", 32)?)?,
            &ctx.bvv(BitVec::from((5, 32)))?,
        )?;
        let ast2 = ctx.eq_(
            &ctx.add(&ctx.bvs("a", 32)?, &ctx.bvs("b", 32)?)?,
            &ctx.bvv(BitVec::from((5, 32)))?,
        )?;

        let dyn_ast1 = ast1.clone();
        let dyn_ast2 = ast2.clone();

        let (_, counter1, canonical1) = canonicalize(&dyn_ast1)?;
        let (_, counter2, canonical2) = canonicalize(&dyn_ast2)?;

        // Both should canonicalize to: (v0 + v1) == 5
        assert_eq!(canonical1, canonical2);
        assert_eq!(counter1, 2);
        assert_eq!(counter2, 2);

        // Also verify structurally_match works for cross-type
        assert!(structurally_match(&dyn_ast1, &dyn_ast2)?);

        Ok(())
    }
}
