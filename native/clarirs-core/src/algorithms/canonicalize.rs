#![allow(clippy::mutable_key_type)]

use std::cmp::Ordering;
use std::collections::HashMap;

use crate::prelude::*;

use super::collect_vars::collect_vars;
use super::replace::Replacements;
use super::walk::walk;
use crate::cache::GenericCache;

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

/// Orders variable names as text, except that runs of digits compare as
/// numbers, so that names which differ only in a counter, such as `x_76_32`
/// and `x_100_32`, keep the order they were created in.
pub fn compare_names(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while let (Some(&x), Some(&y)) = (a.first(), b.first()) {
        if x.is_ascii_digit() && y.is_ascii_digit() {
            let a_len = a.iter().take_while(|c| c.is_ascii_digit()).count();
            let b_len = b.iter().take_while(|c| c.is_ascii_digit()).count();
            let (a_num, b_num) = (&a[..a_len], &b[..b_len]);
            let a_trim = &a_num[a_num.iter().take_while(|&&c| c == b'0').count()..];
            let b_trim = &b_num[b_num.iter().take_while(|&&c| c == b'0').count()..];
            let order = a_trim
                .len()
                .cmp(&b_trim.len())
                .then_with(|| a_trim.cmp(b_trim))
                .then_with(|| a_len.cmp(&b_len));
            if order != Ordering::Equal {
                return order;
            }
            (a, b) = (&a[a_len..], &b[b_len..]);
        } else if x != y {
            return x.cmp(&y);
        } else {
            (a, b) = (&a[1..], &b[1..]);
        }
    }
    a.len().cmp(&b.len())
}

/// Creates a canonical version of an AST by replacing variable names with
/// deterministic ones (v0, v1, v2, ...). This allows comparing two ASTs for
/// structural equality even if they have different variable names.
///
/// The function returns a tuple of the variable replacement map, the next
/// available canonical index, and the canonicalized AST. The replacement map is
/// keyed by each variable and stores the canonical variable AST.
///
/// Variables are renamed in the order of their original names, as
/// [`compare_names`] orders them.
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
) -> Result<(HashMap<AstRef<'c>, AstRef<'c>>, usize, AstRef<'c>), ClarirsError> {
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
    var_names.sort_by(|a, b| compare_names(a.as_str(), b.as_str()));
    var_names.dedup();

    // Create mapping from original names to canonical names
    let ctx_ref = ast.context();
    let var_mapping: HashMap<InternedString, InternedString> = var_names
        .iter()
        .enumerate()
        .map(|(i, name)| (name.clone(), ctx_ref.intern_string(format!("v{i}"))))
        .collect();

    // Build replacement map: original var -> canonical var AST
    let mut replacement_map: HashMap<AstRef<'c>, AstRef<'c>> = HashMap::new();
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
            replacement_map.insert(var.clone(), canonical_var);
        }
    }

    let replacements: Replacements<'c> = replacement_map
        .iter()
        .map(|(var, canonical)| (var.clone(), canonical.clone()))
        .collect();
    let result = ast.replace_many(&replacements)?;
    let result = order_commutative_operands(&result)?;

    let counter = var_mapping.len();

    Ok((replacement_map, counter, result))
}

/// `true` when `op` is associative and commutative, so that the order of its
/// operands carries no meaning. This is the same set of ops that
/// [`crate::algorithms::replace::Replacements`] recognizes for commutative
/// pattern matching.
fn is_associative_commutative(op: &AstOp<'_>) -> bool {
    matches!(
        op,
        AstOp::And(_)
            | AstOp::Or(_)
            | AstOp::Xor(_)
            | AstOp::Add(_)
            | AstOp::Mul(_)
            | AstOp::Union(_)
            | AstOp::Intersection(_)
    )
}

/// Deterministic order key for the operands of an associative-commutative op:
/// the cached structural hash first, then the structural form on a hash
/// collision, so the resulting order never depends on the operand order the
/// AST happened to be built with.
fn compare_operands(a: &AstRef<'_>, b: &AstRef<'_>) -> Ordering {
    a.hash()
        .cmp(&b.hash())
        .then_with(|| format!("{:?}", a.op()).cmp(&format!("{:?}", b.op())))
}

/// Rebuilds `ast` with the operands of every associative-commutative op
/// (`And`, `Or`, `Xor`, `Add`, `Mul`, `Union`, `Intersection`) in a
/// deterministic order, so that two ASTs differing only in the operand order
/// of those ops produce the same canonical form. Operand order carries no
/// meaning for these ops, so the rebuilt AST is semantically identical to
/// its input.
pub fn order_commutative_operands<'c>(ast: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
    walk(
        ast.clone(),
        |_| Ok(None),
        |node: AstRef<'c>, children: &[AstRef<'c>]| {
            let ctx = node.context();
            let mut children = children.to_vec();
            if is_associative_commutative(node.op()) {
                children.sort_by(compare_operands);
            }
            ctx.make_ast_annotated(
                node.op().with_children(&children),
                node.annotations().clone(),
            )
        },
        &GenericCache::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_names() {
        assert_eq!(compare_names("x_76_32", "x_100_32"), Ordering::Less);
        assert_eq!(compare_names("x_100_32", "x_76_32"), Ordering::Greater);
        assert_eq!(compare_names("a", "z"), Ordering::Less);
        assert_eq!(compare_names("x_7", "x_07"), Ordering::Less);
        assert_eq!(compare_names("x_1", "x_1"), Ordering::Equal);
        assert_eq!(compare_names("x", "x_1"), Ordering::Less);
    }

    #[test]
    fn test_canonicalize_counter_order() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // the same structure, with counters that sort in the opposite order
        // as text in one of the two
        let ast1 = ctx.sub(&ctx.bvs("x_76", 32)?, &ctx.bvs("x_100", 32)?)?;
        let ast2 = ctx.sub(&ctx.bvs("y_74", 32)?, &ctx.bvs("y_93", 32)?)?;

        let (_, _, canonical1) = canonicalize(&ast1)?;
        let (_, _, canonical2) = canonicalize(&ast2)?;

        assert_eq!(canonical1, canonical2);

        Ok(())
    }

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

        // Check that the variable was renamed to v0. The operands of the
        // commutative `Add` come out in canonical (structural hash) order,
        // which places the constant first here.
        let canonical_expected = ctx.add(&ctx.bvv(BitVec::from((5, 64)))?, &ctx.bvs("v0", 64)?)?;
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

        // a -> v0, z -> v1 in both cases. The commutative `Add` operands
        // come out in canonical (structural hash) order, so both inputs now
        // produce the identical canonical form.
        let expected = ctx.add(&ctx.bvs("v1", 64)?, &ctx.bvs("v0", 64)?)?;

        assert_eq!(canonical1, expected);
        assert_eq!(canonical2, expected);
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

    /// angr/angr#5796: the same expression built with the operands of a
    /// commutative op in a different order must canonicalize identically,
    /// otherwise the unicorn congruency check flakes on equivalent states.
    #[test]
    fn test_canonicalize_commutative_operand_order_issue_5796() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // (filesize <=s 0) || (filesize[31:4] == 0), as built on the native side
        let x1 = ctx.bvs("filesize_file_1_???_174_32", 32)?;
        let zero32 = ctx.bvv(BitVec::from((0, 32)))?;
        let zero28 = ctx.bvv(BitVec::from((0, 28)))?;
        let a1 = ctx.sle(&x1, &zero32)?;
        let b1 = ctx.eq_(&ctx.extract(&x1, 31, 4)?, &zero28)?;
        let ast1 = ctx.or2(&a1, &b1)?;

        // the unicorn side produces the same expression with `or` operands swapped
        let x2 = ctx.bvs("filesize_file_2_???_177_32", 32)?;
        let a2 = ctx.sle(&x2, &zero32)?;
        let b2 = ctx.eq_(&ctx.extract(&x2, 31, 4)?, &zero28)?;
        let ast2 = ctx.or2(&b2, &a2)?;

        let (map1, counter1, canonical1) = canonicalize(&ast1)?;
        let (map2, counter2, canonical2) = canonicalize(&ast2)?;

        assert_eq!(canonical1, canonical2);
        assert_eq!(counter1, counter2);
        assert_eq!(map1.len(), map2.len());
        assert!(structurally_match(&ast1, &ast2)?);

        Ok(())
    }

    /// Operand-order independence must hold for every n-ary commutative op,
    /// including when the swapped subtrees carry differently named variables,
    /// so renaming order and operand order cannot interact.
    #[test]
    fn test_canonicalize_commutative_ops_order_independent() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        let x = ctx.bvs("alpha_1", 32)?;
        let y = ctx.bvs("zeta_2", 32)?;
        let five = ctx.bvv(BitVec::from((5, 32)))?;
        let left: Vec<AstRef> = vec![
            ctx.add(&x, &y)?,
            ctx.mul(&x, &y)?,
            ctx.and2(&x, &y)?,
            ctx.or2(&x, &y)?,
            ctx.xor2(&x, &y)?,
            ctx.add_many([x.clone(), y.clone(), five.clone()])?,
        ];

        // same expressions, operands reversed, different variable names
        let a = ctx.bvs("beta_1", 32)?;
        let b = ctx.bvs("omega_2", 32)?;
        let right: Vec<AstRef> = vec![
            ctx.add(&b, &a)?,
            ctx.mul(&b, &a)?,
            ctx.and2(&b, &a)?,
            ctx.or2(&b, &a)?,
            ctx.xor2(&b, &a)?,
            ctx.add_many([five.clone(), b.clone(), a.clone()])?,
        ];

        for (l, r) in left.iter().zip(right.iter()) {
            assert!(
                structurally_match(l, r)?,
                "canonical forms differ: {l:?} vs {r:?}"
            );
        }

        Ok(())
    }
}
