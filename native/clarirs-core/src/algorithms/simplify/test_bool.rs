use anyhow::Result;
use clarirs_num::BitVec;

use crate::{
    ast::{
        AstFactory,
        annotation::{Annotation, AnnotationType},
    },
    context::Context,
};

#[test]
fn test_prim() -> Result<()> {
    let ctx = Context::default();
    let true_ast = ctx.true_()?;
    let false_ast = ctx.false_()?;
    let sym_ast = ctx.bools("test")?;

    assert_eq!(true_ast.simplify()?, true_ast);
    assert_eq!(false_ast.simplify()?, false_ast);
    assert_eq!(sym_ast.simplify()?, sym_ast);

    Ok(())
}

#[test]
fn test_xor_double_negation() -> Result<()> {
    let ctx = Context::new();

    let x = ctx.bools("x")?;
    let y = ctx.bools("y")?;
    let not_x = ctx.not(&x)?;
    let not_y = ctx.not(&y)?;

    // Test: ¬x ⊕ ¬y = x ⊕ y
    let xor_not_not = ctx.xor2(&not_x, &not_y)?.simplify()?;
    let xor_plain = ctx.xor2(&x, &y)?.simplify()?;
    assert_eq!(xor_not_not, xor_plain);

    // Verify with concrete values
    let true_ast = ctx.true_()?;
    let false_ast = ctx.false_()?;

    // ¬T ⊕ ¬T = F ⊕ F = F, and T ⊕ T = F
    let not_true = ctx.not(&true_ast)?;
    let result = ctx.xor2(&not_true, &not_true)?.simplify()?;
    assert_eq!(result, false_ast);

    // ¬T ⊕ ¬F = F ⊕ T = T, and T ⊕ F = T
    let not_false = ctx.not(&false_ast)?;
    let result2 = ctx.xor2(&not_true, &not_false)?.simplify()?;
    assert_eq!(result2, true_ast);

    // ¬F ⊕ ¬T = T ⊕ F = T, and F ⊕ T = T
    let result3 = ctx.xor2(&not_false, &not_true)?.simplify()?;
    assert_eq!(result3, true_ast);

    // ¬F ⊕ ¬F = T ⊕ T = F, and F ⊕ F = F
    let result4 = ctx.xor2(&not_false, &not_false)?.simplify()?;
    assert_eq!(result4, false_ast);

    Ok(())
}

#[test]
fn test_not() -> Result<()> {
    let ctx = Context::new();

    let true_ast = ctx.true_()?;
    let false_ast = ctx.false_()?;
    let sym_ast = ctx.bools("test")?;

    let table = vec![
        (&true_ast, &true_ast, &true_ast),
        (&true_ast, &false_ast, &false_ast),
        (&true_ast, &sym_ast, &sym_ast),
        (&false_ast, &true_ast, &false_ast),
        (&false_ast, &false_ast, &false_ast),
        (&false_ast, &sym_ast, &false_ast),
        (&sym_ast, &true_ast, &sym_ast),
        (&sym_ast, &false_ast, &false_ast),
        (&sym_ast, &sym_ast, &sym_ast),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.and2(lhs, rhs)?.simplify()?,
            expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_or() -> Result<()> {
    let ctx = Context::new();

    let true_ast = ctx.true_()?;
    let false_ast = ctx.false_()?;
    let sym_ast = ctx.bools("test")?;

    let table = vec![
        (&true_ast, &true_ast, &true_ast),
        (&true_ast, &false_ast, &true_ast),
        (&true_ast, &sym_ast, &true_ast),
        (&false_ast, &true_ast, &true_ast),
        (&false_ast, &false_ast, &false_ast),
        (&false_ast, &sym_ast, &sym_ast),
        (&sym_ast, &true_ast, &true_ast),
        (&sym_ast, &false_ast, &sym_ast),
        (&sym_ast, &sym_ast, &sym_ast),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.or2(lhs, rhs)?.simplify()?,
            expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_xor() -> Result<()> {
    let ctx = Context::new();

    let true_ast = ctx.true_()?;
    let false_ast = ctx.false_()?;
    let sym_ast = ctx.bools("test")?;
    let not_sym_ast = ctx.not(&sym_ast)?;

    let table = vec![
        (&true_ast, &true_ast, &false_ast),
        (&true_ast, &false_ast, &true_ast),
        (&true_ast, &sym_ast, &not_sym_ast),
        (&false_ast, &true_ast, &true_ast),
        (&false_ast, &false_ast, &false_ast),
        (&false_ast, &sym_ast, &sym_ast),
        (&sym_ast, &true_ast, &not_sym_ast),
        (&sym_ast, &false_ast, &sym_ast),
        (&sym_ast, &sym_ast, &false_ast),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.xor2(lhs, rhs)?.simplify()?,
            expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_if() -> Result<()> {
    let ctx = Context::new();

    let true_ast = ctx.true_()?;
    let false_ast = ctx.false_()?;
    let sym_ast = ctx.bools("test")?;
    let not_sym_ast = ctx.not(&sym_ast)?;

    let table = vec![
        (&true_ast, &true_ast, &true_ast, &true_ast),
        (&true_ast, &true_ast, &false_ast, &true_ast),
        (&true_ast, &true_ast, &sym_ast, &true_ast),
        (&true_ast, &false_ast, &true_ast, &false_ast),
        (&true_ast, &false_ast, &false_ast, &false_ast),
        (&true_ast, &false_ast, &sym_ast, &false_ast),
        (&true_ast, &sym_ast, &true_ast, &sym_ast),
        (&true_ast, &sym_ast, &false_ast, &sym_ast),
        (&true_ast, &sym_ast, &sym_ast, &sym_ast),
        (&false_ast, &true_ast, &true_ast, &true_ast),
        (&false_ast, &true_ast, &false_ast, &false_ast),
        (&false_ast, &true_ast, &sym_ast, &sym_ast),
        (&false_ast, &false_ast, &true_ast, &true_ast),
        (&false_ast, &false_ast, &false_ast, &false_ast),
        (&false_ast, &false_ast, &sym_ast, &sym_ast),
        (&false_ast, &sym_ast, &true_ast, &true_ast),
        (&false_ast, &sym_ast, &false_ast, &false_ast),
        (&false_ast, &sym_ast, &sym_ast, &sym_ast),
        (&sym_ast, &true_ast, &true_ast, &true_ast),
        (&sym_ast, &true_ast, &false_ast, &sym_ast),
        (&sym_ast, &true_ast, &sym_ast, &sym_ast),
        (&sym_ast, &false_ast, &true_ast, &not_sym_ast),
        (&sym_ast, &false_ast, &false_ast, &false_ast),
        (&sym_ast, &false_ast, &sym_ast, &false_ast),
        (&sym_ast, &sym_ast, &true_ast, &true_ast),
        (&sym_ast, &sym_ast, &false_ast, &sym_ast),
        (&sym_ast, &sym_ast, &sym_ast, &sym_ast),
    ];

    for (cond, then_, else_, expected) in table {
        assert_eq!(
            &ctx.ite(cond, then_, else_)?.simplify()?,
            expected,
            "cond: {cond:?}, then_branch: {then_:?}, else_branch: {else_:?}"
        );
    }

    Ok(())
}

#[test]
fn test_eq() -> Result<()> {
    let ctx = Context::new();

    let true_ast = ctx.true_()?;
    let false_ast = ctx.false_()?;
    let sym_ast = ctx.bools("test")?;
    let not_sym_ast = ctx.not(&sym_ast)?;

    let table = vec![
        (&true_ast, &true_ast, &true_ast),
        (&true_ast, &false_ast, &false_ast),
        (&true_ast, &sym_ast, &sym_ast),
        (&false_ast, &true_ast, &false_ast),
        (&false_ast, &false_ast, &true_ast),
        (&false_ast, &sym_ast, &not_sym_ast),
        (&sym_ast, &true_ast, &sym_ast),
        (&sym_ast, &false_ast, &not_sym_ast),
        // Note: sym == sym does NOT simplify to true (NaN consideration)
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.eq_(lhs, rhs)?.simplify()?,
            expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_neq() -> Result<()> {
    let ctx = Context::new();

    let true_ast = ctx.true_()?;
    let false_ast = ctx.false_()?;
    let sym_ast = ctx.bools("test")?;
    let not_sym_ast = ctx.not(&sym_ast)?;

    let table = vec![
        (&true_ast, &true_ast, &false_ast),
        (&true_ast, &false_ast, &true_ast),
        (&true_ast, &sym_ast, &not_sym_ast),
        (&false_ast, &true_ast, &true_ast),
        (&false_ast, &false_ast, &false_ast),
        (&false_ast, &sym_ast, &sym_ast),
        (&sym_ast, &true_ast, &not_sym_ast),
        (&sym_ast, &false_ast, &sym_ast),
        // Note: sym != sym does NOT simplify to false (NaN consideration)
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.neq(lhs, rhs)?.simplify()?,
            expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_ult() -> Result<()> {
    let ctx = Context::new();

    let table = vec![
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.false_()?,
        ),
        (ctx.bvs("a", 8)?, ctx.bvs("a", 8)?, ctx.false_()?),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.ult(&lhs, &rhs)?.simplify()?,
            &expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_ule() -> Result<()> {
    let ctx = Context::new();

    let table = vec![
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.true_()?,
        ),
        (ctx.bvs("a", 8)?, ctx.bvs("a", 8)?, ctx.true_()?),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.ule(&lhs, &rhs)?.simplify()?,
            &expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_ugt() -> Result<()> {
    let ctx = Context::new();

    let table = vec![
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.false_()?,
        ),
        (ctx.bvs("a", 8)?, ctx.bvs("a", 8)?, ctx.false_()?),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.ugt(&lhs, &rhs)?.simplify()?,
            &expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_uge() -> Result<()> {
    let ctx = Context::new();

    let table = vec![
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.true_()?,
        ),
        (ctx.bvs("a", 8)?, ctx.bvs("a", 8)?, ctx.true_()?),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.uge(&lhs, &rhs)?.simplify()?,
            &expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_slt() -> Result<()> {
    let ctx = Context::new();

    let table = vec![
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((255, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((255, 8)))?,
            ctx.false_()?,
        ),
        (ctx.bvs("a", 8)?, ctx.bvs("a", 8)?, ctx.false_()?),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.slt(&lhs, &rhs)?.simplify()?,
            &expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_sle() -> Result<()> {
    let ctx = Context::new();

    let table = vec![
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((255, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((255, 8)))?,
            ctx.false_()?,
        ),
        (ctx.bvs("a", 8)?, ctx.bvs("a", 8)?, ctx.true_()?),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.sle(&lhs, &rhs)?.simplify()?,
            &expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_sgt() -> Result<()> {
    let ctx = Context::new();

    let table = vec![
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((255, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((255, 8)))?,
            ctx.true_()?,
        ),
        (ctx.bvs("a", 8)?, ctx.bvs("a", 8)?, ctx.false_()?),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.sgt(&lhs, &rhs)?.simplify()?,
            &expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_sge() -> Result<()> {
    let ctx = Context::new();

    let table = vec![
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((2, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.true_()?,
        ),
        (
            ctx.bvv(BitVec::from((255, 8)))?,
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.false_()?,
        ),
        (
            ctx.bvv(BitVec::from((1, 8)))?,
            ctx.bvv(BitVec::from((255, 8)))?,
            ctx.true_()?,
        ),
        (ctx.bvs("a", 8)?, ctx.bvs("a", 8)?, ctx.true_()?),
    ];

    for (lhs, rhs, expected) in table {
        assert_eq!(
            &ctx.sge(&lhs, &rhs)?.simplify()?,
            &expected,
            "lhs: {lhs:?}, rhs: {rhs:?}"
        );
    }

    Ok(())
}

#[test]
fn test_boolean_identity_simplifications() -> Result<()> {
    let ctx = Context::new();

    let x = ctx.bools("x")?;
    let not_x = ctx.not(&x)?.simplify()?;

    // x && !x == false
    let simplified = ctx.and2(&x, &not_x)?.simplify()?;
    assert_eq!(simplified, ctx.false_()?);

    let simplified = ctx.and2(&not_x, &x)?.simplify()?;
    assert_eq!(simplified, ctx.false_()?);

    // x || !x == true
    let simplified = ctx.or2(&x, &not_x)?.simplify()?;
    assert_eq!(simplified, ctx.true_()?);

    let simplified = ctx.or2(&not_x, &x)?.simplify()?;
    assert_eq!(simplified, ctx.true_()?);

    // x ^ !x == true
    let simplified = ctx.xor2(&x, &not_x)?.simplify()?;
    assert_eq!(simplified, ctx.true_()?);

    let simplified = ctx.xor2(&not_x, &x)?.simplify()?;
    assert_eq!(simplified, ctx.true_()?);

    Ok(())
}

#[test]
fn test_booleq_identity_simplification_without_floats() -> Result<()> {
    // BoolEq(x, x) should simplify to true
    let ctx = Context::default();
    let a = ctx.bvs("a", 64)?;
    let b = ctx.bvs("b", 64)?;

    let neq = ctx.neq(&a, &b)?;
    let eq_check = ctx.eq_(&neq, &neq)?;
    let simplified = eq_check.simplify()?;

    assert!(
        matches!(simplified.op(), crate::ast::AstOp::BoolV(true)),
        "BoolEq(x, x) should simplify to true when no floats are involved, got: {:?}",
        simplified.op()
    );
    Ok(())
}

#[test]
fn test_booleq_identity_simplification_with_floats() -> Result<()> {
    // BoolEq(x, x) SHOULD simplify to true even when x involves floats.
    // NaN != NaN applies to fp== itself, but bool== of two identical boolean
    // expressions is always true: whatever value (fp== A B) takes, both sides
    // are the same expression and thus equal.
    let ctx = Context::default();
    let a = ctx.fps("a", clarirs_num::FSort::f64())?;
    let b = ctx.fps("b", clarirs_num::FSort::f64())?;

    let fp_eq = ctx.fp_eq(&a, &b)?;
    let eq_check = ctx.eq_(&fp_eq, &fp_eq)?;
    let simplified = eq_check.simplify()?;

    assert!(
        matches!(simplified.op(), crate::ast::AstOp::BoolV(true)),
        "BoolEq(x, x) should simplify to true even when floats are involved, got: {:?}",
        simplified.op()
    );
    Ok(())
}

#[test]
fn test_relocatable_annotations_preserved_through_simplification() -> Result<()> {
    let ctx = Context::new();

    let annotation = Annotation::new(AnnotationType::Uninitialized, true, true);

    // Create an expression that will be simplified: true && x => x
    let x = ctx.bools("x")?;
    let true_ast = ctx.true_()?;

    // Annotate x with a relocatable+eliminatable annotation
    let annotated_x = ctx.annotate(&x, vec![annotation.clone()])?;
    let expr = ctx.and2(&true_ast, &annotated_x)?;

    let simplified = expr.simplify()?;

    // The annotation should be preserved on the simplified result
    assert!(
        simplified.annotations().contains(&annotation),
        "Relocatable annotation should be preserved through simplification, got annotations: {:?}",
        simplified.annotations()
    );

    Ok(())
}

#[test]
fn test_non_eliminatable_non_relocatable_blocks_simplification() -> Result<()> {
    let ctx = Context::new();

    // SimplificationAvoidance is !eliminatable && !relocatable
    let annotation = Annotation::new(AnnotationType::SimplificationAvoidance, false, false);

    // Create an expression that would normally simplify: true && x => x
    let x = ctx.bools("x")?;
    let true_ast = ctx.true_()?;
    let expr = ctx.and2(&true_ast, &x)?;

    // Annotate the expression with a blocking annotation
    let annotated = ctx.annotate(&expr, vec![annotation])?;

    // Simplification should be blocked — the expression should remain unchanged
    let simplified = annotated.simplify()?;
    assert_eq!(
        simplified, annotated,
        "Non-eliminatable, non-relocatable annotation should block simplification"
    );

    Ok(())
}

#[test]
fn test_eliminatable_non_relocatable_does_not_block_simplification() -> Result<()> {
    let ctx = Context::new();

    // An eliminatable, non-relocatable annotation should NOT block simplification
    let annotation = Annotation::new(AnnotationType::Uninitialized, true, false);

    // Create an expression that would normally simplify: true && x => x
    let x = ctx.bools("x")?;
    let true_ast = ctx.true_()?;
    let expr = ctx.and2(&true_ast, &x)?;

    // Annotate the expression
    let annotated = ctx.annotate(&expr, vec![annotation])?;

    // Simplification should proceed since the annotation is eliminatable
    let simplified = annotated.simplify()?;

    // The result should be simplified (x, not the original and-expression)
    // The non-relocatable annotation is dropped since it can't move to the new expression
    assert_eq!(
        simplified.annotations().len(),
        0,
        "Non-relocatable annotation should be dropped after simplification"
    );

    Ok(())
}
