use crate::prelude::*;

#[test]
fn test_bitvec_not_with_ite() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bvs("a", 32).unwrap();
    let b = ctx.bvs("b", 32).unwrap();
    let c = ctx.bools("c").unwrap();

    // Create expression: not(if c then a else b)
    let ite = ctx.ite(&c, &a, &b).unwrap();
    let expr = ctx.not(&ite).unwrap();

    // Expected result: if c then not(a) else not(b)
    let not_a = ctx.not(&a).unwrap();
    let not_b = ctx.not(&b).unwrap();
    let expected = ctx.ite(&c, &not_a, &not_b).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}

#[test]
fn test_bitvec_neg_with_ite() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bvs("a", 32).unwrap();
    let b = ctx.bvs("b", 32).unwrap();
    let c = ctx.bools("c").unwrap();

    // Create expression: neg(if c then a else b)
    let ite = ctx.ite(&c, &a, &b).unwrap();
    let expr = ctx.neg(&ite).unwrap();

    // Expected result: if c then neg(a) else neg(b)
    let neg_a = ctx.neg(&a).unwrap();
    let neg_b = ctx.neg(&b).unwrap();
    let expected = ctx.ite(&c, &neg_a, &neg_b).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}

#[test]
fn test_bitvec_add_with_ite() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bvs("a", 32).unwrap();
    let b = ctx.bvs("b", 32).unwrap();
    let c = ctx.bools("c").unwrap();
    let d = ctx.bvs("d", 32).unwrap();

    // Create expression: d + (if c then a else b)
    let ite = ctx.ite(&c, &a, &b).unwrap();
    let expr = ctx.add(&d, &ite).unwrap();

    // Expected result: if c then (d + a) else (d + b)
    let d_add_a = ctx.add(&d, &a).unwrap();
    let d_add_b = ctx.add(&d, &b).unwrap();
    let expected = ctx.ite(&c, &d_add_a, &d_add_b).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}

#[test]
fn test_bitvec_sub_with_ite() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bvs("a", 32).unwrap();
    let b = ctx.bvs("b", 32).unwrap();
    let c = ctx.bools("c").unwrap();
    let d = ctx.bvs("d", 32).unwrap();

    // Create expression: d - (if c then a else b)
    let ite = ctx.ite(&c, &a, &b).unwrap();
    let expr = ctx.sub(&d, &ite).unwrap();

    // Expected result: if c then (d - a) else (d - b)
    let d_sub_a = ctx.sub(&d, &a).unwrap();
    let d_sub_b = ctx.sub(&d, &b).unwrap();
    let expected = ctx.ite(&c, &d_sub_a, &d_sub_b).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}

#[test]
fn test_bitvec_mul_with_ite() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bvs("a", 32).unwrap();
    let b = ctx.bvs("b", 32).unwrap();
    let c = ctx.bools("c").unwrap();
    let d = ctx.bvs("d", 32).unwrap();

    // Create expression: d * (if c then a else b)
    let ite = ctx.ite(&c, &a, &b).unwrap();
    let expr = ctx.mul(&d, &ite).unwrap();

    // Expected result: if c then (d * a) else (d * b)
    let d_mul_a = ctx.mul(&d, &a).unwrap();
    let d_mul_b = ctx.mul(&d, &b).unwrap();
    let expected = ctx.ite(&c, &d_mul_a, &d_mul_b).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}
