use crate::prelude::*;

#[test]
fn test_bool_not_with_ite() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bools("a").unwrap();
    let b = ctx.bools("b").unwrap();
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
fn test_bool_and_with_ite() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bools("a").unwrap();
    let b = ctx.bools("b").unwrap();
    let c = ctx.bools("c").unwrap();
    let d = ctx.bools("d").unwrap();

    // Create expression: d && (if c then a else b)
    let ite = ctx.ite(&c, &a, &b).unwrap();
    let expr = ctx.and2(&d, &ite).unwrap();

    // Expected result: if c then (d && a) else (d && b)
    let d_and_a = ctx.and2(&d, &a).unwrap();
    let d_and_b = ctx.and2(&d, &b).unwrap();
    let expected = ctx.ite(&c, &d_and_a, &d_and_b).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}

#[test]
fn test_bool_or_with_ite() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bools("a").unwrap();
    let b = ctx.bools("b").unwrap();
    let c = ctx.bools("c").unwrap();
    let d = ctx.bools("d").unwrap();

    // Create expression: d || (if c then a else b)
    let ite = ctx.ite(&c, &a, &b).unwrap();
    let expr = ctx.or2(&d, &ite).unwrap();

    // Expected result: if c then (d || a) else (d || b)
    let d_or_a = ctx.or2(&d, &a).unwrap();
    let d_or_b = ctx.or2(&d, &b).unwrap();
    let expected = ctx.ite(&c, &d_or_a, &d_or_b).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}

#[test]
fn test_bool_xor_with_ite() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bools("a").unwrap();
    let b = ctx.bools("b").unwrap();
    let c = ctx.bools("c").unwrap();
    let d = ctx.bools("d").unwrap();

    // Create expression: d ^ (if c then a else b)
    let ite = ctx.ite(&c, &a, &b).unwrap();
    let expr = ctx.xor2(&d, &ite).unwrap();

    // Expected result: if c then (d ^ a) else (d ^ b)
    let d_xor_a = ctx.xor2(&d, &a).unwrap();
    let d_xor_b = ctx.xor2(&d, &b).unwrap();
    let expected = ctx.ite(&c, &d_xor_a, &d_xor_b).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}

#[test]
fn test_nested_bool_ite() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bools("a").unwrap();
    let b = ctx.bools("b").unwrap();
    let c = ctx.bools("c").unwrap();
    let d = ctx.bools("d").unwrap();

    // Create expression: (if c then a else b) && (if d then b else a)
    let ite1 = ctx.ite(&c, &a, &b).unwrap();
    let ite2 = ctx.ite(&d, &b, &a).unwrap();
    let expr = ctx.and2(&ite1, &ite2).unwrap();

    // Expected result:
    // if c then
    //   (if d then (a && b) else (a && a))
    // else
    //   (if d then (b && b) else (b && a))
    let a_and_b = ctx.and2(&a, &b).unwrap();
    let a_and_a = ctx.and2(&a, &a).unwrap();
    let b_and_b = ctx.and2(&b, &b).unwrap();
    let b_and_a = ctx.and2(&b, &a).unwrap();

    let then_branch = ctx.ite(&d, &a_and_b, &a_and_a).unwrap();
    let else_branch = ctx.ite(&d, &b_and_b, &b_and_a).unwrap();

    let expected = ctx.ite(&c, &then_branch, &else_branch).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}
