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
fn test_unrelated_conditions_are_left_alone() {
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

    // The two ITEs are on unrelated conditions, so hoisting both would produce
    // the full `c` x `d` decision tree. Excavation gives up and leaves the
    // expression as it found it.
    let result = expr.excavate_ite().unwrap();

    assert_eq!(result.op(), expr.op());
}

#[test]
fn test_shared_condition_is_hoisted_once() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bools("a").unwrap();
    let b = ctx.bools("b").unwrap();
    let c = ctx.bools("c").unwrap();
    let x = ctx.bools("x").unwrap();
    let y = ctx.bools("y").unwrap();

    // Create expression: (if c then a else b) && (if c then x else y)
    let ite1 = ctx.ite(&c, &a, &b).unwrap();
    let ite2 = ctx.ite(&c, &x, &y).unwrap();
    let expr = ctx.and2(&ite1, &ite2).unwrap();

    // Expected result: if c then (a && x) else (b && y)
    let a_and_x = ctx.and2(&a, &x).unwrap();
    let b_and_y = ctx.and2(&b, &y).unwrap();
    let expected = ctx.ite(&c, &a_and_x, &b_and_y).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}

#[test]
fn test_negated_condition_branches_are_swapped() {
    let ctx = Context::new();

    // Create variables
    let a = ctx.bools("a").unwrap();
    let b = ctx.bools("b").unwrap();
    let c = ctx.bools("c").unwrap();
    let x = ctx.bools("x").unwrap();
    let y = ctx.bools("y").unwrap();

    // Create expression: (if c then a else b) && (if !c then x else y)
    let not_c = ctx.not(&c).unwrap();
    let ite1 = ctx.ite(&c, &a, &b).unwrap();
    let ite2 = ctx.ite(&not_c, &x, &y).unwrap();
    let expr = ctx.and2(&ite1, &ite2).unwrap();

    // Expected result: if c then (a && y) else (b && x)
    let a_and_y = ctx.and2(&a, &y).unwrap();
    let b_and_x = ctx.and2(&b, &x).unwrap();
    let expected = ctx.ite(&c, &a_and_y, &b_and_x).unwrap();

    // Excavate ITEs
    let result = expr.excavate_ite().unwrap();

    // Verify result
    assert_eq!(result.op(), expected.op());
}
