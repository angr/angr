use std::sync::Arc;

use super::*;
use crate::ast::AnnotationType;

fn round_trip<'c>(ctx: &'c Context<'c>, roots: &[AstRef<'c>]) -> Vec<AstRef<'c>> {
    let json = serde_json::to_string(&WireDag::encode(roots)).unwrap();
    let dag: WireDag = serde_json::from_str(&json).unwrap();
    dag.decode(ctx).unwrap()
}

fn assert_same_nodes<'c>(original: &[AstRef<'c>], decoded: &[AstRef<'c>]) {
    assert_eq!(original.len(), decoded.len());
    for (a, b) in original.iter().zip(decoded) {
        assert!(Arc::ptr_eq(a, b), "{a:?} decoded as {b:?}");
    }
}

#[test]
fn every_parameterised_op_round_trips_to_the_same_node() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    let rm = FPRM::TowardZero;
    let x = ctx.bvs("x", 32)?;
    let f = ctx.fps("f", FSort::f32())?;
    let d = ctx.fps("d", FSort::f64())?;
    let ops = [
        AstOp::ZeroExt(x.clone(), 8),
        AstOp::SignExt(x.clone(), 16),
        AstOp::Extract(x.clone(), 15, 4),
        AstOp::FpToUBV(f.clone(), 16, rm),
        AstOp::FpToSBV(d.clone(), 64, FPRM::NearestTiesToAway),
        AstOp::FpSqrt(f.clone(), rm),
        AstOp::FpToFp(d.clone(), FSort::f32(), rm),
        AstOp::BvToFp(x.clone(), FSort::f32()),
        AstOp::BvToFpSigned(x.clone(), FSort::f64(), rm),
        AstOp::BvToFpUnsigned(x.clone(), FSort::f64(), FPRM::TowardPositive),
        AstOp::FpAdd(f.clone(), f.clone(), rm),
        AstOp::FpSub(f.clone(), f.clone(), FPRM::TowardNegative),
        AstOp::FpMul(d.clone(), d.clone(), rm),
        AstOp::FpDiv(d.clone(), d.clone(), FPRM::NearestTiesToEven),
        AstOp::FpToIEEEBV(f.clone()),
        AstOp::FpMin(d.clone(), ctx.fpv(Float::from(2.0f64))?),
        AstOp::FpMax(d.clone(), d.clone()),
        AstOp::FpFma(d.clone(), d.clone(), d.clone(), FPRM::TowardPositive),
        AstOp::FpRoundToIntegral(f.clone(), rm),
        AstOp::FpLt(f.clone(), f.clone()),
        AstOp::RotateLeft(x.clone(), x.clone()),
        AstOp::ITE(ctx.bools("c")?, x.clone(), ctx.bvv(BitVec::from((7, 32)))?),
        AstOp::Concat(vec![x.clone(), x.clone(), x.clone()]),
        AstOp::Add(vec![x.clone(), x.clone(), x.clone()]),
        AstOp::FpFP(ctx.bvs("s", 1)?, ctx.bvs("e", 8)?, ctx.bvs("m", 23)?),
        AstOp::StrIndexOf(ctx.strings("s")?, ctx.stringv("a\"b")?, ctx.bvs("i", 64)?),
        AstOp::Not(ctx.bools("b")?),
        AstOp::Eq(ctx.fpv(Float::from(1.5f64))?, d.clone()),
    ];
    let roots = ops
        .into_iter()
        .map(|op| ctx.make_ast(op))
        .collect::<Result<Vec<_>, _>>()?;
    assert_same_nodes(&roots, &round_trip(&ctx, &roots));
    Ok(())
}

#[test]
fn shared_subterms_are_encoded_once() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    let mut e = ctx.bvs("x", 64)?;
    // A 40-deep chain in which each level uses the previous one twice: the
    // expanded tree has 2^40 leaves, the DAG 42 nodes.
    for _ in 0..40 {
        e = ctx.add(&e, &e)?;
    }
    let dag = WireDag::encode(std::slice::from_ref(&e));
    assert_eq!(dag.nodes.len(), 41);
    assert_same_nodes(&[e.clone()], &dag.decode(&ctx)?);
    Ok(())
}

#[test]
fn roots_share_nodes_and_keep_their_order() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 8)?;
    let y = ctx.bvs("y", 8)?;
    let sum = ctx.add(&x, &y)?;
    let roots = vec![ctx.mul(&sum, &x)?, x.clone(), sum.clone(), x.clone()];
    let dag = WireDag::encode(&roots);
    // x, y, sum, product.
    assert_eq!(dag.nodes.len(), 4);
    assert_same_nodes(&roots, &dag.decode(&ctx)?);
    Ok(())
}

#[test]
fn annotations_survive() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    let annotated = ctx.annotate(
        ctx.bvs("x", 32)?,
        [
            Annotation::new(AnnotationType::Uninitialized, true, false),
            Annotation::new(
                AnnotationType::Region {
                    region_id: "stack".into(),
                    region_base_addr: 0x7fff_0000u32.into(),
                },
                false,
                true,
            ),
        ],
    )?;
    let root = ctx.zero_ext(&annotated, 32)?;
    let decoded = round_trip(&ctx, std::slice::from_ref(&root));
    assert_same_nodes(&[root], &decoded);
    assert_eq!(decoded[0].op().get_child(0).unwrap().annotations().len(), 2);
    Ok(())
}

#[test]
fn decoding_into_another_context_rebuilds_the_same_structure() -> Result<(), ClarirsError> {
    let a = Context::new();
    let b = Context::new();
    let x = a.bvs("x", 32)?;
    let root = a.ite(
        a.ult(&x, a.bvv(BitVec::from((9, 32)))?)?,
        &x,
        a.extract(&x, 31, 0)?,
    )?;
    let decoded = WireDag::encode(std::slice::from_ref(&root)).decode(&b)?;
    assert_eq!(decoded[0].hash(), root.hash());
    assert_eq!(decoded[0].to_smtlib(), root.to_smtlib());
    Ok(())
}

#[test]
fn malformed_input_is_an_error_not_a_panic() {
    let ctx = Context::new();
    let forward: WireDag = serde_json::from_str(
        r#"{"nodes":[{"op":"Not","children":[1]},{"op":{"BoolV":true}}],"roots":[0]}"#,
    )
    .unwrap();
    assert!(forward.decode(&ctx).is_err());
    let arity: WireDag = serde_json::from_str(
        r#"{"nodes":[{"op":{"BoolV":true}},{"op":"Not","children":[0,0]}],"roots":[1]}"#,
    )
    .unwrap();
    assert!(arity.decode(&ctx).is_err());
    let root: WireDag =
        serde_json::from_str(r#"{"nodes":[{"op":{"BoolV":true}}],"roots":[3]}"#).unwrap();
    assert!(root.decode(&ctx).is_err());
}
