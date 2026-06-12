use clarirs_core::prelude::*;
use clarirs_z3_sys as z3;

use super::AstExtZ3;
use crate::{Z3_CONTEXT, rc::RcAst};

fn round_trip<'c>(ctx: &'c Context<'c>, ast: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
    AstRef::from_z3(ctx, ast.to_z3()?)
}

// ---------------------------------------------------------------
// to_z3 tests
// ---------------------------------------------------------------
mod to_z3 {
    use super::*;

    // -- Leaf nodes --

    #[test]
    fn symbol_f32() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let z3_ast = x.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::Uninterpreted);
        assert_eq!(z3_ast.symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn symbol_f64() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f64()).unwrap();
        let z3_ast = x.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::Uninterpreted);
        assert_eq!(z3_ast.symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn value_f32() {
        let ctx = Context::new();
        let f = ctx.fpv(Float::F32(3.14f32)).unwrap();
        let z3_ast = f.to_z3().unwrap();
        // Z3 represents float numerals as FpaNum
        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaNum);
    }

    #[test]
    fn value_f64() {
        let ctx = Context::new();
        let f = ctx.fpv(Float::F64(2.718281828459045f64)).unwrap();
        let z3_ast = f.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaNum);
    }

    #[test]
    fn value_f32_zero() {
        let ctx = Context::new();
        let f = ctx.fpv(Float::F32(0.0f32)).unwrap();
        let z3_ast = f.to_z3().unwrap();
        // Z3 may represent +0.0 as FpaNum or FpaPlusZero
        let dk = z3_ast.decl_kind();
        assert!(dk == z3::DeclKind::FpaNum || dk == z3::DeclKind::FpaPlusZero);
    }

    #[test]
    fn value_f32_neg_zero() {
        let ctx = Context::new();
        let f = ctx.fpv(Float::F32(-0.0f32)).unwrap();
        let z3_ast = f.to_z3().unwrap();
        let dk = z3_ast.decl_kind();
        assert!(dk == z3::DeclKind::FpaNum || dk == z3::DeclKind::FpaMinusZero);
    }

    // -- Unary ops --

    #[test]
    fn fp_neg() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let neg = ctx.fp_neg(x).unwrap();
        let z3_ast = neg.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaNeg);
        assert_eq!(z3_ast.num_args(), 1);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn fp_abs() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let abs = ctx.fp_abs(x).unwrap();
        let z3_ast = abs.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaAbs);
        assert_eq!(z3_ast.num_args(), 1);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
    }

    // -- Binary arithmetic ops (with rounding mode) --

    #[test]
    fn fp_add() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let add = ctx.fp_add(a, b, FPRM::NearestTiesToEven).unwrap();
        let z3_ast = add.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaAdd);
        // 3 args: rounding mode, a, b
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            z3::DeclKind::FpaRmNearestTiesToEven
        );
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("a"));
        assert_eq!(z3_ast.arg(2).unwrap().symbol_name().as_deref(), Some("b"));
    }

    #[test]
    fn fp_sub() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let sub = ctx.fp_sub(a, b, FPRM::TowardZero).unwrap();
        let z3_ast = sub.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaSub);
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            z3::DeclKind::FpaRmTowardZero
        );
    }

    #[test]
    fn fp_mul() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let mul = ctx.fp_mul(a, b, FPRM::TowardPositive).unwrap();
        let z3_ast = mul.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaMul);
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            z3::DeclKind::FpaRmTowardPositive
        );
    }

    #[test]
    fn fp_div() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let div = ctx.fp_div(a, b, FPRM::TowardNegative).unwrap();
        let z3_ast = div.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaDiv);
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            z3::DeclKind::FpaRmTowardNegative
        );
    }

    #[test]
    fn fp_sqrt() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let sqrt = ctx.fp_sqrt(x, FPRM::NearestTiesToAway).unwrap();
        let z3_ast = sqrt.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaSqrt);
        // 2 args: rounding mode, operand
        assert_eq!(z3_ast.num_args(), 2);
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            z3::DeclKind::FpaRmNearestTiesToAway
        );
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("x"));
    }

    // -- Conversion ops --

    #[test]
    fn fp_to_fp() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let conv = ctx
            .fp_to_fp(x, FSort::f64(), FPRM::NearestTiesToEven)
            .unwrap();
        let z3_ast = conv.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaToFp);
        // 2 args: rounding mode, operand
        assert_eq!(z3_ast.num_args(), 2);
    }

    #[test]
    fn bv_to_fp() {
        let ctx = Context::new();
        let bv = ctx.bvs("bits", 32).unwrap();
        let conv = ctx.bv_to_fp(bv, FSort::f32()).unwrap();
        let z3_ast = conv.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaToFp);
    }

    #[test]
    fn bv_to_fp_signed() {
        let ctx = Context::new();
        let bv = ctx.bvs("bits", 32).unwrap();
        let conv = ctx
            .bv_to_fp_signed(bv, FSort::f32(), FPRM::NearestTiesToEven)
            .unwrap();
        let z3_ast = conv.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaToFp);
        assert_eq!(z3_ast.num_args(), 2);
    }

    #[test]
    fn bv_to_fp_unsigned() {
        let ctx = Context::new();
        let bv = ctx.bvs("bits", 32).unwrap();
        let conv = ctx
            .bv_to_fp_unsigned(bv, FSort::f32(), FPRM::NearestTiesToEven)
            .unwrap();
        let z3_ast = conv.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaToFpUnsigned);
        assert_eq!(z3_ast.num_args(), 2);
    }

    #[test]
    fn fp_fp() {
        let ctx = Context::new();
        let sign = ctx.bvv_prim(0u8).unwrap();
        let sign = ctx.extract(sign, 0, 0).unwrap(); // 1-bit
        let exp = ctx.bvs("exp", 8).unwrap();
        let sig = ctx.bvs("sig", 23).unwrap();
        let fp = ctx.fp_fp(sign, exp, sig).unwrap();
        let z3_ast = fp.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::FpaFp);
        assert_eq!(z3_ast.num_args(), 3);
    }

    // -- ITE --

    #[test]
    fn ite() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ite = ctx.ite(c, a, b).unwrap();
        let z3_ast = ite.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::Ite);
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("c"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("a"));
        assert_eq!(z3_ast.arg(2).unwrap().symbol_name().as_deref(), Some("b"));
    }

    // -- Rounding modes --

    #[test]
    fn rounding_mode_rne() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let add = ctx.fp_add(a, b, FPRM::NearestTiesToEven).unwrap();
        let z3_ast = add.to_z3().unwrap();
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            z3::DeclKind::FpaRmNearestTiesToEven
        );
    }

    #[test]
    fn rounding_mode_rtp() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let add = ctx.fp_add(a, b, FPRM::TowardPositive).unwrap();
        let z3_ast = add.to_z3().unwrap();
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            z3::DeclKind::FpaRmTowardPositive
        );
    }

    #[test]
    fn rounding_mode_rtn() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let add = ctx.fp_add(a, b, FPRM::TowardNegative).unwrap();
        let z3_ast = add.to_z3().unwrap();
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            z3::DeclKind::FpaRmTowardNegative
        );
    }

    #[test]
    fn rounding_mode_rtz() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let add = ctx.fp_add(a, b, FPRM::TowardZero).unwrap();
        let z3_ast = add.to_z3().unwrap();
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            z3::DeclKind::FpaRmTowardZero
        );
    }

    #[test]
    fn rounding_mode_rna() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let add = ctx.fp_add(a, b, FPRM::NearestTiesToAway).unwrap();
        let z3_ast = add.to_z3().unwrap();
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            z3::DeclKind::FpaRmNearestTiesToAway
        );
    }
}

// ---------------------------------------------------------------
// from_z3 tests
// ---------------------------------------------------------------
mod from_z3 {
    use super::*;

    // -- Leaf nodes --

    #[test]
    fn symbol_f32() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_fp("x", FSort::f32());
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        let expected = ctx.fps("x", FSort::f32()).unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn symbol_f64() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_fp("x", FSort::f64());
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        let expected = ctx.fps("x", FSort::f64()).unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn value_f32() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_fp_val_f32(3.14f32);
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        let expected = ctx.fpv(Float::F32(3.14f32)).unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn value_f64() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_fp_val_f64(2.718281828459045f64);
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        let expected = ctx.fpv(Float::F64(2.718281828459045f64)).unwrap();
        assert_eq!(expected, result);
    }

    // -- Unary ops --

    #[test]
    fn fp_neg() {
        let ctx = Context::new();
        let x = RcAst::mk_fp("x", FSort::f32());
        let z3_neg = Z3_CONTEXT
            .with(|&z3_ctx| unsafe { RcAst::try_from(z3::mk_fpa_neg(z3_ctx, *x)).unwrap() });
        let result = AstRef::from_z3(&ctx, z3_neg).unwrap();
        let expected = ctx.fp_neg(ctx.fps("x", FSort::f32()).unwrap()).unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn fp_abs() {
        let ctx = Context::new();
        let x = RcAst::mk_fp("x", FSort::f32());
        let z3_abs = Z3_CONTEXT
            .with(|&z3_ctx| unsafe { RcAst::try_from(z3::mk_fpa_abs(z3_ctx, *x)).unwrap() });
        let result = AstRef::from_z3(&ctx, z3_abs).unwrap();
        let expected = ctx.fp_abs(ctx.fps("x", FSort::f32()).unwrap()).unwrap();
        assert_eq!(expected, result);
    }

    // -- Binary arithmetic ops --

    #[test]
    fn fp_add() {
        let ctx = Context::new();
        let a = RcAst::mk_fp("a", FSort::f32());
        let b = RcAst::mk_fp("b", FSort::f32());
        let rm = RcAst::mk_fprm(FPRM::NearestTiesToEven);
        let z3_add = Z3_CONTEXT.with(|&z3_ctx| unsafe {
            RcAst::try_from(z3::mk_fpa_add(z3_ctx, *rm, *a, *b)).unwrap()
        });
        let result = AstRef::from_z3(&ctx, z3_add).unwrap();
        let expected = ctx
            .fp_add(
                ctx.fps("a", FSort::f32()).unwrap(),
                ctx.fps("b", FSort::f32()).unwrap(),
                FPRM::NearestTiesToEven,
            )
            .unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn fp_sub() {
        let ctx = Context::new();
        let a = RcAst::mk_fp("a", FSort::f32());
        let b = RcAst::mk_fp("b", FSort::f32());
        let rm = RcAst::mk_fprm(FPRM::TowardZero);
        let z3_sub = Z3_CONTEXT.with(|&z3_ctx| unsafe {
            RcAst::try_from(z3::mk_fpa_sub(z3_ctx, *rm, *a, *b)).unwrap()
        });
        let result = AstRef::from_z3(&ctx, z3_sub).unwrap();
        let expected = ctx
            .fp_sub(
                ctx.fps("a", FSort::f32()).unwrap(),
                ctx.fps("b", FSort::f32()).unwrap(),
                FPRM::TowardZero,
            )
            .unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn fp_mul() {
        let ctx = Context::new();
        let a = RcAst::mk_fp("a", FSort::f32());
        let b = RcAst::mk_fp("b", FSort::f32());
        let rm = RcAst::mk_fprm(FPRM::TowardPositive);
        let z3_mul = Z3_CONTEXT.with(|&z3_ctx| unsafe {
            RcAst::try_from(z3::mk_fpa_mul(z3_ctx, *rm, *a, *b)).unwrap()
        });
        let result = AstRef::from_z3(&ctx, z3_mul).unwrap();
        let expected = ctx
            .fp_mul(
                ctx.fps("a", FSort::f32()).unwrap(),
                ctx.fps("b", FSort::f32()).unwrap(),
                FPRM::TowardPositive,
            )
            .unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn fp_div() {
        let ctx = Context::new();
        let a = RcAst::mk_fp("a", FSort::f32());
        let b = RcAst::mk_fp("b", FSort::f32());
        let rm = RcAst::mk_fprm(FPRM::TowardNegative);
        let z3_div = Z3_CONTEXT.with(|&z3_ctx| unsafe {
            RcAst::try_from(z3::mk_fpa_div(z3_ctx, *rm, *a, *b)).unwrap()
        });
        let result = AstRef::from_z3(&ctx, z3_div).unwrap();
        let expected = ctx
            .fp_div(
                ctx.fps("a", FSort::f32()).unwrap(),
                ctx.fps("b", FSort::f32()).unwrap(),
                FPRM::TowardNegative,
            )
            .unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn fp_sqrt() {
        let ctx = Context::new();
        let x = RcAst::mk_fp("x", FSort::f32());
        let rm = RcAst::mk_fprm(FPRM::NearestTiesToAway);
        let z3_sqrt = Z3_CONTEXT
            .with(|&z3_ctx| unsafe { RcAst::try_from(z3::mk_fpa_sqrt(z3_ctx, *rm, *x)).unwrap() });
        let result = AstRef::from_z3(&ctx, z3_sqrt).unwrap();
        let expected = ctx
            .fp_sqrt(ctx.fps("x", FSort::f32()).unwrap(), FPRM::NearestTiesToAway)
            .unwrap();
        assert_eq!(expected, result);
    }

    // -- Conversion ops --

    #[test]
    fn fp_fp() {
        let ctx = Context::new();
        let sign = RcAst::mk_bv_val("0", 1);
        let exp = RcAst::mk_bv("exp", 8);
        let sig = RcAst::mk_bv("sig", 23);
        let z3_fp = Z3_CONTEXT.with(|&z3_ctx| unsafe {
            RcAst::try_from(z3::mk_fpa_fp(z3_ctx, *sign, *exp, *sig)).unwrap()
        });
        let result = AstRef::from_z3(&ctx, z3_fp).unwrap();

        // Verify it's an FpFP node with the right structure
        match result.op() {
            AstOp::FpFP(..) => {} // expected
            other => panic!("Expected FpFP, got {:?}", other),
        }
    }

    #[test]
    fn ite() {
        let ctx = Context::new();
        let c = RcAst::mk_bool("c");
        let a = RcAst::mk_fp("a", FSort::f32());
        let b = RcAst::mk_fp("b", FSort::f32());
        let z3_ite = Z3_CONTEXT
            .with(|&z3_ctx| unsafe { RcAst::try_from(z3::mk_ite(z3_ctx, *c, *a, *b)).unwrap() });
        let result = AstRef::from_z3(&ctx, z3_ite).unwrap();
        let expected = ctx
            .ite(
                ctx.bools("c").unwrap(),
                ctx.fps("a", FSort::f32()).unwrap(),
                ctx.fps("b", FSort::f32()).unwrap(),
            )
            .unwrap();
        assert_eq!(expected, result);
    }
}

// ---------------------------------------------------------------
// roundtrip tests
// ---------------------------------------------------------------
mod roundtrip {
    use super::*;

    // -- Leaf nodes --

    #[test]
    fn symbol_f32() {
        let ctx = Context::new();
        let ast = ctx.fps("x", FSort::f32()).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn symbol_f64() {
        let ctx = Context::new();
        let ast = ctx.fps("x", FSort::f64()).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_f32_pi() {
        let ctx = Context::new();
        let ast = ctx.fpv(Float::F32(std::f32::consts::PI)).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_f64_e() {
        let ctx = Context::new();
        let ast = ctx.fpv(Float::F64(std::f64::consts::E)).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_f32_one() {
        let ctx = Context::new();
        let ast = ctx.fpv(Float::F32(1.0f32)).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_f64_one() {
        let ctx = Context::new();
        let ast = ctx.fpv(Float::F64(1.0f64)).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_f32_negative() {
        let ctx = Context::new();
        let ast = ctx.fpv(Float::F32(-42.5f32)).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_f64_negative() {
        let ctx = Context::new();
        let ast = ctx.fpv(Float::F64(-123.456f64)).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- Unary ops --

    #[test]
    fn fp_neg() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let ast = ctx.fp_neg(x).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_abs() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let ast = ctx.fp_abs(x).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- Binary arithmetic ops --

    #[test]
    fn fp_add() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_add(a, b, FPRM::NearestTiesToEven).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_sub() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_sub(a, b, FPRM::NearestTiesToEven).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_mul() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_mul(a, b, FPRM::NearestTiesToEven).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_div() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_div(a, b, FPRM::NearestTiesToEven).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_sqrt() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let ast = ctx.fp_sqrt(x, FPRM::NearestTiesToEven).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- Conversion ops --

    #[test]
    fn fp_to_fp_f32_to_f64() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let ast = ctx
            .fp_to_fp(x, FSort::f64(), FPRM::NearestTiesToEven)
            .unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_to_fp_f64_to_f32() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f64()).unwrap();
        let ast = ctx
            .fp_to_fp(x, FSort::f32(), FPRM::NearestTiesToEven)
            .unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn bv_to_fp() {
        let ctx = Context::new();
        let bv = ctx.bvs("bits", 32).unwrap();
        let ast = ctx.bv_to_fp(bv, FSort::f32()).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn bv_to_fp_signed() {
        let ctx = Context::new();
        let bv = ctx.bvs("bits", 32).unwrap();
        let ast = ctx
            .bv_to_fp_signed(bv, FSort::f32(), FPRM::NearestTiesToEven)
            .unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_fp() {
        let ctx = Context::new();
        let sign = ctx.bvv_prim(0u8).unwrap();
        let sign = ctx.extract(sign, 0, 0).unwrap(); // 1-bit
        let exp = ctx.bvs("exp", 8).unwrap();
        let sig = ctx.bvs("sig", 23).unwrap();
        let ast = ctx.fp_fp(sign, exp, sig).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- ITE --

    #[test]
    fn ite() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.ite(c, a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- F64 variants --

    #[test]
    fn fp_neg_f64() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f64()).unwrap();
        let ast = ctx.fp_neg(x).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_abs_f64() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f64()).unwrap();
        let ast = ctx.fp_abs(x).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_add_f64() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f64()).unwrap();
        let b = ctx.fps("b", FSort::f64()).unwrap();
        let ast = ctx.fp_add(a, b, FPRM::NearestTiesToEven).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_mul_f64() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f64()).unwrap();
        let b = ctx.fps("b", FSort::f64()).unwrap();
        let ast = ctx.fp_mul(a, b, FPRM::NearestTiesToEven).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- Rounding mode variants --

    #[test]
    fn fp_add_toward_zero() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_add(a, b, FPRM::TowardZero).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_add_toward_positive() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_add(a, b, FPRM::TowardPositive).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_add_toward_negative() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_add(a, b, FPRM::TowardNegative).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_add_nearest_ties_away() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_add(a, b, FPRM::NearestTiesToAway).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }
}
