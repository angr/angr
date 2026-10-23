use clarirs_core::prelude::*;
use z3_sys::*;

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

        assert_eq!(z3_ast.decl_kind(), DeclKind::Uninterpreted);
        assert_eq!(z3_ast.symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn symbol_f64() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f64()).unwrap();
        let z3_ast = x.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Uninterpreted);
        assert_eq!(z3_ast.symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn value_f32() {
        let ctx = Context::new();
        let f = ctx.fpv(Float::F32(std::f32::consts::PI)).unwrap();
        let z3_ast = f.to_z3().unwrap();
        // Z3 represents float numerals as FpaNum
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaNum);
    }

    #[test]
    fn value_f64() {
        let ctx = Context::new();
        let f = ctx.fpv(Float::F64(std::f64::consts::E)).unwrap();
        let z3_ast = f.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaNum);
    }

    #[test]
    fn value_f32_zero() {
        let ctx = Context::new();
        let f = ctx.fpv(Float::F32(0.0f32)).unwrap();
        let z3_ast = f.to_z3().unwrap();
        // Z3 may represent +0.0 as FpaNum or FpaPlusZero
        let dk = z3_ast.decl_kind();
        assert!(dk == DeclKind::FpaNum || dk == DeclKind::FpaPlusZero);
    }

    #[test]
    fn value_f32_neg_zero() {
        let ctx = Context::new();
        let f = ctx.fpv(Float::F32(-0.0f32)).unwrap();
        let z3_ast = f.to_z3().unwrap();
        let dk = z3_ast.decl_kind();
        assert!(dk == DeclKind::FpaNum || dk == DeclKind::FpaMinusZero);
    }

    // -- Unary ops --

    #[test]
    fn fp_neg() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let neg = ctx.fp_neg(x).unwrap();
        let z3_ast = neg.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaNeg);
        assert_eq!(z3_ast.num_args(), 1);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn fp_abs() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let abs = ctx.fp_abs(x).unwrap();
        let z3_ast = abs.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaAbs);
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

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaAdd);
        // 3 args: rounding mode, a, b
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            DeclKind::FpaRmNearestTiesToEven
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

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaSub);
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            DeclKind::FpaRmTowardZero
        );
    }

    #[test]
    fn fp_mul() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let mul = ctx.fp_mul(a, b, FPRM::TowardPositive).unwrap();
        let z3_ast = mul.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaMul);
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            DeclKind::FpaRmTowardPositive
        );
    }

    #[test]
    fn fp_div() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let div = ctx.fp_div(a, b, FPRM::TowardNegative).unwrap();
        let z3_ast = div.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaDiv);
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            DeclKind::FpaRmTowardNegative
        );
    }

    #[test]
    fn fp_sqrt() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f32()).unwrap();
        let sqrt = ctx.fp_sqrt(x, FPRM::NearestTiesToAway).unwrap();
        let z3_ast = sqrt.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaSqrt);
        // 2 args: rounding mode, operand
        assert_eq!(z3_ast.num_args(), 2);
        assert_eq!(
            z3_ast.arg(0).unwrap().decl_kind(),
            DeclKind::FpaRmNearestTiesToAway
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

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaToFp);
        // 2 args: rounding mode, operand
        assert_eq!(z3_ast.num_args(), 2);
    }

    #[test]
    fn bv_to_fp() {
        let ctx = Context::new();
        let bv = ctx.bvs("bits", 32).unwrap();
        let conv = ctx.bv_to_fp(bv, FSort::f32()).unwrap();
        let z3_ast = conv.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaToFp);
    }

    #[test]
    fn bv_to_fp_signed() {
        let ctx = Context::new();
        let bv = ctx.bvs("bits", 32).unwrap();
        let conv = ctx
            .bv_to_fp_signed(bv, FSort::f32(), FPRM::NearestTiesToEven)
            .unwrap();
        let z3_ast = conv.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaToFp);
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

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaToFpUnsigned);
        assert_eq!(z3_ast.num_args(), 2);
    }

    #[test]
    fn fp_fp() {
        let ctx = Context::new();
        let sign = ctx.bvv(BitVec::from((0, 8))).unwrap();
        let sign = ctx.extract(sign, 0, 0).unwrap(); // 1-bit
        let exp = ctx.bvs("exp", 8).unwrap();
        let sig = ctx.bvs("sig", 23).unwrap();
        let fp = ctx.fp_fp(sign, exp, sig).unwrap();
        let z3_ast = fp.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaFp);
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

        assert_eq!(z3_ast.decl_kind(), DeclKind::Ite);
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
            DeclKind::FpaRmNearestTiesToEven
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
            DeclKind::FpaRmTowardPositive
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
            DeclKind::FpaRmTowardNegative
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
            DeclKind::FpaRmTowardZero
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
            DeclKind::FpaRmNearestTiesToAway
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
        let z3_ast = RcAst::mk_fp_val_f32(std::f32::consts::PI);
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        let expected = ctx.fpv(Float::F32(std::f32::consts::PI)).unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn value_f64() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_fp_val_f64(std::f64::consts::E);
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        let expected = ctx.fpv(Float::F64(std::f64::consts::E)).unwrap();
        assert_eq!(expected, result);
    }

    // -- Unary ops --

    #[test]
    fn fp_neg() {
        let ctx = Context::new();
        let x = RcAst::mk_fp("x", FSort::f32());
        let z3_neg = Z3_CONTEXT
            .with(|&z3_ctx| unsafe { RcAst::try_from(Z3_mk_fpa_neg(z3_ctx, *x)).unwrap() });
        let result = AstRef::from_z3(&ctx, z3_neg).unwrap();
        let expected = ctx.fp_neg(ctx.fps("x", FSort::f32()).unwrap()).unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn fp_abs() {
        let ctx = Context::new();
        let x = RcAst::mk_fp("x", FSort::f32());
        let z3_abs = Z3_CONTEXT
            .with(|&z3_ctx| unsafe { RcAst::try_from(Z3_mk_fpa_abs(z3_ctx, *x)).unwrap() });
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
            RcAst::try_from(Z3_mk_fpa_add(z3_ctx, *rm, *a, *b)).unwrap()
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
            RcAst::try_from(Z3_mk_fpa_sub(z3_ctx, *rm, *a, *b)).unwrap()
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
            RcAst::try_from(Z3_mk_fpa_mul(z3_ctx, *rm, *a, *b)).unwrap()
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
            RcAst::try_from(Z3_mk_fpa_div(z3_ctx, *rm, *a, *b)).unwrap()
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
            .with(|&z3_ctx| unsafe { RcAst::try_from(Z3_mk_fpa_sqrt(z3_ctx, *rm, *x)).unwrap() });
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
            RcAst::try_from(Z3_mk_fpa_fp(z3_ctx, *sign, *exp, *sig)).unwrap()
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
            .with(|&z3_ctx| unsafe { RcAst::try_from(Z3_mk_ite(z3_ctx, *c, *a, *b)).unwrap() });
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
        let sign = ctx.bvv(BitVec::from((0, 8))).unwrap();
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

// ---------------------------------------------------------------
// Constant folds under every rounding mode, checked against Z3
// ---------------------------------------------------------------
mod rounding_folds {
    use super::*;

    const MODES: [FPRM; 5] = [
        FPRM::NearestTiesToEven,
        FPRM::NearestTiesToAway,
        FPRM::TowardPositive,
        FPRM::TowardNegative,
        FPRM::TowardZero,
    ];

    /// What Z3 computes for `term` itself, unsimplified by clarirs.
    fn z3_value<'c>(ctx: &'c Context<'c>, term: &AstRef<'c>) -> AstRef<'c> {
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let simplified = Z3_simplify(*z3_ctx, *term.to_z3().unwrap());
            AstRef::from_z3(ctx, RcAst::try_from(simplified).unwrap()).unwrap()
        })
    }

    /// `term` folds to the value Z3 gives it. Floats are compared as IEEE
    /// bits, so the sign of a zero counts; a NaN only has to be a NaN.
    fn assert_folds_like_z3<'c>(ctx: &'c Context<'c>, term: AstRef<'c>) {
        let folded = term.simplify().unwrap();
        if let AstOp::FPV(value) = folded.op() {
            if value.is_nan() {
                let is_nan = z3_value(ctx, &ctx.fp_is_nan(&term).unwrap());
                assert!(is_nan.is_true(), "{term:?} folds to NaN, Z3 disagrees");
            } else {
                let bits = z3_value(ctx, &ctx.fp_to_ieeebv(&term).unwrap());
                assert_eq!(
                    ctx.bvv(value.to_ieee_bits()).unwrap(),
                    bits,
                    "{term:?} folds to {value:?}"
                );
            }
            return;
        }
        assert_eq!(folded, z3_value(ctx, &term), "{term:?}");
    }

    /// Operand pairs whose results are inexact, ties, overflow, subnormal or
    /// an exact zero, in both signs.
    const F64_PAIRS: &[(f64, f64)] = &[
        (1.5, 0.2),
        (-1.5, 0.2),
        (0.1, 0.3),
        (1.0, 3.0),
        (2.0, 3.0),
        // 1 + 2^-53 is halfway between 1 and the next f64
        (1.0, 1.0 / 9_007_199_254_740_992.0),
        (1.0, -1.0),
        (1.0, 1.0 + f64::EPSILON),
        (f64::MAX, f64::MAX),
        (-f64::MAX, f64::MAX),
        (f64::MIN_POSITIVE, 0.75),
        (f64::MIN_POSITIVE, -0.3),
        (5e-324, 0.5),
        (5e-324, 1.5),
    ];

    const F32_PAIRS: &[(f32, f32)] = &[
        (1.5, 0.2),
        (-1.5, 0.2),
        (0.1, 0.3),
        (1.0, 3.0),
        (2.0, 3.0),
        // 1 + 2^-24 is halfway between 1 and the next f32
        (1.0, 1.0 / 16_777_216.0),
        (1.0, -1.0),
        (1.0, 1.0 + f32::EPSILON),
        (f32::MAX, f32::MAX),
        (-f32::MAX, f32::MAX),
        (f32::MIN_POSITIVE, 0.75),
        (f32::MIN_POSITIVE, -0.3),
        (1e-45, 0.5),
        (1e-45, 1.5),
    ];

    /// Every pair from the tables, then a few from a fixed-seed generator:
    /// each random value paired with one a few ulps away, so that
    /// subtracting them cancels.
    fn operand_pairs() -> Vec<(Float, Float)> {
        let mut pairs: Vec<_> = F64_PAIRS
            .iter()
            .map(|&(a, b)| (Float::F64(a), Float::F64(b)))
            .chain(
                F32_PAIRS
                    .iter()
                    .map(|&(a, b)| (Float::F32(a), Float::F32(b))),
            )
            .collect();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for i in 0..16 {
            // Finite, with a modest exponent, either sign
            let a = f64::from_bits((next() >> 12) | ((1013 + i % 21) << 52) | (next() & 1) << 63);
            let b = f64::from_bits(a.to_bits() ^ (next() % 8));
            pairs.push((Float::F64(a), Float::F64(b)));
            let (a, b) = (a as f32, b as f32);
            pairs.push((Float::F32(a), Float::F32(f32::from_bits(a.to_bits() ^ 5))));
            pairs.push((Float::F32(a), Float::F32(b)));
        }
        pairs
    }

    #[test]
    fn arithmetic_folds_match_z3_in_every_mode() {
        let ctx = Context::new();
        for (a, b) in operand_pairs() {
            let (x, y) = (ctx.fpv(a).unwrap(), ctx.fpv(b).unwrap());
            for rm in MODES {
                assert_folds_like_z3(&ctx, ctx.fp_add(&x, &y, rm).unwrap());
                assert_folds_like_z3(&ctx, ctx.fp_sub(&x, &y, rm).unwrap());
                assert_folds_like_z3(&ctx, ctx.fp_mul(&x, &y, rm).unwrap());
                assert_folds_like_z3(&ctx, ctx.fp_div(&x, &y, rm).unwrap());
                assert_folds_like_z3(&ctx, ctx.fp_sqrt(&x, rm).unwrap());
            }
        }
    }

    #[test]
    fn to_integer_folds_match_z3_in_every_mode() {
        let ctx = Context::new();
        for v in [
            0.5,
            1.5,
            2.5,
            2.7,
            -0.5,
            -2.5,
            -2.7,
            4_503_599_627_370_497.5,
        ] {
            for x in [Float::F64(v), Float::F32(v as f32)].map(|f| ctx.fpv(f).unwrap()) {
                for rm in MODES {
                    assert_folds_like_z3(&ctx, ctx.fp_to_sbv(&x, 64, rm).unwrap());
                    if v >= 0.0 {
                        assert_folds_like_z3(&ctx, ctx.fp_to_ubv(&x, 64, rm).unwrap());
                    }
                }
            }
        }
    }

    /// f64 to f32, including a tie, the edge of overflow and subnormals.
    #[test]
    fn narrowing_folds_match_z3_in_every_mode() {
        let ctx = Context::new();
        let tie = 1.0 + 1.0 / 16_777_216.0;
        for v in [
            0.1,
            -0.1,
            tie,
            -tie,
            tie + f64::EPSILON,
            f64::from(f32::MAX) * (1.0 + 1.0 / 16_777_216.0),
            f64::from(f32::MAX) * (1.0 + 1.0 / 33_554_432.0),
            f64::MAX,
            1e-45,
            -1e-45,
            7e-46,
            1e-300,
        ] {
            let x = ctx.fpv(Float::F64(v)).unwrap();
            for rm in MODES {
                assert_folds_like_z3(&ctx, ctx.fp_to_fp(&x, FSort::f32(), rm).unwrap());
            }
        }
    }

    /// Integers that do not fit the significand; above 2^53, rounding through
    /// f64 first would round twice.
    #[test]
    fn integer_to_float_folds_match_z3_in_every_mode() {
        let ctx = Context::new();
        for v in [
            (1u64 << 24) + 1,
            (1 << 24) + 3,
            (1 << 53) + 1,
            (1 << 63) + (1 << 10) + 1,
            (1 << 63) + (1 << 39) + 1,
            u64::MAX,
            i64::MIN as u64,
            -((1i64 << 53) + 1) as u64,
            -((1i64 << 62) + (1 << 9) + 1) as u64,
        ] {
            let int = ctx.bvv(BitVec::from((v, 64))).unwrap();
            for fsort in [FSort::f32(), FSort::f64()] {
                for rm in MODES {
                    assert_folds_like_z3(&ctx, ctx.bv_to_fp_signed(&int, fsort, rm).unwrap());
                    assert_folds_like_z3(&ctx, ctx.bv_to_fp_unsigned(&int, fsort, rm).unwrap());
                }
            }
        }
    }
}
