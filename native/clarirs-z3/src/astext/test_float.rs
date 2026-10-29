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

    #[test]
    fn fp_min_max_fma_round_to_integral() {
        let ctx = Context::new();
        let x = ctx.fps("x", FSort::f64()).unwrap();
        let y = ctx.fps("y", FSort::f64()).unwrap();
        let z = ctx.fps("z", FSort::f64()).unwrap();
        for ast in [
            ctx.fp_min(&x, &y).unwrap(),
            ctx.fp_max(&x, &y).unwrap(),
            ctx.fp_fma(&x, &y, &z, FPRM::TowardNegative).unwrap(),
            ctx.fp_round_to_integral(&x, FPRM::NearestTiesToAway)
                .unwrap(),
        ] {
            assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
        }
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
// SMT-LIB export accepted by Z3
// ---------------------------------------------------------------
mod smtlib {
    use super::*;
    use clarirs_core::smtlib::constraints_to_smtlib;

    /// Parses `benchmark` with Z3's SMT-LIB reader, failing on any sort error.
    fn z3_parses(benchmark: &str) {
        let text = std::ffi::CString::new(benchmark).unwrap();
        Z3_CONTEXT.with(|&z3_ctx| unsafe {
            let parsed = Z3_parse_smtlib2_string(
                z3_ctx,
                text.as_ptr(),
                0,
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            );
            crate::check_z3_error().unwrap_or_else(|e| panic!("{e}:\n{benchmark}"));
            assert!(parsed.is_some(), "Z3 rejected:\n{benchmark}");
        });
    }

    #[test]
    fn min_max_fma_round_parse() {
        let ctx = Context::new();
        let rm = FPRM::TowardZero;
        let x = ctx.fps("x", FSort::f64()).unwrap();
        let y = ctx.fps("y", FSort::f64()).unwrap();
        let z = ctx.fps("z", FSort::f64()).unwrap();

        let constraints = [
            ctx.fp_eq(&x, ctx.fp_min(&y, &z).unwrap()).unwrap(),
            ctx.fp_eq(&x, ctx.fp_max(&y, &z).unwrap()).unwrap(),
            ctx.fp_eq(&x, ctx.fp_fma(&x, &y, &z, rm).unwrap()).unwrap(),
            ctx.fp_eq(&x, ctx.fp_round_to_integral(&y, rm).unwrap())
                .unwrap(),
        ];
        z3_parses(&constraints_to_smtlib(&constraints).unwrap());
    }
}

// ---------------------------------------------------------------
// Semantics of the lowered ops, checked by Z3
// ---------------------------------------------------------------
mod semantics {
    use super::*;
    use crate::Z3Solver;

    fn f64v<'c>(ctx: &'c Context<'c>, v: f64) -> AstRef<'c> {
        ctx.fpv(Float::F64(v)).unwrap()
    }

    /// `fp.eq(got, want)` holds, checked by Z3.
    fn holds<'c>(ctx: &'c Context<'c>, got: AstRef<'c>, want: f64) -> bool {
        let eq = ctx.fp_eq(got, f64v(ctx, want)).unwrap();
        Z3Solver::new(ctx).is_true(&eq).unwrap()
    }

    #[test]
    fn min_max_return_the_number_over_nan() {
        let ctx = Context::new();
        let (nan, one, two) = (f64v(&ctx, f64::NAN), f64v(&ctx, 1.0), f64v(&ctx, 2.0));
        assert!(holds(&ctx, ctx.fp_min(&nan, &one).unwrap(), 1.0));
        assert!(holds(&ctx, ctx.fp_max(&two, &nan).unwrap(), 2.0));
        assert!(holds(&ctx, ctx.fp_min(&one, &two).unwrap(), 1.0));
        assert!(holds(&ctx, ctx.fp_max(&one, &two).unwrap(), 2.0));
    }

    /// Whatever Z3 returns for `fp.min(+0, -0)` has to decode.
    #[test]
    fn min_max_of_signed_zeros_come_back_from_z3() {
        let ctx = Context::new();
        let (pz, nz) = (f64v(&ctx, 0.0), f64v(&ctx, -0.0));
        for got in [ctx.fp_min(&pz, &nz).unwrap(), ctx.fp_max(&nz, &pz).unwrap()] {
            let back = got.simplify_z3().unwrap();
            assert!(
                matches!(back.op(), AstOp::FPV(f) if f.is_zero())
                    || matches!(back.op(), AstOp::FpMin(..) | AstOp::FpMax(..)),
                "{back:?}"
            );
        }
    }

    /// The constant FMA fold agrees with Z3's `fp.fma` in every rounding
    /// mode, on operands chosen so the product and addend overlap and cancel.
    #[test]
    fn fma_fold_matches_z3_in_every_mode() {
        let ctx = Context::new();
        let modes = [
            FPRM::NearestTiesToEven,
            FPRM::NearestTiesToAway,
            FPRM::TowardPositive,
            FPRM::TowardNegative,
            FPRM::TowardZero,
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for i in 0..150 {
            let mut f64_near =
                |exp: u64| f64::from_bits((next() >> 12) | (exp << 52) | (next() & 1) << 63);
            let (a, b) = (f64_near(1023 + i % 7), f64_near(1020 + i % 5));
            let c = if i % 3 == 0 {
                -(a * b)
            } else {
                f64_near(1023 + i % 11)
            };
            let f32s = [a as f32, b as f32, c as f32].map(Float::F32);
            for ops in [[a, b, c].map(Float::F64), f32s] {
                for rm in modes {
                    let [fa, fb, fc] = ops.map(|v| ctx.fpv(v).unwrap());
                    let fma = ctx.fp_fma(&fa, &fb, &fc, rm).unwrap();
                    let folded = fma.simplify().unwrap();
                    // Z3 evaluates the unsimplified term itself
                    let z3 = Z3_CONTEXT.with(|z3_ctx| unsafe {
                        let ast = fma.to_z3().unwrap();
                        let simplified = RcAst::try_from(Z3_simplify(*z3_ctx, *ast)).unwrap();
                        AstRef::from_z3(&ctx, simplified).unwrap()
                    });
                    let same = match (folded.op(), z3.op()) {
                        (AstOp::FPV(x), AstOp::FPV(y)) => {
                            (x.is_nan() && y.is_nan())
                                || x.to_f64().map(f64::to_bits) == y.to_f64().map(f64::to_bits)
                        }
                        _ => false,
                    };
                    assert!(same, "{ops:?} under {rm:?}: folded {folded:?}, Z3 {z3:?}");
                }
            }
        }
    }

    /// `(1 + 2^-52) * (1 - 2^-52) - 1` is `-2^-104` exactly; a separately
    /// rounded product is `1.0`, which would give 0.
    #[test]
    fn fma_rounds_once() {
        let ctx = Context::new();
        let a = f64v(&ctx, 1.0 + f64::EPSILON);
        let b = f64v(&ctx, 1.0 - f64::EPSILON);
        let c = f64v(&ctx, -1.0);
        let rne = FPRM::NearestTiesToEven;
        let exact = -(2f64.powi(-104));
        assert!(holds(&ctx, ctx.fp_fma(&a, &b, &c, rne).unwrap(), exact));
        let split = ctx
            .fp_add(ctx.fp_mul(&a, &b, rne).unwrap(), &c, rne)
            .unwrap();
        assert!(holds(&ctx, split, 0.0));
    }

    #[test]
    fn round_to_integral_honors_the_rounding_mode() {
        let ctx = Context::new();
        let half = f64v(&ctx, 2.5);
        let neg = f64v(&ctx, -2.5);
        for (x, rm, want) in [
            (&half, FPRM::NearestTiesToEven, 2.0),
            (&half, FPRM::NearestTiesToAway, 3.0),
            (&half, FPRM::TowardPositive, 3.0),
            (&half, FPRM::TowardNegative, 2.0),
            (&neg, FPRM::TowardZero, -2.0),
        ] {
            let got = ctx.fp_round_to_integral(x, rm).unwrap();
            assert!(holds(&ctx, got, want), "{rm:?}");
        }
    }
}
