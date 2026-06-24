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
    fn symbol() {
        let ctx = Context::new();
        let bv = ctx.bvs("x", 32).unwrap();
        let z3_ast = bv.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Uninterpreted);
        assert_eq!(z3_ast.symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn value_8bit() {
        let ctx = Context::new();
        let bv = ctx.bvv(BitVec::from((42, 8))).unwrap();
        let z3_ast = bv.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Bnum);
    }

    #[test]
    fn value_32bit() {
        let ctx = Context::new();
        let bv = ctx.bvv(BitVec::from((0xDEADBEEF, 32))).unwrap();
        let z3_ast = bv.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Bnum);
    }

    #[test]
    fn value_64bit() {
        let ctx = Context::new();
        let bv = ctx.bvv(BitVec::from((0x0123456789ABCDEF, 64))).unwrap();
        let z3_ast = bv.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Bnum);
    }

    // -- Unary ops --

    #[test]
    fn not() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let ast = ctx.not(x).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Bnot);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn neg() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let ast = ctx.neg(x).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Bneg);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
    }

    // -- Binary arithmetic ops --

    #[test]
    fn and() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.and2(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Band);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn or() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.or2(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Bor);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn xor() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.xor2(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Bxor);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn add() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.add(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Badd);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn sub() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.sub(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Bsub);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn mul() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.mul(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Bmul);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn udiv() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.udiv(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Budiv);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn sdiv() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.sdiv(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Bsdiv);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn urem() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.urem(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Burem);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn srem() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.srem(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Bsrem);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    // -- Shift / rotate --

    #[test]
    fn shl() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.shl(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Bshl);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn lshr() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.lshr(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Blshr);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn ashr() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.ashr(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Bashr);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn rotate_left() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.rotate_left(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::ExtRotateLeft);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn rotate_right() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.rotate_right(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::ExtRotateRight);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    // -- Extension / extraction --

    #[test]
    fn zero_ext() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let ast = ctx.zero_ext(x, 8).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::ZeroExt);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn sign_ext() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let ast = ctx.sign_ext(x, 8).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::SignExt);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn extract() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let ast = ctx.extract(x, 6, 2).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Extract);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
    }

    // -- Concat --

    #[test]
    fn concat_2args() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.concat2(x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Concat);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn concat_3args() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let z = ctx.bvs("z", 8).unwrap();
        let ast = ctx.concat([x, y, z]).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        // Z3's concat is binary, so 3-arg concat becomes nested:
        // concat(concat(x, y), z)
        assert_eq!(z3_ast.decl_kind(), DeclKind::Concat);
        assert_eq!(z3_ast.num_args(), 2);
    }

    // -- ITE --

    #[test]
    fn ite() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.ite(c, x, y).unwrap();
        let z3_ast = ast.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Ite);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("c"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(2).unwrap().symbol_name().as_deref(), Some("y"));
    }

    // -- FP to BV conversions --

    #[test]
    fn fp_to_ieeebv() {
        let ctx = Context::new();
        let fp = ctx.fps("x", FSort::f32()).unwrap();
        let ast = ctx.fp_to_ieeebv(fp).unwrap();
        let z3_ast = ast.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaToIeeeBv);
    }

    #[test]
    fn fp_to_ubv() {
        let ctx = Context::new();
        let fp = ctx.fps("x", FSort::f32()).unwrap();
        let ast = ctx.fp_to_ubv(fp, 32, FPRM::TowardZero).unwrap();
        let z3_ast = ast.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaToUbv);
    }

    #[test]
    fn fp_to_sbv() {
        let ctx = Context::new();
        let fp = ctx.fps("x", FSort::f32()).unwrap();
        let ast = ctx.fp_to_sbv(fp, 32, FPRM::TowardZero).unwrap();
        let z3_ast = ast.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaToSbv);
    }
}

// ---------------------------------------------------------------
// from_z3 tests
// ---------------------------------------------------------------
mod from_z3 {
    use super::*;

    // -- Leaf nodes --

    #[test]
    fn symbol() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_bv("x", 32);
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        assert_eq!(result, ctx.bvs("x", 32).unwrap());
    }

    #[test]
    fn value_8bit() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_bv_val("42", 8);
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        assert_eq!(result, ctx.bvv(BitVec::from((42, 8))).unwrap());
    }

    #[test]
    fn value_32bit() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_bv_val("3735928559", 32); // 0xDEADBEEF
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        assert_eq!(result, ctx.bvv(BitVec::from((0xDEADBEEF, 32))).unwrap());
    }

    #[test]
    fn value_64bit() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_bv_val("81985529216486895", 64); // 0x0123456789ABCDEF
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        assert_eq!(
            result,
            ctx.bvv(BitVec::from((0x0123456789ABCDEF, 64))).unwrap()
        );
    }

    // -- Unary ops --

    #[test]
    fn not() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvnot(*z3_ctx, *x)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx.not(ctx.bvs("x", 8).unwrap()).unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn neg() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvneg(*z3_ctx, *x)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx.neg(ctx.bvs("x", 8).unwrap()).unwrap();
            assert_eq!(result, expected);
        });
    }

    // -- Binary arithmetic ops --

    #[test]
    fn and() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvand(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .and2(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn or() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvor(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .or2(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn xor() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvxor(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .xor2(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn add() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvadd(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .add(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn sub() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvsub(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .sub(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn mul() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvmul(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .mul(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn udiv() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvudiv(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .udiv(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn sdiv() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvsdiv(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .sdiv(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn urem() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvurem(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .urem(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn srem() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvsrem(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .srem(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    // -- Shift / rotate --

    #[test]
    fn shl() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvshl(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .shl(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn lshr() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvlshr(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .lshr(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn ashr() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_bvashr(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .ashr(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn rotate_left() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_ext_rotate_left(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .rotate_left(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn rotate_right() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_ext_rotate_right(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .rotate_right(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    // -- Extension / extraction --

    #[test]
    fn zero_ext() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let z3_ast = RcAst::try_from(Z3_mk_zero_ext(*z3_ctx, 8, *x)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx.zero_ext(ctx.bvs("x", 8).unwrap(), 8).unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn sign_ext() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let z3_ast = RcAst::try_from(Z3_mk_sign_ext(*z3_ctx, 8, *x)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx.sign_ext(ctx.bvs("x", 8).unwrap(), 8).unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn extract() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let z3_ast = RcAst::try_from(Z3_mk_extract(*z3_ctx, 6, 2, *x)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx.extract(ctx.bvs("x", 8).unwrap(), 6, 2).unwrap();
            assert_eq!(result, expected);
        });
    }

    // -- Concat --

    #[test]
    fn concat_2args() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_concat(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .concat2(ctx.bvs("x", 8).unwrap(), ctx.bvs("y", 8).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    // -- ITE --

    #[test]
    fn ite() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let c = RcAst::mk_bool("c");
            let x = RcAst::mk_bv("x", 8);
            let y = RcAst::mk_bv("y", 8);
            let z3_ast = RcAst::try_from(Z3_mk_ite(*z3_ctx, *c, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .ite(
                    ctx.bools("c").unwrap(),
                    ctx.bvs("x", 8).unwrap(),
                    ctx.bvs("y", 8).unwrap(),
                )
                .unwrap();
            assert_eq!(result, expected);
        });
    }
}

// ---------------------------------------------------------------
// roundtrip tests
// ---------------------------------------------------------------
mod roundtrip {
    use super::*;

    // -- Leaf nodes --

    #[test]
    fn symbol() {
        let ctx = Context::new();
        let ast = ctx.bvs("x", 32).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_8bit() {
        let ctx = Context::new();
        let ast = ctx.bvv(BitVec::from((42, 8))).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_32bit() {
        let ctx = Context::new();
        let ast = ctx.bvv(BitVec::from((0xDEADBEEF, 32))).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_64bit() {
        let ctx = Context::new();
        let ast = ctx.bvv(BitVec::from((0x0123456789ABCDEF, 64))).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- Unary ops --

    #[test]
    fn not() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let ast = ctx.not(x).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn neg() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let ast = ctx.neg(x).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- Binary arithmetic ops --

    #[test]
    fn and() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.and2(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn or() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.or2(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn xor() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.xor2(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn add() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.add(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn sub() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.sub(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn mul() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.mul(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn udiv() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.udiv(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn sdiv() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.sdiv(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn urem() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.urem(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn srem() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.srem(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- Shift / rotate --

    #[test]
    fn shl() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.shl(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn lshr() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.lshr(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn ashr() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.ashr(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn rotate_left() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.rotate_left(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn rotate_right() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.rotate_right(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- Extension / extraction --

    #[test]
    fn zero_ext() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let ast = ctx.zero_ext(x, 8).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn sign_ext() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let ast = ctx.sign_ext(x, 8).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn extract() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let ast = ctx.extract(x, 6, 2).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- Concat --

    #[test]
    fn concat_2args() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.concat2(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn concat_3args() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let z = ctx.bvs("z", 8).unwrap();
        let ast = ctx.concat([x.clone(), y.clone(), z.clone()]).unwrap();
        // Z3's concat is binary, so Concat([x,y,z]) becomes concat(concat(x,y),z).
        // from_z3 reads the binary tree faithfully: Concat([Concat([x,y]), z]).
        let result = round_trip(&ctx, &ast).unwrap();
        let expected = ctx.concat2(ctx.concat2(x, y).unwrap(), z).unwrap();
        assert_eq!(expected, result);
    }

    // -- ITE --

    #[test]
    fn ite() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let x = ctx.bvs("x", 8).unwrap();
        let y = ctx.bvs("y", 8).unwrap();
        let ast = ctx.ite(c, x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- FP to BV conversions --

    #[test]
    fn fp_to_ieeebv() {
        let ctx = Context::new();
        let fp = ctx.fps("x", FSort::f32()).unwrap();
        let ast = ctx.fp_to_ieeebv(fp).unwrap();
        // fp_to_ieeebv has no from_z3 handler (Z3 DeclKind::FpaToIeeeBv is
        // not matched in bv::from_z3), so just verify to_z3 succeeds.
        assert!(ast.to_z3().is_ok());
    }

    #[test]
    fn fp_to_ubv() {
        let ctx = Context::new();
        let fp = ctx.fps("x", FSort::f32()).unwrap();
        let ast = ctx.fp_to_ubv(fp, 32, FPRM::TowardZero).unwrap();
        assert!(ast.to_z3().is_ok());
    }

    #[test]
    fn fp_to_sbv() {
        let ctx = Context::new();
        let fp = ctx.fps("x", FSort::f32()).unwrap();
        let ast = ctx.fp_to_sbv(fp, 32, FPRM::TowardZero).unwrap();
        assert!(ast.to_z3().is_ok());
    }

    // -- String-related BV ops --

    #[test]
    fn str_index_of_symbols() {
        let ctx = Context::new();
        let s = ctx.strings("s").unwrap();
        let t = ctx.strings("t").unwrap();
        let offset = ctx.bvv(BitVec::from((0, 64))).unwrap();
        let ast = ctx.str_index_of(s, t, offset).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn str_index_of_values() {
        let ctx = Context::new();
        let s = ctx.stringv("hello world").unwrap();
        let t = ctx.stringv("world").unwrap();
        let offset = ctx.bvv(BitVec::from((0, 64))).unwrap();
        let ast = ctx.str_index_of(s, t, offset).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn str_index_of_with_offset() {
        let ctx = Context::new();
        let s = ctx.strings("s").unwrap();
        let t = ctx.strings("t").unwrap();
        let offset = ctx.bvv(BitVec::from((5, 64))).unwrap();
        let ast = ctx.str_index_of(s, t, offset).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn str_to_bv_symbol() {
        let ctx = Context::new();
        let s = ctx.strings("s").unwrap();
        let ast = ctx.str_to_bv(s).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn str_to_bv_value() {
        let ctx = Context::new();
        let s = ctx.stringv("12345").unwrap();
        let ast = ctx.str_to_bv(s).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }
}
