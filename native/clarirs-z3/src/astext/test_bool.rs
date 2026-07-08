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
        let sym = ctx.bools("x").unwrap();
        let z3_ast = sym.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Uninterpreted);
        assert_eq!(z3_ast.symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn true_value() {
        let ctx = Context::new();
        let t = ctx.true_().unwrap();
        let z3_ast = t.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::True);
    }

    #[test]
    fn false_value() {
        let ctx = Context::new();
        let f = ctx.false_().unwrap();
        let z3_ast = f.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::False);
    }

    // -- Pure boolean ops --

    #[test]
    fn not() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let not_x = ctx.not(x).unwrap();
        let z3_ast = not_x.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Not);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn and_2args() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let and = ctx.and2(x, y).unwrap();
        let z3_ast = and.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::And);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn and_3args() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let z = ctx.bools("z").unwrap();
        let and = ctx.and([x, y, z]).unwrap();
        let z3_ast = and.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::And);
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
        assert_eq!(z3_ast.arg(2).unwrap().symbol_name().as_deref(), Some("z"));
    }

    #[test]
    fn or_2args() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let or = ctx.or2(x, y).unwrap();
        let z3_ast = or.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Or);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn or_3args() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let z = ctx.bools("z").unwrap();
        let or = ctx.or([x, y, z]).unwrap();
        let z3_ast = or.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Or);
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
        assert_eq!(z3_ast.arg(2).unwrap().symbol_name().as_deref(), Some("z"));
    }

    #[test]
    fn xor() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let xor = ctx.xor2(x, y).unwrap();
        let z3_ast = xor.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Xor);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn bool_eq() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let eq = ctx.eq_(x, y).unwrap();
        let z3_ast = eq.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Eq);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn bool_neq() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let neq = ctx.neq(x, y).unwrap();
        let z3_ast = neq.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Distinct);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("x"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("y"));
    }

    #[test]
    fn ite() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let t = ctx.bools("t").unwrap();
        let e = ctx.bools("e").unwrap();
        let ite = ctx.ite(c, t, e).unwrap();
        let z3_ast = ite.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), DeclKind::Ite);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("c"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("t"));
        assert_eq!(z3_ast.arg(2).unwrap().symbol_name().as_deref(), Some("e"));
    }

    // -- BV comparisons --

    #[test]
    fn bv_eq() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let eq = ctx.eq_(a, b).unwrap();
        let z3_ast = eq.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Eq);
    }

    #[test]
    fn bv_neq() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let neq = ctx.neq(a, b).unwrap();
        let z3_ast = neq.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Distinct);
    }

    #[test]
    fn ult() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let r = ctx.ult(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Ult);
    }

    #[test]
    fn ule() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let r = ctx.ule(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Uleq);
    }

    #[test]
    fn ugt() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let r = ctx.ugt(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Ugt);
    }

    #[test]
    fn uge() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let r = ctx.uge(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Ugeq);
    }

    #[test]
    fn slt() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let r = ctx.slt(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Slt);
    }

    #[test]
    fn sle() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let r = ctx.sle(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Sleq);
    }

    #[test]
    fn sgt() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let r = ctx.sgt(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Sgt);
    }

    #[test]
    fn sge() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let r = ctx.sge(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Sgeq);
    }

    // -- FP comparisons --

    #[test]
    fn fp_eq() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let r = ctx.fp_eq(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaEq);
    }

    #[test]
    fn fp_neq() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let r = ctx.fp_neq(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        // IEEE inequality lowers to not(fp.eq), not object-level `distinct`
        // (under which NaN would equal itself and +0 would differ from -0).
        assert_eq!(z3_ast.decl_kind(), DeclKind::Not);
        assert_eq!(z3_ast.arg(0).unwrap().decl_kind(), DeclKind::FpaEq);
    }

    #[test]
    fn fp_lt() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let r = ctx.fp_lt(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaLt);
    }

    #[test]
    fn fp_leq() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let r = ctx.fp_leq(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaLe);
    }

    #[test]
    fn fp_gt() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let r = ctx.fp_gt(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaGt);
    }

    #[test]
    fn fp_geq() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let r = ctx.fp_geq(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaGe);
    }

    #[test]
    fn fp_is_nan() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let r = ctx.fp_is_nan(a).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaIsNan);
    }

    #[test]
    fn fp_is_inf() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let r = ctx.fp_is_inf(a).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::FpaIsInf);
    }

    // -- String predicates --

    #[test]
    fn str_contains() {
        let ctx = Context::new();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let r = ctx.str_contains(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::SeqContains);
    }

    #[test]
    fn str_prefix_of() {
        let ctx = Context::new();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let r = ctx.str_prefix_of(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::SeqPrefix);
    }

    #[test]
    fn str_suffix_of() {
        let ctx = Context::new();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let r = ctx.str_suffix_of(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::SeqSuffix);
    }

    #[test]
    fn str_eq() {
        let ctx = Context::new();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let r = ctx.str_eq(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Eq);
    }

    #[test]
    fn str_neq() {
        let ctx = Context::new();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let r = ctx.str_neq(a, b).unwrap();
        let z3_ast = r.to_z3().unwrap();
        assert_eq!(z3_ast.decl_kind(), DeclKind::Distinct);
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
        let z3_ast = RcAst::mk_bool("x");
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        assert_eq!(result, ctx.bools("x").unwrap());
    }

    #[test]
    fn true_value() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let z3_ast = RcAst::try_from(Z3_mk_true(*z3_ctx)).unwrap();
            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            assert_eq!(result, ctx.true_().unwrap());
        });
    }

    #[test]
    fn false_value() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let z3_ast = RcAst::try_from(Z3_mk_false(*z3_ctx)).unwrap();
            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            assert_eq!(result, ctx.false_().unwrap());
        });
    }

    // -- Pure boolean ops --

    #[test]
    fn not() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bool("x");
            let not_z3 = RcAst::try_from(Z3_mk_not(*z3_ctx, *x)).unwrap();

            let result = AstRef::from_z3(&ctx, not_z3).unwrap();
            let expected = ctx.not(ctx.bools("x").unwrap()).unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn and_2args() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bool("x");
            let y = RcAst::mk_bool("y");
            let args = [*x, *y];
            let and_z3 = RcAst::try_from(Z3_mk_and(*z3_ctx, 2, args.as_ptr())).unwrap();

            let result = AstRef::from_z3(&ctx, and_z3).unwrap();
            let expected = ctx
                .and2(ctx.bools("x").unwrap(), ctx.bools("y").unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn or_2args() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bool("x");
            let y = RcAst::mk_bool("y");
            let args = [*x, *y];
            let or_z3 = RcAst::try_from(Z3_mk_or(*z3_ctx, 2, args.as_ptr())).unwrap();

            let result = AstRef::from_z3(&ctx, or_z3).unwrap();
            let expected = ctx
                .or2(ctx.bools("x").unwrap(), ctx.bools("y").unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn xor() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bool("x");
            let y = RcAst::mk_bool("y");
            let xor_z3 = RcAst::try_from(Z3_mk_xor(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, xor_z3).unwrap();
            let expected = ctx
                .xor2(ctx.bools("x").unwrap(), ctx.bools("y").unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn bool_eq() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bool("x");
            let y = RcAst::mk_bool("y");
            let eq_z3 = RcAst::try_from(Z3_mk_eq(*z3_ctx, *x, *y)).unwrap();

            let result = AstRef::from_z3(&ctx, eq_z3).unwrap();
            let expected = ctx
                .eq_(ctx.bools("x").unwrap(), ctx.bools("y").unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn bool_neq() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let x = RcAst::mk_bool("x");
            let y = RcAst::mk_bool("y");
            let args = [*x, *y];
            let neq_z3 = RcAst::try_from(Z3_mk_distinct(*z3_ctx, 2, args.as_ptr())).unwrap();

            let result = AstRef::from_z3(&ctx, neq_z3).unwrap();
            let expected = ctx
                .neq(ctx.bools("x").unwrap(), ctx.bools("y").unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn ite() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let c = RcAst::mk_bool("c");
            let t = RcAst::try_from(Z3_mk_true(*z3_ctx)).unwrap();
            let e = RcAst::try_from(Z3_mk_false(*z3_ctx)).unwrap();
            let ite_z3 = RcAst::try_from(Z3_mk_ite(*z3_ctx, *c, *t, *e)).unwrap();

            let result = AstRef::from_z3(&ctx, ite_z3).unwrap();
            let expected = ctx
                .ite(
                    ctx.bools("c").unwrap(),
                    ctx.true_().unwrap(),
                    ctx.false_().unwrap(),
                )
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    // -- BV comparisons --

    #[test]
    fn bv_eq() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_bv("a", 32);
            let b = RcAst::mk_bv("b", 32);
            let eq_z3 = RcAst::try_from(Z3_mk_eq(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, eq_z3).unwrap();
            let expected = ctx
                .eq_(ctx.bvs("a", 32).unwrap(), ctx.bvs("b", 32).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn bv_neq() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_bv("a", 32);
            let b = RcAst::mk_bv("b", 32);
            let args = [*a, *b];
            let neq_z3 = RcAst::try_from(Z3_mk_distinct(*z3_ctx, 2, args.as_ptr())).unwrap();

            let result = AstRef::from_z3(&ctx, neq_z3).unwrap();
            let expected = ctx
                .neq(ctx.bvs("a", 32).unwrap(), ctx.bvs("b", 32).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn ult() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_bv("a", 32);
            let b = RcAst::mk_bv("b", 32);
            let z3_ast = RcAst::try_from(Z3_mk_bvult(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .ult(ctx.bvs("a", 32).unwrap(), ctx.bvs("b", 32).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn ule() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_bv("a", 32);
            let b = RcAst::mk_bv("b", 32);
            let z3_ast = RcAst::try_from(Z3_mk_bvule(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .ule(ctx.bvs("a", 32).unwrap(), ctx.bvs("b", 32).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn ugt() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_bv("a", 32);
            let b = RcAst::mk_bv("b", 32);
            let z3_ast = RcAst::try_from(Z3_mk_bvugt(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .ugt(ctx.bvs("a", 32).unwrap(), ctx.bvs("b", 32).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn uge() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_bv("a", 32);
            let b = RcAst::mk_bv("b", 32);
            let z3_ast = RcAst::try_from(Z3_mk_bvuge(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .uge(ctx.bvs("a", 32).unwrap(), ctx.bvs("b", 32).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn slt() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_bv("a", 32);
            let b = RcAst::mk_bv("b", 32);
            let z3_ast = RcAst::try_from(Z3_mk_bvslt(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .slt(ctx.bvs("a", 32).unwrap(), ctx.bvs("b", 32).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn sle() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_bv("a", 32);
            let b = RcAst::mk_bv("b", 32);
            let z3_ast = RcAst::try_from(Z3_mk_bvsle(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .sle(ctx.bvs("a", 32).unwrap(), ctx.bvs("b", 32).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn sgt() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_bv("a", 32);
            let b = RcAst::mk_bv("b", 32);
            let z3_ast = RcAst::try_from(Z3_mk_bvsgt(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .sgt(ctx.bvs("a", 32).unwrap(), ctx.bvs("b", 32).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn sge() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_bv("a", 32);
            let b = RcAst::mk_bv("b", 32);
            let z3_ast = RcAst::try_from(Z3_mk_bvsge(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .sge(ctx.bvs("a", 32).unwrap(), ctx.bvs("b", 32).unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    // -- FP comparisons --

    #[test]
    fn fp_eq() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_fp("a", FSort::f32());
            let b = RcAst::mk_fp("b", FSort::f32());
            let z3_ast = RcAst::try_from(Z3_mk_fpa_eq(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .fp_eq(
                    ctx.fps("a", FSort::f32()).unwrap(),
                    ctx.fps("b", FSort::f32()).unwrap(),
                )
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn fp_neq() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_fp("a", FSort::f32());
            let b = RcAst::mk_fp("b", FSort::f32());
            let args = [*a, *b];
            let z3_ast = RcAst::try_from(Z3_mk_distinct(*z3_ctx, 2, args.as_ptr())).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .neq(
                    ctx.fps("a", FSort::f32()).unwrap(),
                    ctx.fps("b", FSort::f32()).unwrap(),
                )
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn fp_lt() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_fp("a", FSort::f32());
            let b = RcAst::mk_fp("b", FSort::f32());
            let z3_ast = RcAst::try_from(Z3_mk_fpa_lt(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .fp_lt(
                    ctx.fps("a", FSort::f32()).unwrap(),
                    ctx.fps("b", FSort::f32()).unwrap(),
                )
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn fp_leq() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_fp("a", FSort::f32());
            let b = RcAst::mk_fp("b", FSort::f32());
            let z3_ast = RcAst::try_from(Z3_mk_fpa_leq(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .fp_leq(
                    ctx.fps("a", FSort::f32()).unwrap(),
                    ctx.fps("b", FSort::f32()).unwrap(),
                )
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn fp_gt() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_fp("a", FSort::f32());
            let b = RcAst::mk_fp("b", FSort::f32());
            let z3_ast = RcAst::try_from(Z3_mk_fpa_gt(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .fp_gt(
                    ctx.fps("a", FSort::f32()).unwrap(),
                    ctx.fps("b", FSort::f32()).unwrap(),
                )
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn fp_geq() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_fp("a", FSort::f32());
            let b = RcAst::mk_fp("b", FSort::f32());
            let z3_ast = RcAst::try_from(Z3_mk_fpa_geq(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .fp_geq(
                    ctx.fps("a", FSort::f32()).unwrap(),
                    ctx.fps("b", FSort::f32()).unwrap(),
                )
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn fp_is_nan() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_fp("a", FSort::f32());
            let z3_ast = RcAst::try_from(Z3_mk_fpa_is_nan(*z3_ctx, *a)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx.fp_is_nan(ctx.fps("a", FSort::f32()).unwrap()).unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn fp_is_inf() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_fp("a", FSort::f32());
            let z3_ast = RcAst::try_from(Z3_mk_fpa_is_infinite(*z3_ctx, *a)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx.fp_is_inf(ctx.fps("a", FSort::f32()).unwrap()).unwrap();
            assert_eq!(result, expected);
        });
    }

    // -- String predicates --

    #[test]
    fn str_contains() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_string("a");
            let b = RcAst::mk_string("b");
            let z3_ast = RcAst::try_from(Z3_mk_seq_contains(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .str_contains(ctx.strings("a").unwrap(), ctx.strings("b").unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn str_prefix_of() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_string("a");
            let b = RcAst::mk_string("b");
            let z3_ast = RcAst::try_from(Z3_mk_seq_prefix(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .str_prefix_of(ctx.strings("a").unwrap(), ctx.strings("b").unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn str_suffix_of() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_string("a");
            let b = RcAst::mk_string("b");
            let z3_ast = RcAst::try_from(Z3_mk_seq_suffix(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .str_suffix_of(ctx.strings("a").unwrap(), ctx.strings("b").unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn str_eq() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_string("a");
            let b = RcAst::mk_string("b");
            let z3_ast = RcAst::try_from(Z3_mk_eq(*z3_ctx, *a, *b)).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .eq_(ctx.strings("a").unwrap(), ctx.strings("b").unwrap())
                .unwrap();
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn str_neq() {
        let ctx = Context::new();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let a = RcAst::mk_string("a");
            let b = RcAst::mk_string("b");
            let args = [*a, *b];
            let z3_ast = RcAst::try_from(Z3_mk_distinct(*z3_ctx, 2, args.as_ptr())).unwrap();

            let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
            let expected = ctx
                .neq(ctx.strings("a").unwrap(), ctx.strings("b").unwrap())
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
        let ast = ctx.bools("x").unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn true_value() {
        let ctx = Context::new();
        let ast = ctx.true_().unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn false_value() {
        let ctx = Context::new();
        let ast = ctx.false_().unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- Pure boolean ops --

    #[test]
    fn not() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let ast = ctx.not(x).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn and_2args() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let ast = ctx.and2(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn and_3args() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let z = ctx.bools("z").unwrap();
        let ast = ctx.and([x, y, z]).unwrap();
        // With n-ary And/Or support, a 3-arg And round-trips exactly.
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn or_2args() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let ast = ctx.or2(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn or_3args() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let z = ctx.bools("z").unwrap();
        let ast = ctx.or([x, y, z]).unwrap();
        // With n-ary And/Or support, a 3-arg Or round-trips exactly.
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn xor() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let ast = ctx.xor2(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn bool_eq() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let ast = ctx.eq_(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn bool_neq() {
        let ctx = Context::new();
        let x = ctx.bools("x").unwrap();
        let y = ctx.bools("y").unwrap();
        let ast = ctx.neq(x, y).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn ite() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let t = ctx.bools("t").unwrap();
        let e = ctx.bools("e").unwrap();
        let ast = ctx.ite(c, t, e).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- BV comparisons --

    #[test]
    fn bv_eq() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ast = ctx.eq_(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn bv_neq() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ast = ctx.neq(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn ult() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ast = ctx.ult(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn ule() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ast = ctx.ule(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn ugt() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ast = ctx.ugt(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn uge() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ast = ctx.uge(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn slt() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ast = ctx.slt(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn sle() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ast = ctx.sle(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn sgt() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ast = ctx.sgt(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn sge() {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32).unwrap();
        let b = ctx.bvs("b", 32).unwrap();
        let ast = ctx.sge(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- FP comparisons --

    #[test]
    fn fp_eq() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_eq(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_neq() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_neq(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_lt() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_lt(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_leq() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_leq(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_gt() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_gt(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_geq() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let b = ctx.fps("b", FSort::f32()).unwrap();
        let ast = ctx.fp_geq(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_is_nan() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let ast = ctx.fp_is_nan(a).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn fp_is_inf() {
        let ctx = Context::new();
        let a = ctx.fps("a", FSort::f32()).unwrap();
        let ast = ctx.fp_is_inf(a).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- String predicates --

    #[test]
    fn str_contains() {
        let ctx = Context::new();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let ast = ctx.str_contains(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn str_prefix_of() {
        let ctx = Context::new();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let ast = ctx.str_prefix_of(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn str_suffix_of() {
        let ctx = Context::new();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let ast = ctx.str_suffix_of(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn str_eq() {
        let ctx = Context::new();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let ast = ctx.str_eq(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn str_neq() {
        let ctx = Context::new();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let ast = ctx.str_neq(a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- StrIsDigit --
    // StrIsDigit is encoded as a composite Z3 expression, so round-trip
    // won't produce the same AST. We test that to_z3 succeeds.

    #[test]
    fn str_is_digit_symbol() {
        let ctx = Context::new();
        let s = ctx.strings("s").unwrap();
        let ast = ctx.str_is_digit(s).unwrap();
        assert!(ast.to_z3().is_ok());
    }

    #[test]
    fn str_is_digit_value() {
        let ctx = Context::new();
        let s = ctx.stringv("123").unwrap();
        let ast = ctx.str_is_digit(s).unwrap();
        assert!(ast.to_z3().is_ok());
    }
}
