use clarirs_core::prelude::*;
use clarirs_z3_sys as z3;

use super::AstExtZ3;
use crate::{Z3_CONTEXT, rc::RcAst};

fn round_trip<'c>(ctx: &'c Context<'c>, ast: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
    AstRef::from_z3(ctx, ast.to_z3()?)
}

/// Helper: check that a Z3 AST is a string with the given value.
fn assert_z3_string_value(ast: &RcAst, expected: &str) {
    Z3_CONTEXT.with(|&z3_ctx| unsafe {
        assert!(
            z3::is_string(z3_ctx, **ast),
            "expected a Z3 string constant"
        );
        let ptr = z3::get_string(z3_ctx, **ast);
        let got = std::ffi::CStr::from_ptr(ptr).to_str().unwrap();
        assert_eq!(got, expected);
    });
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
        let s = ctx.strings("x").unwrap();
        let z3_ast = s.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::Uninterpreted);
        assert_eq!(z3_ast.symbol_name().as_deref(), Some("x"));
    }

    #[test]
    fn value_simple() {
        let ctx = Context::new();
        let s = ctx.stringv("hello").unwrap();
        let z3_ast = s.to_z3().unwrap();

        Z3_CONTEXT.with(|&z3_ctx| unsafe {
            assert!(z3::is_string(z3_ctx, *z3_ast));
        });
        assert_z3_string_value(&z3_ast, "hello");
    }

    #[test]
    fn value_empty() {
        let ctx = Context::new();
        let s = ctx.stringv("").unwrap();
        let z3_ast = s.to_z3().unwrap();

        Z3_CONTEXT.with(|&z3_ctx| unsafe {
            assert!(z3::is_string(z3_ctx, *z3_ast));
        });
        assert_z3_string_value(&z3_ast, "");
    }

    #[test]
    fn value_with_spaces() {
        let ctx = Context::new();
        let s = ctx.stringv("hello world").unwrap();
        let z3_ast = s.to_z3().unwrap();
        assert_z3_string_value(&z3_ast, "hello world");
    }

    // -- StrConcat --

    #[test]
    fn concat() {
        let ctx = Context::new();
        let s1 = ctx.stringv("hello").unwrap();
        let s2 = ctx.stringv(" world").unwrap();
        let cat = ctx.str_concat(s1, s2).unwrap();
        let z3_ast = cat.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::SeqConcat);
        assert_eq!(z3_ast.num_args(), 2);
        assert_z3_string_value(&z3_ast.arg(0).unwrap(), "hello");
        assert_z3_string_value(&z3_ast.arg(1).unwrap(), " world");
    }

    #[test]
    fn concat_symbols() {
        let ctx = Context::new();
        let s1 = ctx.strings("a").unwrap();
        let s2 = ctx.strings("b").unwrap();
        let cat = ctx.str_concat(s1, s2).unwrap();
        let z3_ast = cat.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::SeqConcat);
        assert_eq!(z3_ast.num_args(), 2);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("a"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("b"));
    }

    // -- StrSubstr --

    #[test]
    fn substr() {
        let ctx = Context::new();
        let s = ctx.stringv("hello world").unwrap();
        let start = ctx.bvv(BitVec::from((6, 32))).unwrap();
        let length = ctx.bvv(BitVec::from((5, 32))).unwrap();
        let sub = ctx.str_substr(s, start, length).unwrap();
        let z3_ast = sub.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::SeqExtract);
        assert_eq!(z3_ast.num_args(), 3);
        assert_z3_string_value(&z3_ast.arg(0).unwrap(), "hello world");
    }

    // -- StrReplace --

    #[test]
    fn replace() {
        let ctx = Context::new();
        let s = ctx.stringv("hello world").unwrap();
        let pat = ctx.stringv("world").unwrap();
        let rep = ctx.stringv("there").unwrap();
        let replaced = ctx.str_replace(s, pat, rep).unwrap();
        let z3_ast = replaced.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::SeqReplace);
        assert_eq!(z3_ast.num_args(), 3);
        assert_z3_string_value(&z3_ast.arg(0).unwrap(), "hello world");
        assert_z3_string_value(&z3_ast.arg(1).unwrap(), "world");
        assert_z3_string_value(&z3_ast.arg(2).unwrap(), "there");
    }

    // -- ITE --

    #[test]
    fn ite() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let then = ctx.stringv("then").unwrap();
        let else_ = ctx.stringv("else").unwrap();
        let ite = ctx.ite(c, then, else_).unwrap();
        let z3_ast = ite.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::Ite);
        assert_eq!(z3_ast.num_args(), 3);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("c"));
        assert_z3_string_value(&z3_ast.arg(1).unwrap(), "then");
        assert_z3_string_value(&z3_ast.arg(2).unwrap(), "else");
    }

    #[test]
    fn ite_symbols() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let ite = ctx.ite(c, a, b).unwrap();
        let z3_ast = ite.to_z3().unwrap();

        assert_eq!(z3_ast.decl_kind(), z3::DeclKind::Ite);
        assert_eq!(z3_ast.arg(0).unwrap().symbol_name().as_deref(), Some("c"));
        assert_eq!(z3_ast.arg(1).unwrap().symbol_name().as_deref(), Some("a"));
        assert_eq!(z3_ast.arg(2).unwrap().symbol_name().as_deref(), Some("b"));
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
        let z3_ast = RcAst::mk_string("x");
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        let expected = ctx.strings("x").unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn value_simple() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_string_val("hello");
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        let expected = ctx.stringv("hello").unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn value_empty() {
        let ctx = Context::new();
        let z3_ast = RcAst::mk_string_val("");
        let result = AstRef::from_z3(&ctx, z3_ast).unwrap();
        let expected = ctx.stringv("").unwrap();
        assert_eq!(expected, result);
    }

    // -- StrConcat --

    #[test]
    fn concat() {
        let ctx = Context::new();
        let s1 = RcAst::mk_string_val("hello");
        let s2 = RcAst::mk_string_val(" world");
        let z3_cat = Z3_CONTEXT.with(|&z3_ctx| unsafe {
            let args = [*s1, *s2];
            RcAst::try_from(z3::mk_seq_concat(z3_ctx, 2, args.as_ptr())).unwrap()
        });
        let result = AstRef::from_z3(&ctx, z3_cat).unwrap();
        let expected = ctx
            .str_concat(
                ctx.stringv("hello").unwrap(),
                ctx.stringv(" world").unwrap(),
            )
            .unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn concat_symbols() {
        let ctx = Context::new();
        let s1 = RcAst::mk_string("a");
        let s2 = RcAst::mk_string("b");
        let z3_cat = Z3_CONTEXT.with(|&z3_ctx| unsafe {
            let args = [*s1, *s2];
            RcAst::try_from(z3::mk_seq_concat(z3_ctx, 2, args.as_ptr())).unwrap()
        });
        let result = AstRef::from_z3(&ctx, z3_cat).unwrap();
        let expected = ctx
            .str_concat(ctx.strings("a").unwrap(), ctx.strings("b").unwrap())
            .unwrap();
        assert_eq!(expected, result);
    }

    // -- StrSubstr --

    #[test]
    fn substr() {
        let ctx = Context::new();
        let s = RcAst::mk_string_val("hello world");
        let z3_sub = Z3_CONTEXT.with(|&z3_ctx| unsafe {
            let int_sort = z3::mk_int_sort(z3_ctx);
            let start_cstr = std::ffi::CString::new("6").unwrap();
            let start = z3::mk_numeral(z3_ctx, start_cstr.as_ptr(), int_sort);
            let len_cstr = std::ffi::CString::new("5").unwrap();
            let len = z3::mk_numeral(z3_ctx, len_cstr.as_ptr(), int_sort);
            RcAst::try_from(z3::mk_seq_extract(z3_ctx, *s, start, len)).unwrap()
        });
        let result = AstRef::from_z3(&ctx, z3_sub).unwrap();
        let expected = ctx
            .str_substr(
                ctx.stringv("hello world").unwrap(),
                ctx.bvv(BitVec::from((6, 64))).unwrap(),
                ctx.bvv(BitVec::from((5, 64))).unwrap(),
            )
            .unwrap();
        assert_eq!(expected, result);
    }

    // -- StrReplace --

    #[test]
    fn replace() {
        let ctx = Context::new();
        let s = RcAst::mk_string_val("hello world");
        let pat = RcAst::mk_string_val("world");
        let rep = RcAst::mk_string_val("there");
        let z3_rep = Z3_CONTEXT.with(|&z3_ctx| unsafe {
            RcAst::try_from(z3::mk_seq_replace(z3_ctx, *s, *pat, *rep)).unwrap()
        });
        let result = AstRef::from_z3(&ctx, z3_rep).unwrap();
        let expected = ctx
            .str_replace(
                ctx.stringv("hello world").unwrap(),
                ctx.stringv("world").unwrap(),
                ctx.stringv("there").unwrap(),
            )
            .unwrap();
        assert_eq!(expected, result);
    }

    // -- ITE --

    #[test]
    fn ite() {
        let ctx = Context::new();
        let c = RcAst::mk_bool("c");
        let then = RcAst::mk_string_val("then");
        let else_ = RcAst::mk_string_val("else");
        let z3_ite = Z3_CONTEXT.with(|&z3_ctx| unsafe {
            RcAst::try_from(z3::mk_ite(z3_ctx, *c, *then, *else_)).unwrap()
        });
        let result = AstRef::from_z3(&ctx, z3_ite).unwrap();
        let expected = ctx
            .ite(
                ctx.bools("c").unwrap(),
                ctx.stringv("then").unwrap(),
                ctx.stringv("else").unwrap(),
            )
            .unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    fn ite_symbols() {
        let ctx = Context::new();
        let c = RcAst::mk_bool("c");
        let a = RcAst::mk_string("a");
        let b = RcAst::mk_string("b");
        let z3_ite = Z3_CONTEXT
            .with(|&z3_ctx| unsafe { RcAst::try_from(z3::mk_ite(z3_ctx, *c, *a, *b)).unwrap() });
        let result = AstRef::from_z3(&ctx, z3_ite).unwrap();
        let expected = ctx
            .ite(
                ctx.bools("c").unwrap(),
                ctx.strings("a").unwrap(),
                ctx.strings("b").unwrap(),
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
    fn symbol() {
        let ctx = Context::new();
        let ast = ctx.strings("x").unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn symbol_long_name() {
        let ctx = Context::new();
        let ast = ctx.strings("my_string_variable").unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_simple() {
        let ctx = Context::new();
        let ast = ctx.stringv("hello").unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_empty() {
        let ctx = Context::new();
        let ast = ctx.stringv("").unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_with_spaces() {
        let ctx = Context::new();
        let ast = ctx.stringv("hello world").unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_single_char() {
        let ctx = Context::new();
        let ast = ctx.stringv("a").unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_digits() {
        let ctx = Context::new();
        let ast = ctx.stringv("12345").unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn value_special_chars() {
        let ctx = Context::new();
        let ast = ctx.stringv("hello\tworld\n").unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- StrConcat --

    #[test]
    fn concat_values() {
        let ctx = Context::new();
        let s1 = ctx.stringv("hello").unwrap();
        let s2 = ctx.stringv(" world").unwrap();
        let ast = ctx.str_concat(s1, s2).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn concat_symbols() {
        let ctx = Context::new();
        let s1 = ctx.strings("a").unwrap();
        let s2 = ctx.strings("b").unwrap();
        let ast = ctx.str_concat(s1, s2).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn concat_mixed() {
        let ctx = Context::new();
        let s1 = ctx.strings("x").unwrap();
        let s2 = ctx.stringv("_suffix").unwrap();
        let ast = ctx.str_concat(s1, s2).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn concat_empty() {
        let ctx = Context::new();
        let s1 = ctx.stringv("hello").unwrap();
        let s2 = ctx.stringv("").unwrap();
        let ast = ctx.str_concat(s1, s2).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- StrSubstr --

    #[test]
    fn substr_value() {
        let ctx = Context::new();
        let s = ctx.stringv("hello world").unwrap();
        let start = ctx.bvv(BitVec::from((6, 64))).unwrap();
        let length = ctx.bvv(BitVec::from((5, 64))).unwrap();
        let ast = ctx.str_substr(s, start, length).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn substr_symbol() {
        let ctx = Context::new();
        let s = ctx.strings("s").unwrap();
        let start = ctx.bvv(BitVec::from((0, 64))).unwrap();
        let length = ctx.bvv(BitVec::from((3, 64))).unwrap();
        let ast = ctx.str_substr(s, start, length).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn substr_from_start() {
        let ctx = Context::new();
        let s = ctx.stringv("abcdef").unwrap();
        let start = ctx.bvv(BitVec::from((0, 64))).unwrap();
        let length = ctx.bvv(BitVec::from((3, 64))).unwrap();
        let ast = ctx.str_substr(s, start, length).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- StrReplace --

    #[test]
    fn replace_values() {
        let ctx = Context::new();
        let s = ctx.stringv("hello world").unwrap();
        let pat = ctx.stringv("world").unwrap();
        let rep = ctx.stringv("there").unwrap();
        let ast = ctx.str_replace(s, pat, rep).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn replace_symbols() {
        let ctx = Context::new();
        let s = ctx.strings("s").unwrap();
        let pat = ctx.strings("p").unwrap();
        let rep = ctx.strings("r").unwrap();
        let ast = ctx.str_replace(s, pat, rep).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn replace_with_empty() {
        let ctx = Context::new();
        let s = ctx.stringv("hello world").unwrap();
        let pat = ctx.stringv("world").unwrap();
        let rep = ctx.stringv("").unwrap();
        let ast = ctx.str_replace(s, pat, rep).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- ITE --

    #[test]
    fn ite_values() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let then = ctx.stringv("then").unwrap();
        let else_ = ctx.stringv("else").unwrap();
        let ast = ctx.ite(c, then, else_).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn ite_symbols() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let a = ctx.strings("a").unwrap();
        let b = ctx.strings("b").unwrap();
        let ast = ctx.ite(c, a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn ite_mixed() {
        let ctx = Context::new();
        let c = ctx.bools("c").unwrap();
        let a = ctx.strings("x").unwrap();
        let b = ctx.stringv("default").unwrap();
        let ast = ctx.ite(c, a, b).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    // -- BVToStr --

    #[test]
    fn bv_to_str_symbol() {
        let ctx = Context::new();
        let bv = ctx.bvs("x", 64).unwrap();
        let ast = ctx.bv_to_str(bv).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }

    #[test]
    fn bv_to_str_value() {
        let ctx = Context::new();
        let bv = ctx.bvv(BitVec::from((42, 64))).unwrap();
        let ast = ctx.bv_to_str(bv).unwrap();
        assert_eq!(ast, round_trip(&ctx, &ast).unwrap());
    }
}
