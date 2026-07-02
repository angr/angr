use std::fmt;
use std::sync::Arc;

use crate::{algorithms::walk_post_order, prelude::*};

/// Converts an FPRM rounding mode to its SMT-LIB 2.6 identifier.
fn fprm_to_smtlib(fprm: &FPRM) -> &'static str {
    match fprm {
        FPRM::NearestTiesToEven => "RNE",
        FPRM::NearestTiesToAway => "RNA",
        FPRM::TowardPositive => "RTP",
        FPRM::TowardNegative => "RTN",
        FPRM::TowardZero => "RTZ",
    }
}

/// Renders a single node to SMT-LIB given its already-rendered children. A
/// single match over the unified op enum replaces the previous per-sort
/// functions.
fn to_smtlib_op(ast: &AstRef<'_>, children: &[String]) -> String {
    match ast.op() {
        // Booleans
        AstOp::BoolS(s) => s.to_string(),
        AstOp::BoolV(b) => b.to_string(),
        AstOp::Eq(a, _) => {
            if a.ast_type().is_float() {
                format!("(fp.eq {} {})", children[0], children[1])
            } else {
                format!("(= {} {})", children[0], children[1])
            }
        }
        AstOp::Neq(a, _) => {
            if a.ast_type().is_float() {
                format!("(not (fp.eq {} {}))", children[0], children[1])
            } else {
                format!("(distinct {} {})", children[0], children[1])
            }
        }
        AstOp::ULT(..) => format!("(bvult {} {})", children[0], children[1]),
        AstOp::ULE(..) => format!("(bvule {} {})", children[0], children[1]),
        AstOp::UGT(..) => format!("(bvugt {} {})", children[0], children[1]),
        AstOp::UGE(..) => format!("(bvuge {} {})", children[0], children[1]),
        AstOp::SLT(..) => format!("(bvslt {} {})", children[0], children[1]),
        AstOp::SLE(..) => format!("(bvsle {} {})", children[0], children[1]),
        AstOp::SGT(..) => format!("(bvsgt {} {})", children[0], children[1]),
        AstOp::SGE(..) => format!("(bvsge {} {})", children[0], children[1]),
        AstOp::FpLt(..) => format!("(fp.lt {} {})", children[0], children[1]),
        AstOp::FpLeq(..) => format!("(fp.leq {} {})", children[0], children[1]),
        AstOp::FpGt(..) => format!("(fp.gt {} {})", children[0], children[1]),
        AstOp::FpGeq(..) => format!("(fp.geq {} {})", children[0], children[1]),
        AstOp::FpIsNan(..) => format!("(fp.isNaN {})", children[0]),
        AstOp::FpIsInf(..) => format!("(fp.isInfinite {})", children[0]),
        AstOp::StrContains(..) => format!("(str.contains {} {})", children[0], children[1]),
        AstOp::StrPrefixOf(..) => format!("(str.prefixof {} {})", children[0], children[1]),
        AstOp::StrSuffixOf(..) => format!("(str.suffixof {} {})", children[0], children[1]),
        AstOp::StrIsDigit(..) => format!("(str.is_digit {})", children[0]),

        // Polymorphic
        AstOp::Not(..) if ast.ast_type().is_bool() => format!("(not {})", children[0]),
        AstOp::Not(..) => format!("(bvnot {})", children[0]),
        AstOp::ITE(..) => format!("(ite {} {} {})", children[0], children[1], children[2]),
        AstOp::And(..) if ast.ast_type().is_bool() => format!("(and {})", children.join(" ")),
        AstOp::Or(..) if ast.ast_type().is_bool() => format!("(or {})", children.join(" ")),
        AstOp::And(..) => format!(
            "(bvand{})",
            children
                .iter()
                .fold(String::new(), |acc, c| format!("{acc} {c}"))
        ),
        AstOp::Or(..) => format!(
            "(bvor{})",
            children
                .iter()
                .fold(String::new(), |acc, c| format!("{acc} {c}"))
        ),

        // Bitvectors
        AstOp::BVS(s, _) => s.to_string(),
        AstOp::BVV(bit_vec) => format!("(_ bv{} {})", bit_vec.to_biguint(), bit_vec.len()),
        AstOp::Xor(..) if ast.ast_type().is_bool() => format!("(xor {})", children.join(" ")),
        AstOp::Xor(..) => format!(
            "(bvxor{})",
            children
                .iter()
                .fold(String::new(), |acc, c| format!("{acc} {c}"))
        ),
        AstOp::Neg(..) => format!("(bvneg {})", children[0]),
        AstOp::Add(..) => format!(
            "(bvadd{})",
            children
                .iter()
                .fold(String::new(), |acc, c| format!("{acc} {c}"))
        ),
        AstOp::Sub(..) => format!("(bvsub {} {})", children[0], children[1]),
        AstOp::Mul(..) => format!(
            "(bvmul{})",
            children
                .iter()
                .fold(String::new(), |acc, c| format!("{acc} {c}"))
        ),
        AstOp::UDiv(..) => format!("(bvudiv {} {})", children[0], children[1]),
        AstOp::SDiv(..) => format!("(bvsdiv {} {})", children[0], children[1]),
        AstOp::URem(..) => format!("(bvurem {} {})", children[0], children[1]),
        AstOp::SRem(..) => format!("(bvsrem {} {})", children[0], children[1]),
        AstOp::ShL(..) => format!("(bvshl {} {})", children[0], children[1]),
        AstOp::LShR(..) => format!("(bvlshr {} {})", children[0], children[1]),
        AstOp::AShR(..) => format!("(bvashr {} {})", children[0], children[1]),
        AstOp::RotateLeft(..) => format!("(ext_rotate_left {} {})", children[0], children[1]),
        AstOp::RotateRight(..) => format!("(ext_rotate_right {} {})", children[0], children[1]),
        AstOp::ZeroExt(_, size) => format!("((_ zero_extend {}) {})", size, children[0]),
        AstOp::SignExt(_, size) => format!("((_ sign_extend {}) {})", size, children[0]),
        AstOp::Extract(_, high, low) => format!("((_ extract {} {}) {})", high, low, children[0]),
        AstOp::Concat(..) => format!("(concat {})", children.join(" ")),
        AstOp::ByteReverse(..) => format!("(bvreverse {})", children[0]),
        AstOp::FpToIEEEBV(..) => format!("(fp.to_ieee_bv {})", children[0]),
        AstOp::FpToUBV(_, size, fprm) => format!(
            "((_ fp.to_ubv {}) {} {})",
            size,
            fprm_to_smtlib(fprm),
            children[0]
        ),
        AstOp::FpToSBV(_, size, fprm) => format!(
            "((_ fp.to_sbv {}) {} {})",
            size,
            fprm_to_smtlib(fprm),
            children[0]
        ),
        AstOp::StrLen(..) => format!("(str.len {})", children[0]),
        AstOp::StrIndexOf(..) => format!(
            "(str.indexof {} {} {})",
            children[0], children[1], children[2]
        ),
        AstOp::StrToBV(..) => format!("(str.to_bv {})", children[0]),
        AstOp::Union(..) => format!("(vsaunion {} {})", children[0], children[1]),
        AstOp::Intersection(..) => format!("(vsaintersection {} {})", children[0], children[1]),
        AstOp::Widen(..) => format!("(vsawiden {} {})", children[0], children[1]),

        // Floats
        AstOp::FPS(s, _) => s.to_string(),
        AstOp::FPV(float) => {
            let sign = if float.sign() { "#b1" } else { "#b0" };
            let exp = float.exponent();
            let sig = float.mantissa();
            let exp_str = format!("{:0>width$b}", exp.to_biguint(), width = exp.len() as usize);
            let sig_str = format!("{:0>width$b}", sig.to_biguint(), width = sig.len() as usize);
            format!("(fp {sign} #b{exp_str} #b{sig_str})")
        }
        AstOp::FpFP(..) => format!("(fp {} {} {})", children[0], children[1], children[2]),
        AstOp::FpNeg(..) => format!("(fp.neg {})", children[0]),
        AstOp::FpAbs(..) => format!("(fp.abs {})", children[0]),
        AstOp::FpAdd(_, _, fprm) => format!(
            "(fp.add {} {} {})",
            fprm_to_smtlib(fprm),
            children[0],
            children[1]
        ),
        AstOp::FpSub(_, _, fprm) => format!(
            "(fp.sub {} {} {})",
            fprm_to_smtlib(fprm),
            children[0],
            children[1]
        ),
        AstOp::FpMul(_, _, fprm) => format!(
            "(fp.mul {} {} {})",
            fprm_to_smtlib(fprm),
            children[0],
            children[1]
        ),
        AstOp::FpDiv(_, _, fprm) => format!(
            "(fp.div {} {} {})",
            fprm_to_smtlib(fprm),
            children[0],
            children[1]
        ),
        AstOp::FpSqrt(_, fprm) => format!("(fp.sqrt {} {})", fprm_to_smtlib(fprm), children[0]),
        AstOp::FpToFp(_, fsort, fprm) => format!(
            "((_ to_fp {} {}) {} {})",
            fsort.exponent,
            fsort.mantissa,
            fprm_to_smtlib(fprm),
            children[0]
        ),
        AstOp::BvToFp(_, fsort) => format!(
            "((_ to_fp {} {}) {})",
            fsort.exponent, fsort.mantissa, children[0]
        ),
        AstOp::BvToFpSigned(_, fsort, fprm) => format!(
            "((_ to_fp {} {}) {} {})",
            fsort.exponent,
            fsort.mantissa,
            fprm_to_smtlib(fprm),
            children[0]
        ),
        AstOp::BvToFpUnsigned(_, fsort, fprm) => format!(
            "((_ to_fp_unsigned {} {}) {} {})",
            fsort.exponent,
            fsort.mantissa,
            fprm_to_smtlib(fprm),
            children[0]
        ),

        // Strings
        AstOp::StringS(s) => s.to_string(),
        AstOp::StringV(s) => format!("\"{}\"", s.replace('"', "\\\"")),
        AstOp::StrConcat(..) => format!("(str.++ {} {})", children[0], children[1]),
        AstOp::StrSubstr(..) => format!(
            "(str.substr {} {} {})",
            children[0], children[1], children[2]
        ),
        AstOp::StrReplace(..) => format!(
            "(str.replace {} {} {})",
            children[0], children[1], children[2]
        ),
        AstOp::BVToStr(..) => format!("(str.from_bv {})", children[0]),
    }
}

/// Depth-limited SMT-LIB rendering. When `remaining_depth` reaches 0,
/// children are replaced with `...` instead of being recursed into.
fn to_smtlib_limited(ast: &AstRef<'_>, remaining_depth: usize) -> String {
    let children: Vec<String> = if remaining_depth == 0 {
        // At depth limit: replace every child with "..."
        (0..ast.child_iter().len())
            .map(|_| "...".to_string())
            .collect()
    } else {
        ast.child_iter()
            .map(|child| to_smtlib_limited(&child, remaining_depth - 1))
            .collect()
    };
    to_smtlib_op(ast, &children)
}

impl<'c> AstNode<'c> {
    /// Converts the AST to an SMT-LIB 2.6 string representation.
    pub fn to_smtlib(self: &Arc<Self>) -> String {
        walk_post_order(
            self.clone(),
            |node, children| Ok(to_smtlib_op(&node, children)),
            &(),
        )
        .expect("infallible")
    }

    /// Returns a depth-limited SMT-LIB representation. Children beyond
    /// `max_depth` levels are replaced with `...`.
    pub fn to_smtlib_shallow(self: &Arc<Self>, max_depth: usize) -> String {
        to_smtlib_limited(self, max_depth)
    }
}

impl fmt::Display for SmtLibDisplay<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_smtlib())
    }
}

/// Wrapper to display an AST as SMT-LIB via `fmt::Display`.
///
/// # Example
/// ```ignore
/// use clarirs_core::smtlib::SmtLibDisplay;
/// let ast = ctx.bvs("x", 64).unwrap();
/// println!("{}", SmtLibDisplay(&ast));
/// ```
pub struct SmtLibDisplay<'a, 'c>(pub &'a AstRef<'c>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool_value() {
        let ctx = Context::new();
        let t = ctx.true_().unwrap();
        let f = ctx.false_().unwrap();
        assert_eq!(t.to_smtlib(), "true");
        assert_eq!(f.to_smtlib(), "false");
    }

    #[test]
    fn test_bool_ops() {
        let ctx = Context::new();
        let a = ctx.bools("a").unwrap();
        let b = ctx.bools("b").unwrap();

        let not_a = ctx.not(&a).unwrap();
        assert_eq!(not_a.to_smtlib(), "(not a)");

        let and = ctx.and([a.clone(), b.clone()]).unwrap();
        assert_eq!(and.to_smtlib(), "(and a b)");

        let or = ctx.or([a.clone(), b.clone()]).unwrap();
        assert_eq!(or.to_smtlib(), "(or a b)");
    }

    #[test]
    fn test_bv_symbol_and_value() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32).unwrap();
        assert_eq!(x.to_smtlib(), "x");

        let v = ctx.bvv(BitVec::from((42, 64))).unwrap();
        assert_eq!(v.to_smtlib(), "(_ bv42 64)");
    }

    #[test]
    fn test_bv_arithmetic() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64).unwrap();
        let y = ctx.bvs("y", 64).unwrap();

        let add = ctx.add(&x, &y).unwrap();
        assert_eq!(add.to_smtlib(), "(bvadd x y)");

        let sub = ctx.sub(&x, &y).unwrap();
        assert_eq!(sub.to_smtlib(), "(bvsub x y)");
    }

    #[test]
    fn test_bv_comparisons() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64).unwrap();
        let y = ctx.bvs("y", 64).unwrap();

        let ult = ctx.ult(&x, &y).unwrap();
        assert_eq!(ult.to_smtlib(), "(bvult x y)");

        let sge = ctx.sge(&x, &y).unwrap();
        assert_eq!(sge.to_smtlib(), "(bvsge x y)");
    }

    #[test]
    fn test_neq_uses_distinct() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64).unwrap();
        let y = ctx.bvs("y", 64).unwrap();

        let neq = ctx.neq(&x, &y).unwrap();
        assert_eq!(neq.to_smtlib(), "(distinct x y)");
    }

    #[test]
    fn test_extract_and_extend() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32).unwrap();

        let ext = ctx.extract(&x, 15, 8).unwrap();
        assert_eq!(ext.to_smtlib(), "((_ extract 15 8) x)");

        let zext = ctx.zero_ext(&x, 32).unwrap();
        assert_eq!(zext.to_smtlib(), "((_ zero_extend 32) x)");

        let sext = ctx.sign_ext(&x, 32).unwrap();
        assert_eq!(sext.to_smtlib(), "((_ sign_extend 32) x)");
    }

    #[test]
    fn test_ite() {
        let ctx = Context::new();
        let cond = ctx.bools("c").unwrap();
        let x = ctx.bvs("x", 64).unwrap();
        let y = ctx.bvs("y", 64).unwrap();

        let ite = ctx.ite(&cond, &x, &y).unwrap();
        assert_eq!(ite.to_smtlib(), "(ite c x y)");
    }

    #[test]
    fn test_string_value() {
        let ctx = Context::new();
        let s = ctx.stringv("hello").unwrap();
        assert_eq!(s.to_smtlib(), "\"hello\"");
    }

    #[test]
    fn test_string_value_with_quotes() {
        let ctx = Context::new();
        let s = ctx.stringv("say \"hi\"").unwrap();
        assert_eq!(s.to_smtlib(), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn test_smtlib_display_wrapper() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64).unwrap();
        let displayed = format!("{}", SmtLibDisplay(&x));
        assert_eq!(displayed, "x");
    }

    #[test]
    fn test_shallow_repr_leaf() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64).unwrap();
        // Leaf nodes are unchanged regardless of depth
        assert_eq!(x.to_smtlib_shallow(0), "x");
        assert_eq!(x.to_smtlib_shallow(2), "x");
    }

    #[test]
    fn test_shallow_repr_depth_limit() {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64).unwrap();
        let y = ctx.bvs("y", 64).unwrap();
        let add = ctx.add(&x, &y).unwrap();
        let neg = ctx.neg(&add).unwrap();

        // Full repr
        assert_eq!(neg.to_smtlib(), "(bvneg (bvadd x y))");

        // Depth 0: children replaced with ...
        assert_eq!(neg.to_smtlib_shallow(0), "(bvneg ...)");

        // Depth 1: one level of children shown, their children replaced
        assert_eq!(neg.to_smtlib_shallow(1), "(bvneg (bvadd ... ...))");

        // Depth 2: full tree (only 2 deep)
        assert_eq!(neg.to_smtlib_shallow(2), "(bvneg (bvadd x y))");
    }
}
