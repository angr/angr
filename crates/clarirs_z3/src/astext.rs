use std::ffi::CStr;

use clarirs_core::{algorithms::walk_post_order, prelude::*};
use clarirs_z3_sys as z3;
use regex::Regex;

use crate::{Z3_AST_CACHE, Z3_CONTEXT, check_z3_error, rc::RcAst};

#[cfg(test)]
mod test_bool;
#[cfg(test)]
mod test_bv;
#[cfg(test)]
mod test_float;
#[cfg(test)]
mod test_string;

fn child(children: &[RcAst], index: usize) -> Result<&RcAst, ClarirsError> {
    children
        .get(index)
        .ok_or(ClarirsError::InvalidArguments(format!(
            "missing child at index {index}"
        )))
}

macro_rules! unop {
    ($z3:ident, $children:ident, $op:ident) => {{
        let a = crate::astext::child($children, 0)?;
        RcAst::try_from(z3::$op($z3, **a))?
    }};
}

macro_rules! binop {
    ($z3:ident, $children:ident, $op:ident) => {{
        let a = crate::astext::child($children, 0)?;
        let b = crate::astext::child($children, 1)?;
        RcAst::try_from(z3::$op($z3, **a, **b))?
    }};
}

macro_rules! naryop {
    ($z3:ident, $children:ident, $op:ident) => {{
        let mut result = crate::astext::child($children, 0)?.clone();
        for i in 1..$children.len() {
            let b = crate::astext::child($children, i)?;
            result = RcAst::try_from(z3::$op($z3, *result, **b))?;
        }
        result
    }};
}

// Conversion helpers shared by the to_z3/from_z3 implementations.

fn fprm_to_z3(rm: FPRM) -> Result<RcAst, ClarirsError> {
    RcAst::try_from(Z3_CONTEXT.with(|&z3_ctx| unsafe {
        match rm {
            FPRM::NearestTiesToEven => z3::mk_fpa_rne(z3_ctx),
            FPRM::TowardPositive => z3::mk_fpa_rtp(z3_ctx),
            FPRM::TowardNegative => z3::mk_fpa_rtn(z3_ctx),
            FPRM::TowardZero => z3::mk_fpa_rtz(z3_ctx),
            FPRM::NearestTiesToAway => z3::mk_fpa_rna(z3_ctx),
        }
    }))
}

fn fsort_to_z3(sort: FSort) -> z3::Sort {
    Z3_CONTEXT.with(|&z3_ctx| unsafe { z3::mk_fpa_sort(z3_ctx, sort.exponent, sort.mantissa + 1) })
}

fn parse_fprm_from_z3(z3_ctx: z3::Context, ast: z3::Ast) -> Result<FPRM, ClarirsError> {
    unsafe {
        let app = z3::to_app(z3_ctx, ast);
        let decl = z3::get_app_decl(z3_ctx, app);
        match z3::get_decl_kind(z3_ctx, decl) {
            z3::DeclKind::FpaRmNearestTiesToEven => Ok(FPRM::NearestTiesToEven),
            z3::DeclKind::FpaRmTowardPositive => Ok(FPRM::TowardPositive),
            z3::DeclKind::FpaRmTowardNegative => Ok(FPRM::TowardNegative),
            z3::DeclKind::FpaRmTowardZero => Ok(FPRM::TowardZero),
            z3::DeclKind::FpaRmNearestTiesToAway => Ok(FPRM::NearestTiesToAway),
            _ => Err(ClarirsError::ConversionError(
                "Unknown rounding mode".to_string(),
            )),
        }
    }
}

fn mk_bv2int(bv: &RcAst) -> Result<RcAst, ClarirsError> {
    Z3_CONTEXT.with(|&z3_ctx| unsafe { RcAst::try_from(z3::mk_bv2int(z3_ctx, **bv, false)) })
}

fn decode_custom_unicode(input: &str) -> String {
    let re = Regex::new(r"\\u\{([0-9a-fA-F]+)\}").unwrap();
    re.replace_all(input, |caps: &regex::Captures| {
        let num = u32::from_str_radix(&caps[1], 16).unwrap();
        std::char::from_u32(num).unwrap().to_string()
    })
    .into_owned()
}

pub(crate) trait AstExtZ3<'c>: HasContext<'c> + Sized {
    fn to_z3(&self) -> Result<RcAst, ClarirsError>;
    fn from_z3(ctx: &'c Context<'c>, ast: impl Into<RcAst>) -> Result<Self, ClarirsError>;
    fn simplify_z3(&self) -> Result<Self, ClarirsError>;
}

impl<'c> AstExtZ3<'c> for AstRef<'c> {
    fn simplify_z3(&self) -> Result<Self, ClarirsError> {
        let ast = self.simplify()?.to_z3()?;
        Z3_CONTEXT.with(|ctx| unsafe {
            let simplified_ast = RcAst::try_from(z3::simplify(*ctx, *ast))?;
            Self::from_z3(self.context(), simplified_ast)
        })
    }

    fn to_z3(&self) -> Result<RcAst, ClarirsError> {
        // Builds a Z3 AST for a single node given its already-converted
        // children. A single match over the unified op enum handles all sorts;
        // polymorphic ops (Not/And/Or/Xor) pick the boolean or bitvector Z3
        // constructor from the node's type.
        Z3_AST_CACHE.with(|cache| {
            walk_post_order(
                self.clone(),
                |ast, children| {
                    Z3_CONTEXT.with(|&z3_ctx| unsafe {
                        Ok(match ast.op() {
                            // Polymorphic boolean/bitvector operations
                            AstOp::Not(..) => {
                                if ast.ast_type().is_bool() {
                                    unop!(z3_ctx, children, mk_not)
                                } else {
                                    unop!(z3_ctx, children, mk_bvnot)
                                }
                            }
                            AstOp::And(..) => {
                                if ast.ast_type().is_bool() {
                                    let args: Vec<_> = children.iter().map(|c| **c).collect();
                                    z3::mk_and(z3_ctx, args.len() as u32, args.as_ptr())
                                        .try_into()?
                                } else {
                                    naryop!(z3_ctx, children, mk_bvand)
                                }
                            }
                            AstOp::Or(..) => {
                                if ast.ast_type().is_bool() {
                                    let args: Vec<_> = children.iter().map(|c| **c).collect();
                                    z3::mk_or(z3_ctx, args.len() as u32, args.as_ptr())
                                        .try_into()?
                                } else {
                                    naryop!(z3_ctx, children, mk_bvor)
                                }
                            }
                            AstOp::Xor(..) => {
                                if ast.ast_type().is_bool() {
                                    naryop!(z3_ctx, children, mk_xor)
                                } else {
                                    naryop!(z3_ctx, children, mk_bvxor)
                                }
                            }
                            AstOp::ITE(..) => {
                                let cond = child(children, 0)?;
                                let then = child(children, 1)?;
                                let else_ = child(children, 2)?;
                                z3::mk_ite(z3_ctx, **cond, **then, **else_).try_into()?
                            }

                            // Boolean leaves and predicates
                            AstOp::BoolS(s) => {
                                let s_cstr = std::ffi::CString::new(s.as_str()).unwrap();
                                let sym = z3::mk_string_symbol(z3_ctx, s_cstr.as_ptr());
                                let sort = z3::mk_bool_sort(z3_ctx);
                                RcAst::try_from(z3::mk_const(z3_ctx, sym, sort))?
                            }
                            AstOp::BoolV(b) => if *b {
                                z3::mk_true(z3_ctx)
                            } else {
                                z3::mk_false(z3_ctx)
                            }
                            .try_into()?,
                            // Equality (any sort): floats use fp.eq, everything else structural =.
                            AstOp::Eq(a, _) => {
                                if a.ast_type().is_float() {
                                    binop!(z3_ctx, children, mk_fpa_eq)
                                } else {
                                    binop!(z3_ctx, children, mk_eq)
                                }
                            }
                            AstOp::Neq(a, _) => {
                                if a.ast_type().is_float() {
                                    // IEEE inequality. Z3's `distinct` on floats is object
                                    // identity (NaN would equal NaN, +0 would differ from -0),
                                    // so emit not(fp.eq) instead.
                                    let eq = binop!(z3_ctx, children, mk_fpa_eq);
                                    z3::mk_not(z3_ctx, *eq).try_into()?
                                } else {
                                    let a = child(children, 0)?;
                                    let b = child(children, 1)?;
                                    z3::mk_distinct(z3_ctx, 2, [**a, **b].as_ptr()).try_into()?
                                }
                            }
                            AstOp::ULT(..) => binop!(z3_ctx, children, mk_bvult),
                            AstOp::ULE(..) => binop!(z3_ctx, children, mk_bvule),
                            AstOp::UGT(..) => binop!(z3_ctx, children, mk_bvugt),
                            AstOp::UGE(..) => binop!(z3_ctx, children, mk_bvuge),
                            AstOp::SLT(..) => binop!(z3_ctx, children, mk_bvslt),
                            AstOp::SLE(..) => binop!(z3_ctx, children, mk_bvsle),
                            AstOp::SGT(..) => binop!(z3_ctx, children, mk_bvsgt),
                            AstOp::SGE(..) => binop!(z3_ctx, children, mk_bvsge),
                            AstOp::FpLt(..) => binop!(z3_ctx, children, mk_fpa_lt),
                            AstOp::FpLeq(..) => binop!(z3_ctx, children, mk_fpa_leq),
                            AstOp::FpGt(..) => binop!(z3_ctx, children, mk_fpa_gt),
                            AstOp::FpGeq(..) => binop!(z3_ctx, children, mk_fpa_geq),
                            AstOp::FpIsNan(..) => unop!(z3_ctx, children, mk_fpa_is_nan),
                            AstOp::FpIsInf(..) => unop!(z3_ctx, children, mk_fpa_is_infinite),
                            AstOp::StrContains(..) => binop!(z3_ctx, children, mk_seq_contains),
                            AstOp::StrPrefixOf(..) => binop!(z3_ctx, children, mk_seq_prefix),
                            AstOp::StrSuffixOf(..) => binop!(z3_ctx, children, mk_seq_suffix),
                            AstOp::StrIsDigit(..) => {
                                let a = child(children, 0)?;
                                // str.to_int returns -1 for non-digit strings, so >= 0 means all digits
                                let int_val = z3::mk_str_to_int(z3_ctx, **a);
                                let int_sort = z3::mk_int_sort(z3_ctx);
                                let zero_cstr = std::ffi::CString::new("0").unwrap();
                                let zero = z3::mk_numeral(z3_ctx, zero_cstr.as_ptr(), int_sort);
                                let is_non_negative = z3::mk_ge(z3_ctx, int_val, zero);
                                let str_len = z3::mk_seq_length(z3_ctx, **a);
                                let zero_int_cstr = std::ffi::CString::new("0").unwrap();
                                let zero_int =
                                    z3::mk_numeral(z3_ctx, zero_int_cstr.as_ptr(), int_sort);
                                let is_non_empty = z3::mk_gt(z3_ctx, str_len, zero_int);
                                let args = [is_non_negative, is_non_empty];
                                z3::mk_and(z3_ctx, 2, args.as_ptr()).try_into()?
                            }

                            // Bitvector leaves and operations
                            AstOp::BVS(s, w) => {
                                let s_cstr = std::ffi::CString::new(s.as_str()).unwrap();
                                let sym = z3::mk_string_symbol(z3_ctx, s_cstr.as_ptr());
                                let sort = z3::mk_bv_sort(z3_ctx, *w);
                                RcAst::try_from(z3::mk_const(z3_ctx, sym, sort))?
                            }
                            AstOp::BVV(v) => {
                                let sort = z3::mk_bv_sort(z3_ctx, v.len());
                                let numeral = v.to_biguint().to_string();
                                let numeral_cstr = std::ffi::CString::new(numeral).unwrap();
                                RcAst::try_from(z3::mk_numeral(
                                    z3_ctx,
                                    numeral_cstr.as_ptr(),
                                    sort,
                                ))?
                            }
                            AstOp::Neg(..) => unop!(z3_ctx, children, mk_bvneg),
                            AstOp::Add(..) => naryop!(z3_ctx, children, mk_bvadd),
                            AstOp::Sub(..) => binop!(z3_ctx, children, mk_bvsub),
                            AstOp::Mul(..) => naryop!(z3_ctx, children, mk_bvmul),
                            AstOp::UDiv(..) => binop!(z3_ctx, children, mk_bvudiv),
                            AstOp::SDiv(..) => binop!(z3_ctx, children, mk_bvsdiv),
                            AstOp::URem(..) => binop!(z3_ctx, children, mk_bvurem),
                            AstOp::SRem(..) => binop!(z3_ctx, children, mk_bvsrem),
                            AstOp::ShL(..) => binop!(z3_ctx, children, mk_bvshl),
                            AstOp::LShR(..) => binop!(z3_ctx, children, mk_bvlshr),
                            AstOp::AShR(..) => binop!(z3_ctx, children, mk_bvashr),
                            AstOp::RotateLeft(..) => binop!(z3_ctx, children, mk_ext_rotate_left),
                            AstOp::RotateRight(..) => binop!(z3_ctx, children, mk_ext_rotate_right),
                            AstOp::ZeroExt(_, i) => {
                                RcAst::try_from(z3::mk_zero_ext(z3_ctx, *i, **child(children, 0)?))?
                            }
                            AstOp::SignExt(_, i) => {
                                RcAst::try_from(z3::mk_sign_ext(z3_ctx, *i, **child(children, 0)?))?
                            }
                            AstOp::Extract(a, high, low) => {
                                if high >= &a.size() || low >= &a.size() {
                                    return Err(ClarirsError::ConversionError(
                                        "extract index is greater than bitvector size".to_string(),
                                    ));
                                }
                                if low > high {
                                    return Err(ClarirsError::ConversionError(
                                        "low index is greater than high index".to_string(),
                                    ));
                                }
                                RcAst::try_from(z3::mk_extract(
                                    z3_ctx,
                                    *high,
                                    *low,
                                    **child(children, 0)?,
                                ))?
                            }
                            AstOp::Concat(args) => {
                                if args.is_empty() {
                                    return Err(ClarirsError::InvalidArguments(
                                        "Concat requires at least one argument".to_string(),
                                    ));
                                }
                                let mut result = child(children, 0)?.clone();
                                for i in 1..children.len() {
                                    result = RcAst::try_from(z3::mk_concat(
                                        z3_ctx,
                                        *result,
                                        **child(children, i)?,
                                    ))?;
                                }
                                result
                            }
                            AstOp::ByteReverse(a) => {
                                let size = a.size();
                                if size == 0 || size % 8 != 0 {
                                    return Err(ClarirsError::ConversionError(
                                        "reverse only supports bitvectors with size multiple of 8"
                                            .to_string(),
                                    ));
                                }
                                let child_z3 = child(children, 0)?;
                                let num_bytes = size / 8;
                                let mut result =
                                    RcAst::try_from(z3::mk_extract(z3_ctx, 7, 0, **child_z3))?;
                                for i in 1..num_bytes {
                                    let high = (i + 1) * 8 - 1;
                                    let low = i * 8;
                                    let byte = RcAst::try_from(z3::mk_extract(
                                        z3_ctx, high, low, **child_z3,
                                    ))?;
                                    result =
                                        RcAst::try_from(z3::mk_concat(z3_ctx, *result, *byte))?;
                                }
                                result
                            }
                            AstOp::FpToIEEEBV(..) => RcAst::try_from(z3::mk_fpa_to_ieee_bv(
                                z3_ctx,
                                **child(children, 0)?,
                            ))?,
                            AstOp::FpToUBV(_, size, rm) => {
                                let rm_ast = fprm_to_z3(*rm)?;
                                RcAst::try_from(z3::mk_fpa_to_ubv(
                                    z3_ctx,
                                    *rm_ast,
                                    **child(children, 0)?,
                                    *size,
                                ))?
                            }
                            AstOp::FpToSBV(_, size, rm) => {
                                let rm_ast = fprm_to_z3(*rm)?;
                                RcAst::try_from(z3::mk_fpa_to_sbv(
                                    z3_ctx,
                                    *rm_ast,
                                    **child(children, 0)?,
                                    *size,
                                ))?
                            }
                            AstOp::StrLen(..) => {
                                let str_len = RcAst::try_from(z3::mk_seq_length(
                                    z3_ctx,
                                    **child(children, 0)?,
                                ))?;
                                RcAst::try_from(z3::mk_int2bv(z3_ctx, 64, *str_len))?
                            }
                            AstOp::StrIndexOf(..) => {
                                let haystack = child(children, 0)?;
                                let needle = child(children, 1)?;
                                let offset_bv = child(children, 2)?;
                                let offset_int =
                                    RcAst::try_from(z3::mk_bv2int(z3_ctx, **offset_bv, false))?;
                                let index_int = RcAst::try_from(z3::mk_seq_index(
                                    z3_ctx,
                                    **haystack,
                                    **needle,
                                    *offset_int,
                                ))?;
                                RcAst::try_from(z3::mk_int2bv(z3_ctx, 64, *index_int))?
                            }
                            AstOp::StrToBV(..) => {
                                let int_val = RcAst::try_from(z3::mk_str_to_int(
                                    z3_ctx,
                                    **child(children, 0)?,
                                ))?;
                                RcAst::try_from(z3::mk_int2bv(z3_ctx, 64, *int_val))?
                            }
                            AstOp::Union(..) | AstOp::Intersection(..) | AstOp::Widen(..) => {
                                return Err(ClarirsError::ConversionError(
                                    "vsa types are not currently supported in the z3 backend"
                                        .to_string(),
                                ));
                            }

                            // Float leaves and operations
                            AstOp::FPS(s, sort) => {
                                let s_cstr = std::ffi::CString::new(s.as_str()).unwrap();
                                let sym = z3::mk_string_symbol(z3_ctx, s_cstr.as_ptr());
                                RcAst::try_from(z3::mk_const(z3_ctx, sym, fsort_to_z3(*sort)))?
                            }
                            AstOp::FPV(f) => {
                                let sort = fsort_to_z3(f.fsort());
                                match f {
                                    Float::F32(val) => RcAst::try_from(z3::mk_fpa_numeral_float(
                                        z3_ctx, *val, sort,
                                    ))?,
                                    Float::F64(val) => RcAst::try_from(z3::mk_fpa_numeral_double(
                                        z3_ctx, *val, sort,
                                    ))?,
                                }
                            }
                            AstOp::FpNeg(..) => unop!(z3_ctx, children, mk_fpa_neg),
                            AstOp::FpAbs(..) => unop!(z3_ctx, children, mk_fpa_abs),
                            AstOp::FpAdd(_, _, rm) => {
                                let rm_ast = fprm_to_z3(*rm)?;
                                let a = child(children, 0)?;
                                let b = child(children, 1)?;
                                RcAst::try_from(z3::mk_fpa_add(z3_ctx, *rm_ast, **a, **b))?
                            }
                            AstOp::FpSub(_, _, rm) => {
                                let rm_ast = fprm_to_z3(*rm)?;
                                let a = child(children, 0)?;
                                let b = child(children, 1)?;
                                RcAst::try_from(z3::mk_fpa_sub(z3_ctx, *rm_ast, **a, **b))?
                            }
                            AstOp::FpMul(_, _, rm) => {
                                let rm_ast = fprm_to_z3(*rm)?;
                                let a = child(children, 0)?;
                                let b = child(children, 1)?;
                                RcAst::try_from(z3::mk_fpa_mul(z3_ctx, *rm_ast, **a, **b))?
                            }
                            AstOp::FpDiv(_, _, rm) => {
                                let rm_ast = fprm_to_z3(*rm)?;
                                let a = child(children, 0)?;
                                let b = child(children, 1)?;
                                RcAst::try_from(z3::mk_fpa_div(z3_ctx, *rm_ast, **a, **b))?
                            }
                            AstOp::FpSqrt(_, rm) => {
                                let rm_ast = fprm_to_z3(*rm)?;
                                RcAst::try_from(z3::mk_fpa_sqrt(
                                    z3_ctx,
                                    *rm_ast,
                                    **child(children, 0)?,
                                ))?
                            }
                            AstOp::FpToFp(_, sort, rm) => {
                                let rm_ast = fprm_to_z3(*rm)?;
                                RcAst::try_from(z3::mk_fpa_to_fp_float(
                                    z3_ctx,
                                    *rm_ast,
                                    **child(children, 0)?,
                                    fsort_to_z3(*sort),
                                ))?
                            }
                            AstOp::FpFP(..) => {
                                let sign = child(children, 0)?;
                                let exp = child(children, 1)?;
                                let sig = child(children, 2)?;
                                RcAst::try_from(z3::mk_fpa_fp(z3_ctx, **sign, **exp, **sig))?
                            }
                            AstOp::BvToFp(_, sort) => RcAst::try_from(z3::mk_fpa_to_fp_bv(
                                z3_ctx,
                                **child(children, 0)?,
                                fsort_to_z3(*sort),
                            ))?,
                            AstOp::BvToFpSigned(_, sort, rm) => {
                                let rm_ast = fprm_to_z3(*rm)?;
                                RcAst::try_from(z3::mk_fpa_to_fp_signed(
                                    z3_ctx,
                                    *rm_ast,
                                    **child(children, 0)?,
                                    fsort_to_z3(*sort),
                                ))?
                            }
                            AstOp::BvToFpUnsigned(_, sort, rm) => {
                                let rm_ast = fprm_to_z3(*rm)?;
                                RcAst::try_from(z3::mk_fpa_to_fp_unsigned(
                                    z3_ctx,
                                    *rm_ast,
                                    **child(children, 0)?,
                                    fsort_to_z3(*sort),
                                ))?
                            }

                            // String leaves and operations
                            AstOp::StringS(s) => {
                                let s_cstr = std::ffi::CString::new(s.as_str()).unwrap();
                                let sym = z3::mk_string_symbol(z3_ctx, s_cstr.as_ptr());
                                let sort = z3::mk_seq_sort(z3_ctx, z3::mk_char_sort(z3_ctx));
                                RcAst::try_from(z3::mk_const(z3_ctx, sym, sort))?
                            }
                            AstOp::StringV(s) => {
                                let mut encoded = String::new();
                                for ch in s.chars() {
                                    if ch.is_ascii() {
                                        encoded.push(ch);
                                    } else {
                                        encoded.push_str(&format!("\\u{{{:04X}}}", ch as u32));
                                    }
                                }
                                let cstr = std::ffi::CString::new(encoded).unwrap();
                                RcAst::try_from(z3::mk_string(z3_ctx, cstr.as_ptr()))?
                            }
                            AstOp::StrConcat(..) => {
                                let a = child(children, 0)?;
                                let b = child(children, 1)?;
                                RcAst::try_from(z3::mk_seq_concat(z3_ctx, 2, [**a, **b].as_ptr()))?
                            }
                            AstOp::StrSubstr(..) => {
                                let a = child(children, 0)?;
                                let offset_int = mk_bv2int(child(children, 1)?)?;
                                let len_int = mk_bv2int(child(children, 2)?)?;
                                RcAst::try_from(z3::mk_seq_extract(
                                    z3_ctx,
                                    **a,
                                    *offset_int,
                                    *len_int,
                                ))?
                            }
                            AstOp::StrReplace(..) => {
                                let a = child(children, 0)?;
                                let b = child(children, 1)?;
                                let c = child(children, 2)?;
                                RcAst::try_from(z3::mk_seq_replace(z3_ctx, **a, **b, **c))?
                            }
                            AstOp::BVToStr(_) => {
                                let int_val = mk_bv2int(child(children, 0)?)?;
                                RcAst::try_from(z3::mk_int_to_str(z3_ctx, *int_val))?
                            }
                        })
                        .and_then(|maybe_null| {
                            check_z3_error()?;
                            Ok(maybe_null)
                        })
                    })
                },
                cache,
            )
        })
    }

    /// Converts a Z3 AST back into an [`AstRef`]. A single match over the Z3
    /// declaration kind replaces the previous per-sort `from_z3` functions; the
    /// few kinds that span sorts (`Ite`, uninterpreted constants, numerals) pick
    /// the result sort from the Z3 sort kind.
    fn from_z3(ctx: &'c Context<'c>, ast: impl Into<RcAst>) -> Result<Self, ClarirsError> {
        let ast = ast.into();
        Z3_CONTEXT.with(|z3_ctx| unsafe {
            let z3_ctx = *z3_ctx;
            match z3::get_ast_kind(z3_ctx, *ast) {
                z3::AstKind::Numeral => {
                    let sort = z3::get_sort(z3_ctx, *ast);
                    match z3::get_sort_kind(z3_ctx, sort) {
                        z3::SortKind::Bv => {
                            let numeral_string = z3::get_numeral_string(z3_ctx, *ast);
                            let numeral_str = CStr::from_ptr(numeral_string).to_str().unwrap();
                            let width = z3::get_bv_sort_size(z3_ctx, sort);
                            ctx.bvv(BitVec::from_str(numeral_str, width).unwrap())
                        }
                        z3::SortKind::FloatingPoint => {
                            let fsort = FSort::new(
                                z3::fpa_get_ebits(z3_ctx, sort),
                                z3::fpa_get_sbits(z3_ctx, sort) - 1,
                            );
                            let numeral_string = z3::get_numeral_string(z3_ctx, *ast);
                            let numeral_str = CStr::from_ptr(numeral_string).to_str().unwrap();
                            if fsort == FSort::f32() {
                                let val = numeral_str.parse::<f32>().map_err(|_| {
                                    ClarirsError::ConversionError("Failed to parse f32".to_string())
                                })?;
                                ctx.fpv(Float::F32(val))
                            } else {
                                let val = numeral_str.parse::<f64>().map_err(|_| {
                                    ClarirsError::ConversionError(
                                        "Failed to parse float".to_string(),
                                    )
                                })?;
                                ctx.fpv(Float::F64(val))
                            }
                        }
                        _ => Err(ClarirsError::ConversionError(
                            "numeral has unsupported sort".to_string(),
                        )),
                    }
                }
                z3::AstKind::App => {
                    let app = z3::to_app(z3_ctx, *ast);
                    let decl = z3::get_app_decl(z3_ctx, app);
                    let decl_kind = z3::get_decl_kind(z3_ctx, decl);
                    let arg = |i| RcAst::try_from(z3::get_app_arg(z3_ctx, app, i));

                    match decl_kind {
                        // String constants present as ordinary apps; catch them first.
                        _ if z3::is_string(z3_ctx, *ast) => {
                            let raw = CStr::from_ptr(z3::get_string(z3_ctx, *ast))
                                .to_str()
                                .unwrap();
                            ctx.stringv(decode_custom_unicode(raw))
                        }

                        // Booleans
                        z3::DeclKind::True => ctx.true_(),
                        z3::DeclKind::False => ctx.false_(),
                        z3::DeclKind::Not => {
                            let inner = AstRef::from_z3(ctx, arg(0)?)?;
                            // Not(Eq(a, b)) canonicalizes to Neq(a, b).
                            if let AstOp::Eq(a, b) = inner.op() {
                                ctx.neq(a, b)
                            } else {
                                ctx.not(inner)
                            }
                        }
                        z3::DeclKind::And | z3::DeclKind::Or => {
                            let num_args = z3::get_app_num_args(z3_ctx, app);
                            let mut args = Vec::with_capacity(num_args as usize);
                            for i in 0..num_args {
                                args.push(AstRef::from_z3(ctx, arg(i)?)?);
                            }
                            match decl_kind {
                                z3::DeclKind::And => ctx.and(args),
                                _ => ctx.or(args),
                            }
                        }
                        z3::DeclKind::Xor => ctx.xor2(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Eq => {
                            let lhs = AstRef::from_z3(ctx, arg(0)?)?;
                            let rhs = AstRef::from_z3(ctx, arg(1)?)?;
                            // eq_ picks the right per-sort equality from the operand type.
                            ctx.eq_(lhs, rhs)
                        }
                        z3::DeclKind::Distinct => {
                            if z3::get_app_num_args(z3_ctx, app) != 2 {
                                return Err(ClarirsError::ConversionError(
                                    "Distinct with != 2 args not supported".to_string(),
                                ));
                            }
                            let lhs = AstRef::from_z3(ctx, arg(0)?)?;
                            let rhs = AstRef::from_z3(ctx, arg(1)?)?;
                            ctx.neq(lhs, rhs)
                        }
                        z3::DeclKind::Ult => ctx.ult(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Uleq => ctx.ule(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Ugt => ctx.ugt(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Ugeq => ctx.uge(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Slt => ctx.slt(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Sleq => ctx.sle(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Sgt => ctx.sgt(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Sgeq => ctx.sge(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::FpaEq => ctx.fp_eq(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::FpaLt => ctx.fp_lt(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::FpaLe => ctx.fp_leq(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::FpaGt => ctx.fp_gt(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::FpaGe => ctx.fp_geq(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::FpaIsNan => ctx.fp_is_nan(AstRef::from_z3(ctx, arg(0)?)?),
                        z3::DeclKind::FpaIsInf => ctx.fp_is_inf(AstRef::from_z3(ctx, arg(0)?)?),
                        z3::DeclKind::SeqContains => ctx.str_contains(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::SeqPrefix => ctx.str_prefix_of(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::SeqSuffix => ctx.str_suffix_of(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),

                        // Bitvectors
                        z3::DeclKind::Bnot => ctx.not(AstRef::from_z3(ctx, arg(0)?)?),
                        z3::DeclKind::Bneg => ctx.neg(AstRef::from_z3(ctx, arg(0)?)?),
                        z3::DeclKind::Band
                        | z3::DeclKind::Bor
                        | z3::DeclKind::Bxor
                        | z3::DeclKind::Badd
                        | z3::DeclKind::Bmul => {
                            let num_args = z3::get_app_num_args(z3_ctx, app);
                            let mut args = Vec::with_capacity(num_args as usize);
                            for i in 0..num_args {
                                args.push(AstRef::from_z3(ctx, arg(i)?)?);
                            }
                            match decl_kind {
                                z3::DeclKind::Band => ctx.and(args),
                                z3::DeclKind::Bor => ctx.or(args),
                                z3::DeclKind::Bxor => ctx.xor(args),
                                z3::DeclKind::Badd => ctx.add_many(args),
                                _ => ctx.mul_many(args),
                            }
                        }
                        z3::DeclKind::Bsub => ctx.sub(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Budiv => ctx.udiv(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Bsdiv => ctx.sdiv(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Burem => ctx.urem(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Bsrem => ctx.srem(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Bshl => ctx.shl(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Blshr => ctx.lshr(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::Bashr => ctx.ashr(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::ExtRotateLeft => ctx.rotate_left(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::ExtRotateRight => ctx.rotate_right(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::ZeroExt => {
                            let inner = AstRef::from_z3(ctx, arg(0)?)?;
                            ctx.zero_ext(inner, z3::get_decl_int_parameter(z3_ctx, decl, 0) as u32)
                        }
                        z3::DeclKind::SignExt => {
                            let inner = AstRef::from_z3(ctx, arg(0)?)?;
                            ctx.sign_ext(inner, z3::get_decl_int_parameter(z3_ctx, decl, 0) as u32)
                        }
                        z3::DeclKind::Extract => {
                            let inner = AstRef::from_z3(ctx, arg(0)?)?;
                            let high = z3::get_decl_int_parameter(z3_ctx, decl, 0) as u32;
                            let low = z3::get_decl_int_parameter(z3_ctx, decl, 1) as u32;
                            ctx.extract(inner, high, low)
                        }
                        z3::DeclKind::Concat => {
                            let num_args = z3::get_app_num_args(z3_ctx, app);
                            let mut args = Vec::with_capacity(num_args as usize);
                            for i in 0..num_args {
                                args.push(AstRef::from_z3(ctx, arg(i)?)?);
                            }
                            ctx.concat(args)
                        }
                        // int2bv wraps the string->bv operations and plain bv2int.
                        z3::DeclKind::Int2bv => {
                            let inner_int = z3::get_app_arg(z3_ctx, app, 0);
                            match z3::get_ast_kind(z3_ctx, inner_int) {
                                z3::AstKind::Numeral => {
                                    let numeral_string = z3::get_numeral_string(z3_ctx, inner_int);
                                    let numeral_str =
                                        CStr::from_ptr(numeral_string).to_str().unwrap();
                                    let s = z3::get_sort(z3_ctx, inner_int);
                                    let width = z3::get_bv_sort_size(z3_ctx, s);
                                    ctx.bvv(BitVec::from_str(numeral_str, width).unwrap())
                                }
                                z3::AstKind::App => {
                                    let inner_app = z3::to_app(z3_ctx, inner_int);
                                    let inner_decl = z3::get_app_decl(z3_ctx, inner_app);
                                    match z3::get_decl_kind(z3_ctx, inner_decl) {
                                        z3::DeclKind::Bv2int => AstRef::from_z3(
                                            ctx,
                                            RcAst::try_from(z3::get_app_arg(z3_ctx, inner_app, 0))?,
                                        ),
                                        z3::DeclKind::SeqIndex => {
                                            let haystack = AstRef::from_z3(
                                                ctx,
                                                RcAst::try_from(z3::get_app_arg(
                                                    z3_ctx, inner_app, 0,
                                                ))?,
                                            )?;
                                            let needle = AstRef::from_z3(
                                                ctx,
                                                RcAst::try_from(z3::get_app_arg(
                                                    z3_ctx, inner_app, 1,
                                                ))?,
                                            )?;
                                            let off = z3::get_app_arg(z3_ctx, inner_app, 2);
                                            let offset_bv =
                                                RcAst::try_from(z3::mk_int2bv(z3_ctx, 64, off))?;
                                            let offset_simplified =
                                                RcAst::try_from(z3::simplify(z3_ctx, *offset_bv))?;
                                            let offset = AstRef::from_z3(ctx, offset_simplified)?;
                                            ctx.str_index_of(haystack, needle, offset)
                                        }
                                        z3::DeclKind::StrToInt => ctx.str_to_bv(AstRef::from_z3(
                                            ctx,
                                            RcAst::try_from(z3::get_app_arg(z3_ctx, inner_app, 0))?,
                                        )?),
                                        z3::DeclKind::SeqLength => ctx.str_len(AstRef::from_z3(
                                            ctx,
                                            RcAst::try_from(z3::get_app_arg(z3_ctx, inner_app, 0))?,
                                        )?),
                                        k => Err(ClarirsError::ConversionError(format!(
                                            "unexpected inner decl kind in Int2bv: {k:?}"
                                        ))),
                                    }
                                }
                                _ => Err(ClarirsError::ConversionError(
                                    "expected a numeral or bv2int".to_string(),
                                )),
                            }
                        }

                        // Floats
                        z3::DeclKind::FpaNum => {
                            let sort = z3::get_sort(z3_ctx, *ast);
                            let fsort = FSort::new(
                                z3::fpa_get_ebits(z3_ctx, sort),
                                z3::fpa_get_sbits(z3_ctx, sort) - 1,
                            );
                            let val = z3::get_numeral_double(z3_ctx, *ast);
                            if fsort == FSort::f32() {
                                ctx.fpv(Float::F32(val as f32))
                            } else {
                                ctx.fpv(Float::F64(val))
                            }
                        }
                        z3::DeclKind::FpaNan => {
                            let sort = z3::get_sort(z3_ctx, *ast);
                            let fsort = FSort::new(
                                z3::fpa_get_ebits(z3_ctx, sort),
                                z3::fpa_get_sbits(z3_ctx, sort) - 1,
                            );
                            if fsort == FSort::f32() {
                                ctx.fpv(Float::F32(f32::NAN))
                            } else {
                                ctx.fpv(Float::F64(f64::NAN))
                            }
                        }
                        z3::DeclKind::FpaNeg => ctx.fp_neg(AstRef::from_z3(ctx, arg(0)?)?),
                        z3::DeclKind::FpaAbs => ctx.fp_abs(AstRef::from_z3(ctx, arg(0)?)?),
                        z3::DeclKind::FpaAdd
                        | z3::DeclKind::FpaSub
                        | z3::DeclKind::FpaMul
                        | z3::DeclKind::FpaDiv => {
                            let rm = parse_fprm_from_z3(z3_ctx, *arg(0)?)?;
                            let a = AstRef::from_z3(ctx, arg(1)?)?;
                            let b = AstRef::from_z3(ctx, arg(2)?)?;
                            match decl_kind {
                                z3::DeclKind::FpaAdd => ctx.fp_add(a, b, rm),
                                z3::DeclKind::FpaSub => ctx.fp_sub(a, b, rm),
                                z3::DeclKind::FpaMul => ctx.fp_mul(a, b, rm),
                                _ => ctx.fp_div(a, b, rm),
                            }
                        }
                        z3::DeclKind::FpaSqrt => {
                            let rm = parse_fprm_from_z3(z3_ctx, *arg(0)?)?;
                            ctx.fp_sqrt(AstRef::from_z3(ctx, arg(1)?)?, rm)
                        }
                        z3::DeclKind::FpaToFp => {
                            let sort = z3::get_sort(z3_ctx, *ast);
                            let fsort = FSort::new(
                                z3::fpa_get_ebits(z3_ctx, sort),
                                z3::fpa_get_sbits(z3_ctx, sort) - 1,
                            );
                            match z3::get_app_num_args(z3_ctx, app) {
                                1 => ctx.bv_to_fp(AstRef::from_z3(ctx, arg(0)?)?, fsort),
                                2 => {
                                    let rm = parse_fprm_from_z3(z3_ctx, *arg(0)?)?;
                                    let operand = arg(1)?;
                                    let operand_sort = z3::get_sort(z3_ctx, *operand);
                                    match z3::get_sort_kind(z3_ctx, operand_sort) {
                                        z3::SortKind::FloatingPoint => {
                                            ctx.fp_to_fp(AstRef::from_z3(ctx, operand)?, fsort, rm)
                                        }
                                        z3::SortKind::Bv => ctx.bv_to_fp_signed(
                                            AstRef::from_z3(ctx, operand)?,
                                            fsort,
                                            rm,
                                        ),
                                        _ => Err(ClarirsError::ConversionError(
                                            "FpaToFp: unexpected sort kind for operand".to_string(),
                                        )),
                                    }
                                }
                                _ => Err(ClarirsError::ConversionError(
                                    "Unexpected number of arguments for FpaToFp".to_string(),
                                )),
                            }
                        }
                        z3::DeclKind::FpaFp => {
                            let sign = AstRef::from_z3(ctx, arg(0)?)?;
                            let exp = AstRef::from_z3(ctx, arg(1)?)?;
                            let sig = AstRef::from_z3(ctx, arg(2)?)?;
                            ctx.fp_fp(sign, exp, sig)
                        }

                        // Strings
                        z3::DeclKind::SeqConcat => ctx.str_concat(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                        ),
                        z3::DeclKind::SeqExtract => {
                            let a = AstRef::from_z3(ctx, arg(0)?)?;
                            let offset_bv = RcAst::try_from(z3::mk_int2bv(z3_ctx, 64, *arg(1)?))?;
                            let offset = AstRef::from_z3(
                                ctx,
                                RcAst::try_from(z3::simplify(z3_ctx, *offset_bv))?,
                            )?;
                            let len_bv = RcAst::try_from(z3::mk_int2bv(z3_ctx, 64, *arg(2)?))?;
                            let len = AstRef::from_z3(
                                ctx,
                                RcAst::try_from(z3::simplify(z3_ctx, *len_bv))?,
                            )?;
                            ctx.str_substr(a, offset, len)
                        }
                        z3::DeclKind::SeqReplace => ctx.str_replace(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                            AstRef::from_z3(ctx, arg(2)?)?,
                        ),
                        z3::DeclKind::IntToStr => {
                            // int.to.str(bv2int(bv)) -> BVToStr(bv)
                            let inner_app = z3::to_app(z3_ctx, *arg(0)?);
                            let inner_decl = z3::get_app_decl(z3_ctx, inner_app);
                            if z3::get_decl_kind(z3_ctx, inner_decl) == z3::DeclKind::Bv2int {
                                ctx.bv_to_str(AstRef::from_z3(
                                    ctx,
                                    RcAst::try_from(z3::get_app_arg(z3_ctx, inner_app, 0))?,
                                )?)
                            } else {
                                Err(ClarirsError::ConversionError(
                                    "expected bv2int inside int_to_str".to_string(),
                                ))
                            }
                        }

                        // Shared across sorts
                        z3::DeclKind::Ite => ctx.ite(
                            AstRef::from_z3(ctx, arg(0)?)?,
                            AstRef::from_z3(ctx, arg(1)?)?,
                            AstRef::from_z3(ctx, arg(2)?)?,
                        ),
                        z3::DeclKind::Uninterpreted => {
                            let sort = z3::get_sort(z3_ctx, *ast);
                            let sym = z3::get_decl_name(z3_ctx, decl);
                            let name = CStr::from_ptr(z3::get_symbol_string(z3_ctx, sym))
                                .to_str()
                                .unwrap();
                            match z3::get_sort_kind(z3_ctx, sort) {
                                z3::SortKind::Bool => ctx.bools(name),
                                z3::SortKind::Bv => {
                                    ctx.bvs(name, z3::get_bv_sort_size(z3_ctx, sort))
                                }
                                z3::SortKind::FloatingPoint => {
                                    let fsort = FSort::new(
                                        z3::fpa_get_ebits(z3_ctx, sort),
                                        z3::fpa_get_sbits(z3_ctx, sort) - 1,
                                    );
                                    ctx.fps(name, fsort)
                                }
                                z3::SortKind::Seq => ctx.strings(name),
                                _ => Err(ClarirsError::ConversionError(
                                    "uninterpreted constant has unsupported sort".to_string(),
                                )),
                            }
                        }
                        _ => {
                            let decl_name =
                                CStr::from_ptr(z3::func_decl_to_string(z3_ctx, decl) as *mut i8)
                                    .to_string_lossy();
                            Err(ClarirsError::ConversionError(format!(
                                "Failed converting from z3: unknown decl kind: {decl_name}"
                            )))
                        }
                    }
                }
                _ => Err(ClarirsError::ConversionError(
                    "Failed converting from z3: unknown ast kind".to_string(),
                )),
            }
        })
    }
}
