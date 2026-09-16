//! Human-readable rendering of claripy ASTs.
//!
//! This is a port of the pre-Rust claripy's `Base.shallow_repr`/`Base._op_repr`
//! (infix operators, C operator precedence, `<BV32 ...>` wrappers), which the
//! SMT-LIB rendering in [`clarirs_core::smtlib`] replaced. SMT-LIB is still
//! available as `Base.smtlib()`.

use num_bigint::BigUint;

use crate::claripy::prelude::*;

/// Print short reprs for both operations and leaves.
pub const LITE_REPR: u8 = 0;
/// Print full reprs for operations, short ones for leaves.
pub const MID_REPR: u8 = 1;
/// Print full reprs for everything.
pub const FULL_REPR: u8 = 2;

/// Precedence of an operation with no entry in [`op_precedence`]; binds the
/// least tightly, so its children are never parenthesized.
const LOWEST_PREC: u8 = 15;

/// Recursion limit. claripy raised `RecursionError` on deeper ASTs; overflowing
/// the Rust stack would abort the process instead, so bail out with `<...>`.
const MAX_RECURSION: usize = 512;

/// The infix spelling of an operation, keyed by claripy op name.
fn infix(op: &str) -> Option<&'static str> {
    Some(match op {
        "__add__" => "+",
        "__sub__" => "-",
        "__mul__" => "*",
        "__floordiv__" | "__truediv__" => "/",
        "__mod__" => "%",
        "__eq__" => "==",
        "__ne__" => "!=",
        "UGE" => ">=",
        "ULE" => "<=",
        "UGT" => ">",
        "ULT" => "<",
        "SGE" => ">=s",
        "SLE" => "<=s",
        "SGT" => ">s",
        "SLT" => "<s",
        "SDiv" => "/s",
        "SMod" => "%s",
        "__or__" => "|",
        "__and__" => "&",
        // Bitvector xor; `Xor` is its boolean counterpart, which pre-Rust
        // claripy did not have.
        "__xor__" | "Xor" => "^",
        "__lshift__" => "<<",
        "__rshift__" => ">>",
        "And" => "&&",
        "Or" => "||",
        "Concat" => "..",
        _ => return None,
    })
}

/// The prefix spelling of a unary operation, keyed by claripy op name.
fn prefix(op: &str) -> Option<&'static str> {
    Some(match op {
        "Not" => "!",
        "__neg__" => "-",
        "__invert__" => "~",
        _ => return None,
    })
}

/// Operator precedence, following C's (lower binds tighter).
fn op_precedence(op: &str) -> u8 {
    match op {
        "Not" | "__neg__" | "__invert__" => 2,
        "__mul__" | "__floordiv__" | "__truediv__" | "__mod__" | "SDiv" | "SMod" => 3,
        "__add__" | "__sub__" => 4,
        "__lshift__" | "__rshift__" => 5,
        "UGE" | "ULE" | "UGT" | "ULT" | "SGE" | "SLE" | "SGT" | "SLT" => 6,
        "__eq__" | "__ne__" => 7,
        "__and__" => 8,
        "__xor__" | "Xor" => 9,
        "__or__" => 10,
        "And" => 11,
        "Or" => 12,
        _ => LOWEST_PREC,
    }
}

/// `RM.<variant>`, matching `repr()` of the Python `RM` enum.
fn fprm_repr(rm: &FPRM) -> &'static str {
    match rm {
        FPRM::NearestTiesToEven => "RM.RM_NearestTiesEven",
        FPRM::NearestTiesToAway => "RM.RM_NearestTiesAwayFromZero",
        FPRM::TowardZero => "RM.RM_TowardsZero",
        FPRM::TowardPositive => "RM.RM_TowardsPositiveInf",
        FPRM::TowardNegative => "RM.RM_TowardsNegativeInf",
    }
}

/// `FSORT_<size>`, matching `repr()` of the Python `FSort` class.
fn fsort_repr(sort: &FSort) -> String {
    format!("FSORT_{}", sort.size())
}

/// Formats a float the way Python's `str()` does: NaN in lowercase, exponent
/// notation outside 1e-4..1e16, and a trailing `.0` on whole numbers.
fn float_repr(value: &Float) -> String {
    let (plain, exponential) = match value {
        Float::F32(value) => (format!("{value}"), format!("{value:e}")),
        Float::F64(value) => (format!("{value}"), format!("{value:e}")),
    };
    if plain == "NaN" {
        return "nan".to_string();
    }
    if plain.contains("inf") {
        // "inf"/"-inf" are already spelled as Python spells them.
        return plain;
    }

    let (mantissa, exponent) = exponential
        .split_once('e')
        .expect("`{:e}` always emits an exponent");
    let exponent: i32 = exponent.parse().expect("`{:e}` emits an integer exponent");
    if !(-4..16).contains(&exponent) {
        let sign = if exponent < 0 { '-' } else { '+' };
        return format!("{mantissa}e{sign}{:02}", exponent.abs());
    }
    if plain.contains('.') {
        plain
    } else {
        plain + ".0"
    }
}

/// A bitvector value: decimal below 10 bits wide, hexadecimal above.
fn bitvec_repr(value: &BigUint, width: u32) -> String {
    if width < 10 {
        value.to_str_radix(10)
    } else {
        format!("{value:#x}")
    }
}

/// The Python wrapper class name of an AST, plus its length for sized sorts.
fn type_name(ast: &AstRef<'static>) -> String {
    match ast.ast_type() {
        AstType::Bool => "Bool".to_string(),
        AstType::BitVec(width) => format!("BV{width}"),
        AstType::Float(sort) => format!("FP{}", sort.size()),
        AstType::String => "String".to_string(),
    }
}

/// One rendered argument of an operation: either a child AST still to be
/// rendered, or an already-formatted non-AST parameter.
enum Arg {
    Child(AstRef<'static>),
    Lit(String),
}

/// The arguments of an operation, in the same order as `Base.args` exposes
/// them.
fn args_of(ast: &AstRef<'static>) -> Vec<Arg> {
    match ast.op() {
        AstOp::BoolS(name) => vec![Arg::Lit(name.to_string())],
        AstOp::BoolV(value) => vec![Arg::Lit(if *value { "True" } else { "False" }.to_string())],
        AstOp::BVS(name, width) => {
            vec![Arg::Lit(name.to_string()), Arg::Lit(width.to_string())]
        }
        AstOp::BVV(value) => vec![
            Arg::Lit(value.to_biguint().to_str_radix(10)),
            Arg::Lit(value.len().to_string()),
        ],
        AstOp::FPS(name, sort) => vec![Arg::Lit(name.to_string()), Arg::Lit(fsort_repr(sort))],
        AstOp::FPV(value) => vec![Arg::Lit(float_repr(value))],
        AstOp::StringS(name) => vec![Arg::Lit(name.to_string())],
        AstOp::StringV(value) => vec![Arg::Lit(value.clone())],

        // Non-child parameters come first, as claripy's arg lists had them.
        AstOp::ZeroExt(a, amount) | AstOp::SignExt(a, amount) => {
            vec![Arg::Lit(amount.to_string()), Arg::Child(a.clone())]
        }
        AstOp::Extract(a, end, start) => vec![
            Arg::Lit(end.to_string()),
            Arg::Lit(start.to_string()),
            Arg::Child(a.clone()),
        ],

        // Rounding modes trail their operands, as `Base.args` reports them.
        AstOp::FpAdd(a, b, rm)
        | AstOp::FpSub(a, b, rm)
        | AstOp::FpMul(a, b, rm)
        | AstOp::FpDiv(a, b, rm) => vec![
            Arg::Child(a.clone()),
            Arg::Child(b.clone()),
            Arg::Lit(fprm_repr(rm).to_string()),
        ],
        AstOp::FpSqrt(a, rm) => vec![Arg::Child(a.clone()), Arg::Lit(fprm_repr(rm).to_string())],

        _ => ast.child_iter().map(Arg::Child).collect(),
    }
}

/// Renders one node given its already-rendered arguments, mirroring claripy's
/// `Base._op_repr`.
fn op_repr(
    ast: &AstRef<'static>,
    op: &str,
    args: &[String],
    inner: bool,
    explicit_length: bool,
    details: u8,
    inner_infix_use_par: bool,
) -> String {
    if details < FULL_REPR {
        match ast.op() {
            AstOp::BVS(name, _) => return name.to_string(),
            AstOp::BoolV(_) => return args[0].clone(),
            AstOp::BVV(value) => {
                let rendered = bitvec_repr(&value.to_biguint(), value.len());
                return if explicit_length {
                    format!("{rendered}#{}", value.len())
                } else {
                    rendered
                };
            }
            _ => {}
        }
    }

    if details < MID_REPR {
        match op {
            "If" => {
                let value = format!("if {} then {} else {}", args[0], args[1], args[2]);
                return if inner { format!("({value})") } else { value };
            }
            "Not" => return format!("!{}", args[0]),
            "Extract" => return format!("{}[{}:{}]", args[2], args[0], args[1]),
            "ZeroExt" => {
                let value = format!("0#{} .. {}", args[0], args[1]);
                return if inner { format!("({value})") } else { value };
            }
            _ => {}
        }
        if let Some(sym) = prefix(op) {
            let value = format!("{sym}{}", args[0]);
            return if inner && inner_infix_use_par {
                format!("({value})")
            } else {
                value
            };
        }
        if let Some(sym) = infix(op) {
            let value = args.join(&format!(" {sym} "));
            return if inner && inner_infix_use_par {
                format!("({value})")
            } else {
                value
            };
        }
    }

    format!("{op}({})", args.join(", "))
}

/// Renders `ast` and, unless `inner`, wraps it in `<SORT ...>`.
#[allow(clippy::too_many_arguments)]
fn render(
    ast: &AstRef<'static>,
    max_depth: Option<usize>,
    explicit_length: bool,
    details: u8,
    inner: bool,
    parent_prec: u8,
    left: bool,
    stack_depth: usize,
) -> String {
    if max_depth == Some(0) || stack_depth >= MAX_RECURSION {
        return "<...>".to_string();
    }

    let op = ast.to_opstring();
    let op_prec = op_precedence(&op);
    let next_max_depth = max_depth.map(|depth| depth - 1);

    let args: Vec<String> = args_of(ast)
        .into_iter()
        .enumerate()
        .map(|(idx, arg)| match arg {
            Arg::Child(child) => render(
                &child,
                next_max_depth,
                explicit_length,
                details,
                true,
                op_prec,
                idx == 0,
                stack_depth + 1,
            ),
            Arg::Lit(lit) => lit,
        })
        .collect();

    // A child binding less tightly than its parent needs parentheses, and so
    // does an equally tight right-hand child (`a - (b - c)`).
    let inner_infix_use_par = parent_prec < op_prec || (parent_prec == op_prec && !left);
    let inner_repr = op_repr(
        ast,
        &op,
        &args,
        inner,
        explicit_length,
        details,
        inner_infix_use_par,
    );

    if inner {
        inner_repr
    } else {
        format!("<{} {}>", type_name(ast), inner_repr)
    }
}

/// claripy's human-readable repr. `max_depth` of `None` renders the whole tree;
/// deeper nodes are elided as `<...>`.
pub fn pretty_repr(
    ast: &AstRef<'static>,
    max_depth: Option<usize>,
    explicit_length: bool,
    details: u8,
) -> String {
    render(
        ast,
        max_depth,
        explicit_length,
        details,
        false,
        LOWEST_PREC,
        true,
        0,
    )
}
