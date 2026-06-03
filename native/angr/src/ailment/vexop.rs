//! Full Rust port of `angr.engines.vex.claripy.irop.vexop_to_simop` (the
//! subset the AIL converter needs). No Python calls: the op name is parsed
//! with the same `OP_ATTRS_PATTERN` regex, the return type comes from libVEX
//! `typeOfPrimop` (via [`crate::ailment::vex_ffi`]), and the
//! supported/unsupported decision mirrors `SimIROp.__init__`'s calculate
//! resolution.
//!
//! The handler name-sets below (`EXPLICIT_OPS`, `GENERIC_OPS`,
//! `FGENERIC_OPS`, `CLARIPY_FP_OPS`) mirror claripy/irop internals. They were
//! captured by introspection; regenerate/verify with the cross-check test
//! `test_vexop_parity` (compares every VEX op against Python `vexop_to_simop`).

use std::sync::OnceLock;

use regex::Regex;

use crate::ailment::vex_ffi;
use crate::ailment::vexop_names::{IOP_BASE, IROP_NAMES};

/// Parsed + classified VEX op, holding only what the converter reads.
#[derive(Debug, Clone)]
pub struct SimOpInfo {
    pub name: String,
    pub generic_name: Option<String>,
    pub from_size: Option<u32>,
    pub from_side: Option<String>,
    pub from_type: Option<String>,
    pub from_signed: Option<String>,
    pub to_size: Option<u32>,
    pub to_type: Option<String>,
    pub conversion: Option<String>,
    pub vector_count: Option<u32>,
    pub vector_size: Option<u32>,
    pub float: bool,
    pub output_size_bits: u32,
    /// Cached `vector_signed == "S"` (the `vector_signed` string itself is
    /// not otherwise needed by the converter).
    pub vector_signed_is_s: bool,
}

impl SimOpInfo {
    pub fn is_signed(&self) -> bool {
        self.from_signed.as_deref() == Some("S") || self.vector_signed_is_s
    }
    pub fn is_conversion(&self) -> bool {
        self.conversion.is_some()
    }
}

// ---------------------------------------------------------------------------
// Handler name-sets mirroring SimIROp / claripy (see module docs).
// ---------------------------------------------------------------------------

/// Ops with an explicit `_op_Iop_<name>` handler.
const EXPLICIT_OPS: &[&str] = &[
    "Iop_64x4toV256",
    "Iop_MAddF64",
    "Iop_Reverse32sIn64_x2",
    "Iop_SliceV128",
    "Iop_V256to64_0",
    "Iop_V256to64_1",
    "Iop_V256to64_2",
    "Iop_V256to64_3",
    "Iop_V256toV128_0",
    "Iop_V256toV128_1",
];

/// Generic names with a `_op_generic_<name>` handler.
const GENERIC_OPS: &[&str] = &[
    "CasCmpEQ",
    "CasCmpGE",
    "CasCmpGT",
    "CasCmpLE",
    "CasCmpLT",
    "CasCmpNE",
    "CatEvenLanes",
    "CatOddLanes",
    "Clz",
    "CmpEQ",
    "CmpGE",
    "CmpGT",
    "CmpLE",
    "CmpLT",
    "CmpNE",
    "CmpNEZ",
    "CmpORD",
    "Ctz",
    "Dup",
    "ExpCmpNE",
    "GetElem",
    "GetMSBs",
    "HAdd",
    "HSub",
    "InterleaveHI",
    "InterleaveLO",
    "Max",
    "Min",
    "MulHi",
    "Mull",
    "Perm",
    "QAdd",
    "QNarrowBin",
    "QSub",
    "SarN",
    "Set",
    "SetElem",
    "ShlN",
    "ShrN",
];

/// Generic names with a `_op_fgeneric_<name>` handler.
const FGENERIC_OPS: &[&str] = &[
    "Cmp", "CmpEQ", "CmpLE", "CmpLT", "Max", "Min", "RSqrtEst", "Reinterp", "Round",
];

/// Generic names `g` for which `claripy.fp<g>` exists (used by the
/// lowest-lane scalar-FP branch).
const CLARIPY_FP_OPS: &[&str] = &[
    "Abs",
    "Add",
    "Div",
    "EQ",
    "FP",
    "GEQ",
    "GT",
    "IsInf",
    "IsNaN",
    "LEQ",
    "LT",
    "Mul",
    "NEQ",
    "Neg",
    "Sqrt",
    "Sub",
    "ToFP",
    "ToFPUnsigned",
    "ToIEEEBV",
    "ToSBV",
    "ToUBV",
];

const ARITHMETIC_OPS: &[&str] = &["Add", "Sub", "Mul", "Div", "Neg", "Abs", "Mod"];
const SHIFT_OPS: &[&str] = &["Shl", "Shr", "Sar"];
const BITWISE_OPS: &[&str] = &["Xor", "Or", "And", "Not"];

// ---------------------------------------------------------------------------
// Raw attribute bag (before classification), mirroring `op_attrs`.
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
struct Attrs {
    generic_name: Option<String>,
    from_type: Option<String>,
    from_signed: Option<String>,
    from_size: Option<u32>,
    from_side: Option<String>,
    conversion: Option<String>,
    to_type: Option<String>,
    to_size: Option<u32>,
    vector_size: Option<u32>,
    vector_signed: Option<String>,
    vector_type: Option<String>,
    vector_zero: Option<String>,
    vector_count: Option<u32>,
}

fn op_attrs_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"^Iop_",
            r"(?P<generic_name>\D+?)??",
            r"(?P<from_type>[IFDV])??",
            r"(?P<from_signed>[US])??",
            r"(?P<from_size>\d+)??",
            r"(?P<from_signed_back>[US])??",
            r"(",
            r"(?P<from_side>HL|HI|L|LO|lo)??",
            r"(?P<conversion>to|as)",
            r"(?P<to_type>Int|I|F|D|V)??",
            r"(?P<to_size>\d+)??",
            r"(?P<to_signed>[US])??",
            r")??",
            r"(",
            r"(?P<set_side>lo)",
            r"(?P<set_size>\d+)",
            r")??",
            r"(?P<vector_info>\d+U?S?F?0?x\d+)??",
            r"(?P<rounding_mode>_R[ZPNM])?$",
        ))
        .expect("OP_ATTRS_PATTERN must compile")
    })
}

fn vector_info_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"^(?P<vector_size>\d+)?",
            r"(?P<vector_signed>[US])?",
            r"(?P<vector_type>[FD])?",
            r"(?P<vector_zero>0)?",
            r"x",
            r"(?P<vector_count>\d+)?$",
        ))
        .expect("vector_info pattern must compile")
    })
}

/// Mirror of `op_attrs(p)`. Returns `None` when the name doesn't match.
fn op_attrs(name: &str) -> Option<Attrs> {
    let caps = op_attrs_re().captures(name)?;
    let get = |g: &str| caps.name(g).map(|m| m.as_str().to_string());

    let mut a = Attrs {
        generic_name: get("generic_name"),
        from_type: get("from_type"),
        from_signed: get("from_signed"),
        from_size: get("from_size").and_then(|s| s.parse().ok()),
        from_side: get("from_side"),
        conversion: get("conversion"),
        to_type: get("to_type"),
        to_size: get("to_size").and_then(|s| s.parse().ok()),
        ..Attrs::default()
    };

    // from_signed = from_signed_back if from_signed is None else from_signed
    if a.from_signed.is_none() {
        a.from_signed = get("from_signed_back");
    }

    // CmpOR special-case
    if a.generic_name.as_deref() == Some("CmpOR") {
        a.generic_name = Some("CmpORD".to_string());
        a.from_type = None;
    }

    // vector_info sub-parse
    if let Some(vi) = get("vector_info")
        && let Some(vc) = vector_info_re().captures(&vi)
    {
        let vget = |g: &str| vc.name(g).map(|m| m.as_str().to_string());
        a.vector_size = vget("vector_size").and_then(|s| s.parse().ok());
        a.vector_signed = vget("vector_signed");
        a.vector_type = vget("vector_type");
        a.vector_zero = vget("vector_zero");
        a.vector_count = vget("vector_count").and_then(|s| s.parse().ok());
    }

    Some(a)
}

/// Build + classify, mirroring `SimIROp.__init__`. `Err(())` means the op
/// would raise (BCD / size-mismatch / no calculate function) and the converter
/// must emit a `DirtyExpression`.
fn build(name: &str, op_int: u32, a: &Attrs) -> Result<SimOpInfo, ()> {
    let output_size_bits = vex_ffi::type_size_bits(vex_ffi::op_result_type(op_int));

    // size_check
    if let Some(to_size) = a.to_size {
        let effective = if a.generic_name.as_deref() == Some("DivMod") {
            to_size * 2
        } else {
            to_size
        };
        if effective != output_size_bits {
            return Err(());
        }
    }

    // float / BCD detection
    let type_letters = [
        a.vector_type.as_deref(),
        a.from_type.as_deref(),
        a.to_type.as_deref(),
    ];
    let has_d = type_letters.contains(&Some("D"));
    if has_d {
        return Err(()); // BCD ops aren't supported
    }
    let float = type_letters
        .iter()
        .any(|t| matches!(*t, Some("F") | Some("D")));

    let vector_signed_is_s = a.vector_signed.as_deref() == Some("S");

    let info = SimOpInfo {
        name: name.to_string(),
        generic_name: a.generic_name.clone(),
        from_size: a.from_size,
        from_side: a.from_side.clone(),
        from_type: a.from_type.clone(),
        from_signed: a.from_signed.clone(),
        to_size: a.to_size,
        to_type: a.to_type.clone(),
        conversion: a.conversion.clone(),
        vector_count: a.vector_count,
        vector_size: a.vector_size,
        float,
        output_size_bits,
        vector_signed_is_s,
    };

    if has_calculate(name, a, float, &info) {
        Ok(info)
    } else {
        Err(())
    }
}

/// Mirror of the `_calculate`-resolution branch in `SimIROp.__init__`:
/// returns whether a calculate function would be assigned (i.e. the op is
/// "supported"). `assert False` paths are treated as unsupported rather than
/// crashing (unreachable for real ops).
fn has_calculate(name: &str, a: &Attrs, float: bool, info: &SimOpInfo) -> bool {
    if EXPLICIT_OPS.contains(&name) {
        return true;
    }

    let generic = a.generic_name.as_deref();

    // generic_name is None and conversion present -> widening/narrowing/etc.
    if generic.is_none() && a.conversion.is_some() {
        let from_size = a.from_size.unwrap_or(0);
        let to_size = a.to_size.unwrap_or(0);
        let from_side = a.from_side.as_deref();
        if float && a.from_type.as_deref() == Some("I") {
            return true;
        }
        if a.from_type.as_deref() == Some("F") && a.to_type.as_deref() == Some("F") {
            return true;
        }
        if a.from_type.as_deref() == Some("F") && a.to_type.as_deref() == Some("I") {
            return true;
        }
        if from_side == Some("HL") {
            return true;
        }
        if from_size > to_size && from_side == Some("HI") {
            return true;
        }
        if from_size > to_size && matches!(from_side, Some("L") | Some("LO")) {
            return true;
        }
        if from_size > to_size && from_side.is_none() {
            return true;
        }
        if from_size < to_size && info.is_signed() {
            return true;
        }
        if from_size < to_size && !info.is_signed() {
            return true;
        }
        return false; // Python: assert False
    }

    if float && a.vector_zero.is_some() {
        if let Some(g) = generic {
            return CLARIPY_FP_OPS.contains(&g) || FGENERIC_OPS.contains(&g);
        }
        return false;
    }

    if a.conversion.is_some()
        && !matches!(
            generic,
            Some("Round") | Some("Reinterp") | Some("QNarrowBin")
        )
    {
        return generic == Some("DivMod");
    }

    if let Some(g) = generic {
        if BITWISE_OPS.contains(&g) {
            return true;
        }
        if ARITHMETIC_OPS.contains(&g) || SHIFT_OPS.contains(&g) {
            return true;
        }
        if float && FGENERIC_OPS.contains(&g) {
            return true;
        }
        if !float && GENERIC_OPS.contains(&g) {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Public entry point.
// ---------------------------------------------------------------------------

/// Name for a VEX op integer (or `None` if out of range).
pub fn op_name(op_int: u32) -> Option<&'static str> {
    if op_int < IOP_BASE {
        return None;
    }
    IROP_NAMES.get((op_int - IOP_BASE) as usize).copied()
}

/// Integer for a VEX op name (or `None` if unknown). Used by the
/// Python-object fallback path, where ops arrive as strings.
pub fn op_int_from_name(name: &str) -> Option<u32> {
    use std::collections::HashMap;
    static REV: OnceLock<HashMap<&'static str, u32>> = OnceLock::new();
    let map = REV.get_or_init(|| {
        IROP_NAMES
            .iter()
            .enumerate()
            .map(|(i, n)| (*n, IOP_BASE + i as u32))
            .collect()
    });
    map.get(name).copied()
}

/// Explicit-attrs overrides keyed by op name (mirrors `explicit_attrs`).
/// Only `generic_name`/`to_size`/`vector_size`/`vector_count` are ever set.
fn explicit_attrs(name: &str) -> Option<Attrs> {
    let mk = |g: &str, to_size: u32, vs: Option<u32>, vc: Option<u32>| {
        Some(Attrs {
            generic_name: Some(g.to_string()),
            to_size: Some(to_size),
            vector_size: vs,
            vector_count: vc,
            ..Attrs::default()
        })
    };
    match name {
        "Iop_64x4toV256" => mk("64x4", 256, None, None),
        "Iop_Yl2xF64" => mk("Yl2x", 64, None, None),
        "Iop_Yl2xp1F64" => mk("Yl2xp1", 64, None, None),
        "Iop_V256to64_0" | "Iop_V256to64_1" | "Iop_V256to64_2" | "Iop_V256to64_3" => {
            mk("unpack", 64, None, None)
        }
        "Iop_V256toV128_0" | "Iop_V256toV128_1" => mk("unpack", 128, None, None),
        "Iop_SliceV128" => mk("slice", 128, None, None),
        "Iop_Reverse32sIn64_x2" => mk("reverse", 128, None, None),
        "Iop_InterleaveHI8x8" => mk("InterleaveHI", 64, Some(8), Some(8)),
        "Iop_InterleaveHI8x16" => mk("InterleaveHI", 128, Some(8), Some(16)),
        "Iop_InterleaveHI16x4" => mk("InterleaveHI", 64, Some(16), Some(4)),
        "Iop_InterleaveHI16x8" => mk("InterleaveHI", 128, Some(16), Some(8)),
        "Iop_InterleaveHI32x2" => mk("InterleaveHI", 64, Some(32), Some(2)),
        "Iop_InterleaveHI32x4" => mk("InterleaveHI", 128, Some(32), Some(4)),
        "Iop_InterleaveHI64x2" => mk("InterleaveHI", 128, Some(64), Some(2)),
        _ => None,
    }
}

/// Faithful port of `vexop_to_simop(op)`. `Err(())` => unsupported (the
/// converter emits a `DirtyExpression`).
pub(crate) fn vexop_to_simop(op_int: u32) -> Result<SimOpInfo, ()> {
    let name = op_name(op_int).ok_or(())?;

    // make_operations: attrs from explicit_attrs-or-op_attrs; if it builds, it
    // is cached in `operations` and returned directly.
    let primary = explicit_attrs(name).or_else(|| op_attrs(name));
    if let Some(a) = &primary
        && let Ok(info) = build(name, op_int, a)
    {
        return Ok(info);
    }

    // Not in the cache -> extended re-parse uses op_attrs only.
    let a2 = op_attrs(name).ok_or(())?;
    build(name, op_int, &a2)
}
