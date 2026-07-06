//! Phase D spike: ``AilExpression`` fat-enum + single ``Expression`` pyclass.
//!
//! Design:
//!
//! * [`AilExpression`] is a pure Rust struct holding the shared header
//!   (idx, tags, bits, depth, cached hash) plus an [`ExprInner`] variant
//!   carrying all variant-specific fields **inline**, with operand
//!   subtrees stored as ``Box<AilExpression>`` -- no ``Py<T>`` for
//!   operand fields.
//!
//! * [`Expression`] is the single ``#[pyclass]`` exposed to Python. It
//!   wraps an [`AilExpression`] and provides Rust-side getters/setters
//!   that dispatch on the variant. Python-side marker classes
//!   (``Const``, ``BinaryOp``, ``Load``, ...) override ``__new__`` to
//!   call one of the per-variant ``_new_*`` factories below, and use a
//!   metaclass to make ``isinstance(load, Load)`` work.
//!
//! Spike scope: ``Const``, ``BinaryOp``, ``Load`` only. The remaining
//! ~24 Expression subclasses are added in a follow-up bulk commit.

use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyAttributeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString, PyTuple};

use crate::ailment::base::CachedHash;
use crate::ailment::const_value::ConstValue;
use crate::ailment::enums::{ConvertType, ExpressionKind, RoundingMode};
use crate::ailment::hash::{HashItem, stable_hash};
use crate::ailment::tags::{Tags, TagsView};
use indexmap::IndexMap;

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// Shared header on every concrete AIL Expression variant. Not exposed
/// to Python directly; lives inside [`AilExpression`].
#[derive(Clone, Debug)]
pub struct ExprHeader {
    pub idx: i64,
    pub tags: Tags,
    pub bits: u32,
    pub depth: u32,
    pub cached_hash: CachedHash,
}

impl ExprHeader {
    pub fn new(idx: i64, depth: u32, bits: u32, tags: Tags) -> Self {
        Self {
            idx,
            tags,
            bits,
            depth,
            cached_hash: CachedHash::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Variant payload
// ---------------------------------------------------------------------------

/// Concrete Expression variants. New variants are added here in the
/// bulk Phase D migration commit.
///
/// Layout note: operand subtrees are owned via ``Box<AilExpression>``
/// (one heap allocation per subtree). Variable information used to live
/// on each variant (``variable`` / ``variable_offset``); it now lives in
/// a side ``VariableMap`` keyed on ``ExprHeader::idx``.
#[derive(Clone, Debug)]
pub enum ExprInner {
    Const {
        value: ConstValue,
    },
    Tmp {
        tmp_idx: i64,
    },
    Register {
        reg_offset: i64,
    },
    ComboRegister {
        /// Each element must be an AIL ``Register``. The variant invariant
        /// is enforced by ``_new_combo_register`` at construction time.
        registers: Vec<AilExpression>,
    },
    /// SSA phi node. ``src_and_vvars`` is a list of
    /// ``((block_addr, block_idx), vvar_id)`` triples; consumers only
    /// ever read ``.varid`` from the second slot, so we store the
    /// integer ``vvar_id`` directly rather than a full
    /// ``VirtualVariable`` Expression.
    Phi {
        src_and_vvars: Vec<PhiEntry>,
    },
    VirtualVariable {
        varid: i64,
        category: crate::ailment::enums::VirtualVariableCategory,
        /// Per-category payload; see ``OIdent``.
        oident: OIdent,
        /// Sub-register vvars for ``COMBO_REGISTER`` category. ``None``
        /// for any other category (semantically "not applicable"); for
        /// ``COMBO_REGISTER`` an empty ``Vec`` represents "not yet
        /// populated", which is the initial state set by clinic's
        /// COMBO_REGISTER parameter-vvar synthesis before sub-register
        /// vvars are computed. Each element is invariantly an
        /// ``AilExpression`` of variant ``VirtualVariable``; the
        /// constructor enforces this once at construction.
        reg_vvars: Option<Vec<Box<AilExpression>>>,
    },
    UnaryOp {
        op: String,
        operand: Box<AilExpression>,
    },
    Convert {
        operand: Box<AilExpression>,
        from_bits: u32,
        to_bits: u32,
        is_signed: bool,
        from_type: ConvertType,
        to_type: ConvertType,
        rounding_mode: Option<RoundingMode>,
    },
    Reinterpret {
        operand: Box<AilExpression>,
        from_bits: u32,
        from_type: String,
        to_bits: u32,
        to_type: String,
    },
    BinaryOp {
        op: String,
        operands: [Box<AilExpression>; 2],
        signed: bool,
        floating_point: bool,
        rounding_mode: Option<RoundingMode>,
        vector_count: Option<i64>,
        vector_size: Option<i64>,
    },
    Load {
        addr: Box<AilExpression>,
        size: i32,
        endness: String,
        guard: Option<Box<AilExpression>>,
        alt: Option<Box<AilExpression>>,
    },
    Call {
        /// Expression (typically Const for direct calls) or str (for
        /// symbolic SimProcedure targets). Promoted from ``Py<PyAny>`` to
        /// a typed sum so ``likes`` / ``matches`` / ``replace_ail`` /
        /// ``_hash_core`` can dispatch without re-extracting from
        /// Python on every call.
        target: CFGTarget,
        args: Option<Vec<AilExpression>>,
        arg_vvars: Option<Vec<AilExpression>>,
    },
    DirtyExpression {
        callee: String,
        operands: Vec<AilExpression>,
        guard: Option<Box<AilExpression>>,
        mfx: Option<String>,
        maddr: Option<Box<AilExpression>>,
        msize: Option<i64>,
    },
    VEXCCallExpression {
        callee: String,
        operands: Vec<AilExpression>,
    },
    MultiStatementExpression {
        stmts: Vec<crate::ailment::ail_stmt::AilStatement>,
        expr: Box<AilExpression>,
    },
    Struct {
        name: String,
        /// Struct fields, keyed by byte offset, ordered by insertion
        /// (matches the Python ``OrderedDict`` callers pass in).
        fields: IndexMap<i64, Box<AilExpression>>,
        /// Field name -> byte offset, ordered by insertion.
        field_offsets: IndexMap<String, i64>,
        /// Byte offset -> field name. Derived in the constructor as
        /// the reverse of ``field_offsets`` and kept eagerly in sync.
        field_names: IndexMap<i64, String>,
    },
    RustEnum {
        name: String,
        /// Variant fields. The marker class accepts a list or tuple of
        /// ``Expression`` -- the constructor normalizes to a typed
        /// ``Vec<Box<AilExpression>>`` so the data round-trips through
        /// Rust without re-extracting via Python on every read.
        fields: Vec<Box<AilExpression>>,
    },
    Array {
        elements: Vec<Box<AilExpression>>,
    },
    Let {
        /// List of bound definitions -- each entry is an AIL
        /// ``Statement`` (the test fixture and ``rust.py`` codegen
        /// path use ``Assignment`` / ``Store``). The bound
        /// ``EnumVariant`` itself lives in the ``VariableMap`` side
        /// container keyed by the ``Let`` expression's ``.idx``.
        defs: Vec<Box<crate::ailment::ail_stmt::AilStatement>>,
        src: Box<AilExpression>,
    },
    Macro {
        name: String,
        delimiter: String,
    },
    FunctionLikeMacro {
        name: String,
        delimiter: String,
        /// Macro call arguments. ``None`` means "no args list specified"
        /// (distinct from ``Some(vec![])``, an empty argument list).
        /// Each entry is an ``AilExpression``; the constructor accepts
        /// any iterable of ``Expression``.
        args: Option<Vec<Box<AilExpression>>>,
    },
    ITE {
        cond: Box<AilExpression>,
        iffalse: Box<AilExpression>,
        iftrue: Box<AilExpression>,
    },
    Extract {
        base: Box<AilExpression>,
        offset: Box<AilExpression>,
        endness: String,
    },
    Insert {
        base: Box<AilExpression>,
        offset: Box<AilExpression>,
        value: Box<AilExpression>,
        endness: String,
    },
    StringLiteral {
        /// String content. In practice every in-tree caller passes a
        /// Python ``str`` (decoded function names like ``"Vec::new"``,
        /// outlined call targets, or the empty string sentinel); the
        /// constructor enforces this with a ``str`` extract so the
        /// data lives in native Rust without per-access Python
        /// round-trips.
        data: String,
    },
    BasePointerOffset {
        /// Named base pointer (e.g. ``"stack_base"``, ``"tls_base"``).
        /// The original ``Py<PyAny>`` storage advertised
        /// ``int or Expression`` flexibility but every in-tree caller
        /// passes a string; the typed storage avoids per-access
        /// Python round-trips for ``.base``.
        base: String,
        /// Signed numeric offset. Same story as ``base``: every
        /// caller passes a Python ``int``; ``i64`` covers the range
        /// safely.
        offset: i64,
    },
    /// A ``BasePointerOffset`` specialized to the stack pointer. The
    /// ``offset`` lives in the variant; the base is implicit (sp).
    StackBaseOffset {
        offset: i128,
    },
}

impl ExprInner {
    /// Variant tag used for ``isinstance`` dispatch on the Python side.
    /// Keep in sync with the marker classes' ``_kind`` attribute.
    pub fn kind(&self) -> ExpressionKind {
        match self {
            ExprInner::Const { .. } => ExpressionKind::Const,
            ExprInner::Tmp { .. } => ExpressionKind::Tmp,
            ExprInner::Register { .. } => ExpressionKind::Register,
            ExprInner::ComboRegister { .. } => ExpressionKind::ComboRegister,
            ExprInner::Phi { .. } => ExpressionKind::Phi,
            ExprInner::VirtualVariable { .. } => ExpressionKind::VirtualVariable,
            ExprInner::UnaryOp { .. } => ExpressionKind::UnaryOp,
            ExprInner::Convert { .. } => ExpressionKind::Convert,
            ExprInner::Reinterpret { .. } => ExpressionKind::Reinterpret,
            ExprInner::BinaryOp { .. } => ExpressionKind::BinaryOp,
            ExprInner::Load { .. } => ExpressionKind::Load,
            ExprInner::Call { .. } => ExpressionKind::Call,
            ExprInner::DirtyExpression { .. } => ExpressionKind::DirtyExpression,
            ExprInner::VEXCCallExpression { .. } => ExpressionKind::VEXCCallExpression,
            ExprInner::MultiStatementExpression { .. } => ExpressionKind::MultiStatementExpression,
            ExprInner::Struct { .. } => ExpressionKind::Struct,
            ExprInner::RustEnum { .. } => ExpressionKind::RustEnum,
            ExprInner::Array { .. } => ExpressionKind::Array,
            ExprInner::Let { .. } => ExpressionKind::Let,
            ExprInner::Macro { .. } => ExpressionKind::Macro,
            ExprInner::FunctionLikeMacro { .. } => ExpressionKind::FunctionLikeMacro,
            ExprInner::ITE { .. } => ExpressionKind::ITE,
            ExprInner::Extract { .. } => ExpressionKind::Extract,
            ExprInner::Insert { .. } => ExpressionKind::Insert,
            ExprInner::StringLiteral { .. } => ExpressionKind::StringLiteral,
            ExprInner::BasePointerOffset { .. } => ExpressionKind::BasePointerOffset,
            ExprInner::StackBaseOffset { .. } => ExpressionKind::StackBaseOffset,
        }
    }
}

// ---------------------------------------------------------------------------
// CFGTarget -- typed sum used by Jump.target,
// ConditionalJump.{true,false}_target, and Call.target
// ---------------------------------------------------------------------------

/// A control-flow target slot. Three AIL constructs carry this shape:
/// ``Jump.target``, ``ConditionalJump.{true,false}_target``, and
/// ``Call.target``. Targets are either AIL expressions (typically a
/// ``Const`` for resolved jumps/calls; ``Register`` / ``VirtualVariable``
/// for indirect calls) or a plain string (SimProcedure name / symbolic
/// label that doesn't bind to a concrete address).
///
/// Legacy AIL stored these as untyped ``Py<PyAny>``; promoting them to a
/// typed enum encodes the polymorphism Rust-side so ``likes`` /
/// ``matches`` / ``replace_ail`` / ``_hash_core`` dispatch without
/// re-extracting from Python on every call, and removes the
/// ``py_target_likes`` / ``py_slot_likes`` helper chains that previously
/// sat in each comparison method.
#[derive(Clone, Debug)]
pub enum CFGTarget {
    Expr(Box<AilExpression>),
    Symbol(String),
}

impl CFGTarget {
    /// Extract from a Python value. Accepts an ``Expression`` wrapper or
    /// a ``str``; rejects everything else.
    pub fn from_py(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(s) = obj.extract::<String>() {
            return Ok(CFGTarget::Symbol(s));
        }
        if let Ok(cell) = obj.cast::<Expression>() {
            return Ok(CFGTarget::Expr(Box::new(cell.borrow().expr.clone())));
        }
        Err(PyTypeError::new_err(
            "CFG target must be an Expression or str",
        ))
    }

    /// Materialize as a Python object: an ``Expression`` wrapper for
    /// ``Expr``, a ``str`` for ``Symbol``.
    pub fn to_py<'py>(&self, py: Python<'py>) -> PyResult<Py<PyAny>> {
        match self {
            CFGTarget::Expr(e) => {
                let wrapper = Py::new(py, Expression::wrap((**e).clone()))?;
                Ok(wrapper.into_any())
            }
            CFGTarget::Symbol(s) => Ok(PyString::new(py, s).into_any().unbind()),
        }
    }

    /// Structural-with-identity equality (idx-strict via inner
    /// ``AilExpression::likes``).
    pub fn likes(&self, other: &CFGTarget) -> bool {
        match (self, other) {
            (CFGTarget::Expr(a), CFGTarget::Expr(b)) => a.likes(b),
            (CFGTarget::Symbol(a), CFGTarget::Symbol(b)) => a == b,
            _ => false,
        }
    }

    /// Structural-only equality (idx-agnostic via inner
    /// ``AilExpression::matches``).
    pub fn matches(&self, other: &CFGTarget) -> bool {
        match (self, other) {
            (CFGTarget::Expr(a), CFGTarget::Expr(b)) => a.matches(b),
            (CFGTarget::Symbol(a), CFGTarget::Symbol(b)) => a == b,
            _ => false,
        }
    }

    /// Recursively substitute ``old`` with ``new`` inside an ``Expr``
    /// target. Walks operand subtrees only -- the top-level target is
    /// NOT checked against ``old``. This mirrors the legacy Jump /
    /// ConditionalJump / Call target handling where the slot itself
    /// isn't a substitution candidate; only nodes underneath it are.
    /// Symbol targets are leaves.
    pub fn replace_ail(&self, old: &AilExpression, new: &AilExpression) -> (bool, CFGTarget) {
        match self {
            CFGTarget::Expr(e) => {
                let (c, r) = e.replace_ail(old, new);
                if c {
                    (true, CFGTarget::Expr(Box::new(r)))
                } else {
                    (false, self.clone())
                }
            }
            CFGTarget::Symbol(_) => (false, self.clone()),
        }
    }

    /// True iff this target is an expression that ``likes``-matches
    /// ``atom`` or contains an inner sub-expression that does.
    pub fn has_atom_ail(&self, atom: &AilExpression, identity: bool) -> bool {
        match self {
            CFGTarget::Expr(e) => e.has_atom_ail(atom, identity),
            CFGTarget::Symbol(_) => false,
        }
    }

    /// Stable hash item for inclusion in the parent statement's hash.
    pub fn hash_item(&self) -> HashItem<'_> {
        match self {
            CFGTarget::Expr(e) => HashItem::U64Hash(e.cached_hash_or_compute() as u64),
            CFGTarget::Symbol(s) => HashItem::Str(s.as_str()),
        }
    }
}

// ---------------------------------------------------------------------------
// OIdent -- typed payload for ExprInner::VirtualVariable.oident
// ---------------------------------------------------------------------------

/// Typed payload for ``VirtualVariable.oident``. Shape depends on the
/// surrounding ``category``:
///
/// | category        | OIdent variant                          |
/// |-----------------|-----------------------------------------|
/// | UNKNOWN         | ``OIdent::None``                        |
/// | REGISTER        | ``OIdent::Int`` (reg_offset)            |
/// | STACK           | ``OIdent::Int`` (signed stack_offset)   |
/// | MEMORY          | ``OIdent::Int`` (memory address)        |
/// | TMP             | ``OIdent::Int`` (tmp_idx)               |
/// | COMBO_REGISTER  | ``OIdent::RegList`` (tuple of offsets)  |
/// | PARAMETER       | ``OIdent::Parameter`` (nested)          |
///
/// The legacy AIL stored ``oident`` as an untyped Python object;
/// promoting to a typed sum lets ``likes`` / ``matches`` /
/// ``_hash_core`` / the accessor getters (``reg_offset``,
/// ``stack_offset``, ``tmp_idx``, ``reg_offsets``, ``parameter_category``,
/// etc.) dispatch on the variant without re-extracting from Python on
/// every call. The constructor parses based on the surrounding
/// ``category`` so callers keep passing the same shape they always did
/// (``int``, ``tuple``, or ``None``).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OIdent {
    /// UNKNOWN / explicit ``None``.
    None,
    /// REGISTER / STACK / MEMORY / TMP -- single integer payload. Stack
    /// offsets are signed; the parser reinterprets large unsigned values
    /// (e.g. ``2^64 - 8`` for ``-8``) as the corresponding ``i64``.
    Int(i64),
    /// COMBO_REGISTER -- tuple of reg_offsets.
    RegList(Vec<i64>),
    /// PARAMETER -- nested ``(inner_category, inner_payload)``. The
    /// inner category may be REGISTER, STACK, or COMBO_REGISTER.
    Parameter(ParameterOIdent),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParameterOIdent {
    Register(i64),
    Stack(i64),
    ComboRegister(Vec<i64>),
}

impl ParameterOIdent {
    pub fn inner_category(&self) -> crate::ailment::enums::VirtualVariableCategory {
        use crate::ailment::enums::VirtualVariableCategory;
        match self {
            Self::Register(_) => VirtualVariableCategory::REGISTER,
            Self::Stack(_) => VirtualVariableCategory::STACK,
            Self::ComboRegister(_) => VirtualVariableCategory::COMBO_REGISTER,
        }
    }
}

impl OIdent {
    /// Extract from a Python value using the surrounding ``category`` as
    /// the dispatch key. Stack offsets are sign-normalized: large
    /// unsigned values (e.g. ``2^64 - 8``) are reinterpreted as the
    /// corresponding ``i64`` (``-8``).
    pub fn from_py(
        py: Python<'_>,
        obj: &Bound<'_, PyAny>,
        category: crate::ailment::enums::VirtualVariableCategory,
    ) -> PyResult<Self> {
        use crate::ailment::enums::VirtualVariableCategory;
        if obj.is_none() {
            return Ok(Self::None);
        }
        // Helper: extract a signed i64 from a Python int that may have
        // been stored as a large unsigned value (legacy stack offsets).
        fn signed(obj: &Bound<'_, PyAny>) -> PyResult<i64> {
            if let Ok(v) = obj.extract::<i64>() {
                return Ok(v);
            }
            if let Ok(v) = obj.extract::<u64>() {
                return Ok(v as i64);
            }
            let big: i128 = obj.extract()?;
            Ok(big as i64)
        }
        fn extract_reg_list(t: &Bound<'_, PyTuple>) -> PyResult<Vec<i64>> {
            let mut out = Vec::with_capacity(t.len());
            for x in t.iter() {
                out.push(x.extract::<i64>()?);
            }
            Ok(out)
        }
        let _ = py;
        match category {
            VirtualVariableCategory::REGISTER
            | VirtualVariableCategory::MEMORY
            | VirtualVariableCategory::TMP => Ok(Self::Int(obj.extract::<i64>()?)),
            VirtualVariableCategory::STACK => Ok(Self::Int(signed(obj)?)),
            VirtualVariableCategory::COMBO_REGISTER => {
                let t = obj.cast::<PyTuple>().map_err(|_| {
                    PyTypeError::new_err("COMBO_REGISTER oident must be a tuple of int")
                })?;
                Ok(Self::RegList(extract_reg_list(t)?))
            }
            VirtualVariableCategory::PARAMETER => {
                let t = obj.cast::<PyTuple>().map_err(|_| {
                    PyTypeError::new_err(
                        "PARAMETER oident must be a 2-tuple (inner_category, inner_payload)",
                    )
                })?;
                if t.len() != 2 {
                    return Err(PyTypeError::new_err(
                        "PARAMETER oident tuple must have exactly 2 elements",
                    ));
                }
                let inner_cat_obj = t.get_item(0)?;
                let inner_cat = if let Ok(c) = inner_cat_obj.extract::<VirtualVariableCategory>() {
                    c
                } else if let Ok(v) = inner_cat_obj.extract::<i64>() {
                    VirtualVariableCategory::from_int(v).ok_or_else(|| {
                        PyTypeError::new_err(format!(
                            "PARAMETER oident inner category int {} is not a valid VirtualVariableCategory",
                            v
                        ))
                    })?
                } else {
                    return Err(PyTypeError::new_err(
                        "PARAMETER oident inner category must be a VirtualVariableCategory",
                    ));
                };
                let inner_payload = t.get_item(1)?;
                let inner = match inner_cat {
                    VirtualVariableCategory::REGISTER => {
                        ParameterOIdent::Register(inner_payload.extract::<i64>()?)
                    }
                    VirtualVariableCategory::STACK => {
                        ParameterOIdent::Stack(signed(&inner_payload)?)
                    }
                    VirtualVariableCategory::COMBO_REGISTER => {
                        let tt = inner_payload.cast::<PyTuple>().map_err(|_| {
                            PyTypeError::new_err(
                                "PARAMETER+COMBO_REGISTER inner payload must be a tuple of int",
                            )
                        })?;
                        ParameterOIdent::ComboRegister(extract_reg_list(tt)?)
                    }
                    _ => {
                        return Err(PyTypeError::new_err(format!(
                            "PARAMETER oident inner category {:?} is not supported",
                            inner_cat
                        )));
                    }
                };
                Ok(Self::Parameter(inner))
            }
            VirtualVariableCategory::UNKNOWN => Ok(Self::None),
        }
    }

    /// Materialize back to the Python representation. Inverse of
    /// ``from_py``.
    pub fn to_py<'py>(&self, py: Python<'py>) -> PyResult<Py<PyAny>> {
        match self {
            Self::None => Ok(py.None()),
            Self::Int(v) => Ok(v.into_py_any(py)?),
            Self::RegList(v) => {
                let items: Vec<Py<PyAny>> = v
                    .iter()
                    .map(|x| x.into_py_any(py))
                    .collect::<PyResult<_>>()?;
                Ok(PyTuple::new(py, items)?.into_any().unbind())
            }
            Self::Parameter(p) => {
                let inner_cat = p.inner_category();
                let cat_obj = Py::new(py, inner_cat)?.into_any();
                let inner_obj: Py<PyAny> = match p {
                    ParameterOIdent::Register(off) => off.into_py_any(py)?,
                    ParameterOIdent::Stack(off) => off.into_py_any(py)?,
                    ParameterOIdent::ComboRegister(offs) => {
                        let items: Vec<Py<PyAny>> = offs
                            .iter()
                            .map(|x| x.into_py_any(py))
                            .collect::<PyResult<_>>()?;
                        PyTuple::new(py, items)?.into_any().unbind()
                    }
                };
                Ok(PyTuple::new(py, [cat_obj, inner_obj])?.into_any().unbind())
            }
        }
    }

    /// Stable hash item for inclusion in the parent VirtualVariable's
    /// hash.
    pub fn hash_item<'a>(&'a self) -> HashItem<'a> {
        match self {
            Self::None => HashItem::None,
            Self::Int(v) => HashItem::Int(*v as i128),
            Self::RegList(v) => {
                HashItem::Tuple(v.iter().map(|x| HashItem::Int(*x as i128)).collect())
            }
            Self::Parameter(p) => {
                let inner_cat = p.inner_category() as i64;
                let inner_item = match p {
                    ParameterOIdent::Register(off) | ParameterOIdent::Stack(off) => {
                        HashItem::Int(*off as i128)
                    }
                    ParameterOIdent::ComboRegister(offs) => {
                        HashItem::Tuple(offs.iter().map(|x| HashItem::Int(*x as i128)).collect())
                    }
                };
                HashItem::Tuple(vec![HashItem::Int(inner_cat as i128), inner_item])
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PhiEntry -- typed payload for ExprInner::Phi.src_and_vvars
// ---------------------------------------------------------------------------

/// One source-block / vvar pair in a phi node.
///
/// ``vvar`` is a ``VirtualVariable`` AilExpression (or ``None``).
/// Downstream analyses (variable_recovery, dephication,
/// ite_region_converter, return_duplicator) read the source vvar's
/// ``.bits`` / ``.category`` / ``.oident`` / ``.reg_offset`` to drive
/// register fallbacks, typevar propagation, and re-substitution, so
/// storing only the varid loses too much information. The variant
/// invariant -- the inner expression is always a ``VirtualVariable`` --
/// is enforced by ``extract_phi_entries`` at construction time.
#[derive(Clone, Debug)]
pub struct PhiEntry {
    pub src_addr: i64,
    pub src_idx: Option<i64>,
    pub vvar: Option<Box<AilExpression>>,
}

// ---------------------------------------------------------------------------
// AilExpression -- pure Rust, not exposed
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AilExpression {
    pub header: ExprHeader,
    pub inner: ExprInner,
}

impl AilExpression {
    pub fn kind(&self) -> ExpressionKind {
        self.inner.kind()
    }

    pub fn kind_str(&self) -> &'static str {
        self.inner.kind().as_str()
    }

    /// Compute the structural hash. Cached on [`ExprHeader::cached_hash`].
    pub fn _hash_core(&self) -> i64 {
        match &self.inner {
            ExprInner::Const { value, .. } => stable_hash(&[
                HashItem::TypeName("Const"),
                value.hash_item(),
                HashItem::Int(self.header.bits as i128),
            ]),
            ExprInner::Tmp { tmp_idx, .. } => stable_hash(&[
                HashItem::Str("tmp"),
                HashItem::Int(*tmp_idx as i128),
                HashItem::Int(self.header.bits as i128),
            ]),
            ExprInner::Register { reg_offset, .. } => stable_hash(&[
                HashItem::Str("reg"),
                HashItem::Int(*reg_offset as i128),
                HashItem::Int(self.header.bits as i128),
            ]),
            ExprInner::ComboRegister { registers, .. } => {
                let mut inner = Vec::with_capacity(registers.len());
                for r in registers {
                    inner.push(HashItem::U64Hash(r.cached_hash_or_compute() as u64));
                }
                stable_hash(&[
                    HashItem::Str("combo_reg"),
                    HashItem::Tuple(inner),
                    HashItem::Int(self.header.bits as i128),
                    HashItem::Int(self.header.idx as i128),
                ])
            }
            ExprInner::Phi { src_and_vvars, .. } => {
                let mut items: Vec<HashItem> = Vec::with_capacity(src_and_vvars.len() * 3);
                for entry in src_and_vvars {
                    items.push(HashItem::Int(entry.src_addr as i128));
                    items.push(match entry.src_idx {
                        Some(v) => HashItem::Int(v as i128),
                        None => HashItem::None,
                    });
                    items.push(match &entry.vvar {
                        Some(v) => HashItem::U64Hash(v.cached_hash_or_compute() as u64),
                        None => HashItem::None,
                    });
                }
                stable_hash(&[
                    HashItem::TypeName("Phi"),
                    HashItem::Tuple(items),
                    HashItem::Int(self.header.bits as i128),
                ])
            }
            ExprInner::VirtualVariable {
                varid,
                category,
                oident,
                ..
            } => stable_hash(&[
                HashItem::Str("var"),
                HashItem::Int(*varid as i128),
                HashItem::Int(self.header.bits as i128),
                HashItem::Int(*category as u8 as i128),
                oident.hash_item(),
            ]),
            ExprInner::UnaryOp { op, operand, .. } => {
                let oh = operand.cached_hash_or_compute();
                stable_hash(&[
                    HashItem::Str(op.as_str()),
                    HashItem::U64Hash(oh as u64),
                    HashItem::Int(self.header.bits as i128),
                ])
            }
            ExprInner::Convert {
                operand,
                from_bits,
                to_bits,
                is_signed,
                from_type,
                to_type,
                rounding_mode,
                ..
            } => {
                let oh = operand.cached_hash_or_compute();
                let rm = match rounding_mode {
                    Some(r) => HashItem::Int(*r as u8 as i128),
                    None => HashItem::None,
                };
                stable_hash(&[
                    HashItem::U64Hash(oh as u64),
                    HashItem::Int(*from_bits as i128),
                    HashItem::Int(*to_bits as i128),
                    HashItem::Int(self.header.bits as i128),
                    HashItem::Bool(*is_signed),
                    HashItem::Int(*from_type as u8 as i128),
                    HashItem::Int(*to_type as u8 as i128),
                    rm,
                ])
            }
            ExprInner::Reinterpret {
                operand,
                from_bits,
                from_type,
                to_bits,
                to_type,
                ..
            } => {
                let oh = operand.cached_hash_or_compute();
                stable_hash(&[
                    HashItem::U64Hash(oh as u64),
                    HashItem::Int(*from_bits as i128),
                    HashItem::Str(from_type.as_str()),
                    HashItem::Int(*to_bits as i128),
                    HashItem::Str(to_type.as_str()),
                ])
            }
            ExprInner::BinaryOp {
                op,
                operands,
                signed,
                floating_point,
                ..
            } => {
                let lhs_h = operands[0].cached_hash_or_compute();
                let rhs_h = operands[1].cached_hash_or_compute();
                stable_hash(&[
                    HashItem::Str(op.as_str()),
                    HashItem::Tuple(vec![
                        HashItem::U64Hash(lhs_h as u64),
                        HashItem::U64Hash(rhs_h as u64),
                    ]),
                    HashItem::Int(self.header.bits as i128),
                    HashItem::Bool(*signed),
                    HashItem::Bool(*floating_point),
                ])
            }
            ExprInner::Load {
                addr,
                size,
                endness,
                ..
            } => {
                let addr_h = addr.cached_hash_or_compute();
                stable_hash(&[
                    HashItem::Str("Load"),
                    HashItem::U64Hash(addr_h as u64),
                    HashItem::Int(*size as i128),
                    HashItem::Str(endness.as_str()),
                ])
            }
            ExprInner::DirtyExpression {
                callee,
                operands,
                guard,
                mfx,
                maddr,
                msize,
            } => {
                let op_items: Vec<HashItem> = operands
                    .iter()
                    .map(|o| HashItem::U64Hash(o.cached_hash_or_compute() as u64))
                    .collect();
                let guard_item = match guard {
                    Some(g) => HashItem::U64Hash(g.cached_hash_or_compute() as u64),
                    None => HashItem::None,
                };
                let maddr_item = match maddr {
                    Some(m) => HashItem::U64Hash(m.cached_hash_or_compute() as u64),
                    None => HashItem::None,
                };
                let mfx_item = match mfx {
                    Some(s) => HashItem::Str(s.as_str()),
                    None => HashItem::None,
                };
                let msize_item = match msize {
                    Some(v) => HashItem::Int(*v as i128),
                    None => HashItem::None,
                };
                stable_hash(&[
                    HashItem::TypeName("DirtyExpression"),
                    HashItem::Str(callee.as_str()),
                    guard_item,
                    HashItem::Tuple(op_items),
                    mfx_item,
                    maddr_item,
                    msize_item,
                    HashItem::Int(self.header.bits as i128),
                ])
            }
            ExprInner::VEXCCallExpression { callee, operands } => {
                let op_items: Vec<HashItem> = operands
                    .iter()
                    .map(|o| HashItem::U64Hash(o.cached_hash_or_compute() as u64))
                    .collect();
                stable_hash(&[
                    HashItem::TypeName("VEXCCallExpression"),
                    HashItem::Str(callee.as_str()),
                    HashItem::Int(self.header.bits as i128),
                    HashItem::Tuple(op_items),
                ])
            }
            ExprInner::Struct {
                name,
                fields,
                field_offsets,
                ..
            } => {
                let fi: Vec<HashItem> = fields
                    .iter()
                    .map(|(off, e)| {
                        HashItem::Tuple(vec![
                            HashItem::Int(*off as i128),
                            HashItem::U64Hash(e.cached_hash_or_compute() as u64),
                        ])
                    })
                    .collect();
                let oi: Vec<HashItem> = field_offsets
                    .iter()
                    .map(|(name, off)| {
                        HashItem::Tuple(vec![
                            HashItem::Str(name.as_str()),
                            HashItem::Int(*off as i128),
                        ])
                    })
                    .collect();
                stable_hash(&[
                    HashItem::Str(name.as_str()),
                    HashItem::Tuple(fi),
                    HashItem::Tuple(oi),
                    HashItem::Int(self.header.bits as i128),
                ])
            }
            ExprInner::RustEnum { name, fields } => {
                let inner: Vec<HashItem> = fields
                    .iter()
                    .map(|f| HashItem::U64Hash(f.cached_hash_or_compute() as u64))
                    .collect();
                stable_hash(&[
                    HashItem::Str(name.as_str()),
                    HashItem::Tuple(inner),
                    HashItem::Int(self.header.bits as i128),
                ])
            }
            ExprInner::Array { elements } => {
                let inner: Vec<HashItem> = elements
                    .iter()
                    .map(|e| HashItem::U64Hash(e.cached_hash_or_compute() as u64))
                    .collect();
                stable_hash(&[
                    HashItem::Tuple(inner),
                    HashItem::Int(self.header.bits as i128),
                ])
            }
            ExprInner::Let { src, .. } => stable_hash(&[
                HashItem::TypeName("Let"),
                HashItem::Int(self.header.idx as i128),
                HashItem::U64Hash(src.cached_hash_or_compute() as u64),
            ]),
            ExprInner::Macro { name, .. } => stable_hash(&[
                HashItem::TypeName("Macro"),
                HashItem::Int(self.header.idx as i128),
                HashItem::Str(name.as_str()),
            ]),
            ExprInner::FunctionLikeMacro { name, .. } => stable_hash(&[
                HashItem::TypeName("FunctionLikeMacro"),
                HashItem::Int(self.header.idx as i128),
                HashItem::Str(name.as_str()),
            ]),
            ExprInner::MultiStatementExpression { stmts, expr } => {
                let mut items = vec![HashItem::TypeName("MultiStatementExpression")];
                for s in stmts {
                    items.push(HashItem::U64Hash(s.cached_hash_or_compute() as u64));
                }
                items.push(HashItem::U64Hash(expr.cached_hash_or_compute() as u64));
                stable_hash(&items)
            }
            ExprInner::Call { target, args, .. } => {
                let args_h = match args {
                    Some(a) => {
                        let parts: Vec<HashItem> = a
                            .iter()
                            .map(|x| HashItem::U64Hash(x.cached_hash_or_compute() as u64))
                            .collect();
                        HashItem::Tuple(parts)
                    }
                    None => HashItem::None,
                };
                stable_hash(&[
                    HashItem::TypeName("Call"),
                    HashItem::Int(self.header.idx as i128),
                    target.hash_item(),
                    args_h,
                ])
            }
            ExprInner::ITE {
                cond,
                iffalse,
                iftrue,
                ..
            } => stable_hash(&[
                HashItem::TypeName("ITE"),
                HashItem::U64Hash(cond.cached_hash_or_compute() as u64),
                HashItem::U64Hash(iffalse.cached_hash_or_compute() as u64),
                HashItem::U64Hash(iftrue.cached_hash_or_compute() as u64),
                HashItem::Int(self.header.bits as i128),
            ]),
            ExprInner::Extract {
                base,
                offset,
                endness,
            } => stable_hash(&[
                HashItem::Int(self.header.bits as i128),
                HashItem::U64Hash(base.cached_hash_or_compute() as u64),
                HashItem::U64Hash(offset.cached_hash_or_compute() as u64),
                HashItem::Str(endness.as_str()),
            ]),
            ExprInner::Insert {
                base,
                offset,
                value,
                endness,
            } => stable_hash(&[
                HashItem::Int(self.header.bits as i128),
                HashItem::U64Hash(base.cached_hash_or_compute() as u64),
                HashItem::U64Hash(offset.cached_hash_or_compute() as u64),
                HashItem::U64Hash(value.cached_hash_or_compute() as u64),
                HashItem::Str(endness.as_str()),
            ]),
            ExprInner::StringLiteral { data } => stable_hash(&[
                HashItem::TypeName("StringLiteral"),
                HashItem::Str(data.as_str()),
                HashItem::Int(self.header.bits as i128),
            ]),
            ExprInner::BasePointerOffset { base, offset, .. } => stable_hash(&[
                HashItem::TypeName("BasePointerOffset"),
                HashItem::Int(self.header.bits as i128),
                HashItem::Str(base.as_str()),
                HashItem::Int(*offset as i128),
            ]),
            ExprInner::StackBaseOffset { offset } => stable_hash(&[
                HashItem::TypeName("StackBaseOffset"),
                HashItem::Int(*offset),
                HashItem::Int(self.header.bits as i128),
            ]),
        }
    }

    /// Recursive ``replace`` -- walk the operand subtrees, substituting
    /// any node that ``__eq__``-matches ``old`` (same kind + same idx +
    /// structural ``likes``). Returns ``(changed, rebuilt)`` -- when
    /// nothing changed, callers can short-circuit and reuse the original
    /// Python wrapper instead of allocating a new one.
    pub fn replace_ail(&self, old: &AilExpression, new: &AilExpression) -> (bool, AilExpression) {
        // Use ``likes`` (structural equality, idx-agnostic) for the match
        // check -- legacy ``replace`` semantics treat any node with the
        // same shape as a hit, regardless of ``idx``.
        if self.likes(old) {
            return (true, new.clone());
        }
        let walk = |child: &AilExpression| -> (bool, Box<AilExpression>) {
            let (c, r) = child.replace_ail(old, new);
            (c, Box::new(r))
        };
        let walk_vec = |v: &Vec<AilExpression>| -> (bool, Vec<AilExpression>) {
            let mut changed = false;
            let mut out = Vec::with_capacity(v.len());
            for x in v {
                let (c, r) = x.replace_ail(old, new);
                changed |= c;
                out.push(r);
            }
            (changed, out)
        };
        let walk_opt = |o: &Option<Box<AilExpression>>| -> (bool, Option<Box<AilExpression>>) {
            match o {
                None => (false, None),
                Some(c) => {
                    let (changed, r) = c.replace_ail(old, new);
                    (changed, Some(Box::new(r)))
                }
            }
        };
        match &self.inner {
            ExprInner::UnaryOp { op, operand } => {
                let (c, r) = walk(operand);
                if !c {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::UnaryOp {
                            op: op.clone(),
                            operand: r,
                        },
                    },
                )
            }
            ExprInner::Convert {
                operand,
                from_bits,
                to_bits,
                is_signed,
                from_type,
                to_type,
                rounding_mode,
            } => {
                let (c, r) = walk(operand);
                if !c {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::Convert {
                            operand: r,
                            from_bits: *from_bits,
                            to_bits: *to_bits,
                            is_signed: *is_signed,
                            from_type: *from_type,
                            to_type: *to_type,
                            rounding_mode: *rounding_mode,
                        },
                    },
                )
            }
            ExprInner::Reinterpret {
                operand,
                from_bits,
                from_type,
                to_bits,
                to_type,
            } => {
                let (c, r) = walk(operand);
                if !c {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::Reinterpret {
                            operand: r,
                            from_bits: *from_bits,
                            from_type: from_type.clone(),
                            to_bits: *to_bits,
                            to_type: to_type.clone(),
                        },
                    },
                )
            }
            ExprInner::BinaryOp {
                op,
                operands,
                signed,
                floating_point,
                rounding_mode,
                vector_count,
                vector_size,
            } => {
                let (cl, rl) = walk(&operands[0]);
                let (cr, rr) = walk(&operands[1]);
                if !cl && !cr {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::BinaryOp {
                            op: op.clone(),
                            operands: [rl, rr],
                            signed: *signed,
                            floating_point: *floating_point,
                            rounding_mode: *rounding_mode,
                            vector_count: *vector_count,
                            vector_size: *vector_size,
                        },
                    },
                )
            }
            ExprInner::Load {
                addr,
                size,
                endness,
                guard,
                alt,
            } => {
                let (ca, ra) = walk(addr);
                let (cg, rg) = walk_opt(guard);
                let (cal, ral) = walk_opt(alt);
                if !ca && !cg && !cal {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::Load {
                            addr: ra,
                            size: *size,
                            endness: endness.clone(),
                            guard: rg,
                            alt: ral,
                        },
                    },
                )
            }
            ExprInner::ITE {
                cond,
                iffalse,
                iftrue,
            } => {
                let (cc, rc) = walk(cond);
                let (cf, rf) = walk(iffalse);
                let (ct, rt) = walk(iftrue);
                if !cc && !cf && !ct {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::ITE {
                            cond: rc,
                            iffalse: rf,
                            iftrue: rt,
                        },
                    },
                )
            }
            ExprInner::Extract {
                base,
                offset,
                endness,
            } => {
                let (cb, rb) = walk(base);
                let (co, ro) = walk(offset);
                if !cb && !co {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::Extract {
                            base: rb,
                            offset: ro,
                            endness: endness.clone(),
                        },
                    },
                )
            }
            ExprInner::Insert {
                base,
                offset,
                value,
                endness,
            } => {
                let (cb, rb) = walk(base);
                let (co, ro) = walk(offset);
                let (cv, rv) = walk(value);
                if !cb && !co && !cv {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::Insert {
                            base: rb,
                            offset: ro,
                            value: rv,
                            endness: endness.clone(),
                        },
                    },
                )
            }
            ExprInner::Call {
                target,
                args,
                arg_vvars,
            } => {
                // Walk the polymorphic ``target`` slot. ``CFGTarget::replace_ail``
                // recurses into the inner ``Expr`` and leaves ``Symbol`` alone.
                let (ct, rt) = target.replace_ail(old, new);
                let (ca, ra) = match args {
                    Some(v) => {
                        let (c, r) = walk_vec(v);
                        (c, Some(r))
                    }
                    None => (false, None),
                };
                let (cav, rav) = match arg_vvars {
                    Some(v) => {
                        let (c, r) = walk_vec(v);
                        (c, Some(r))
                    }
                    None => (false, None),
                };
                if !ct && !ca && !cav {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::Call {
                            target: rt,
                            args: ra,
                            arg_vvars: rav,
                        },
                    },
                )
            }
            ExprInner::DirtyExpression {
                callee,
                operands,
                guard,
                mfx,
                maddr,
                msize,
            } => {
                let (co, ro) = walk_vec(operands);
                let (cg, rg) = walk_opt(guard);
                let (cm, rm) = walk_opt(maddr);
                if !co && !cg && !cm {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::DirtyExpression {
                            callee: callee.clone(),
                            operands: ro,
                            guard: rg,
                            mfx: mfx.clone(),
                            maddr: rm,
                            msize: *msize,
                        },
                    },
                )
            }
            ExprInner::VEXCCallExpression { callee, operands } => {
                let (co, ro) = walk_vec(operands);
                if !co {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::VEXCCallExpression {
                            callee: callee.clone(),
                            operands: ro,
                        },
                    },
                )
            }
            ExprInner::ComboRegister { registers } => {
                let (cr, rr) = walk_vec(registers);
                if !cr {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::ComboRegister { registers: rr },
                    },
                )
            }
            ExprInner::Struct {
                name,
                fields,
                field_offsets,
                field_names,
            } => {
                // Walk the value map; rebuild only if any field needs
                // replacement. Offsets/names are scalar metadata.
                let mut changed = false;
                let mut new_fields: IndexMap<i64, Box<AilExpression>> =
                    IndexMap::with_capacity(fields.len());
                for (off, e) in fields {
                    let (c, r) = e.replace_ail(old, new);
                    if c {
                        changed = true;
                        new_fields.insert(*off, Box::new(r));
                    } else {
                        new_fields.insert(*off, e.clone());
                    }
                }
                if !changed {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::Struct {
                            name: name.clone(),
                            fields: new_fields,
                            field_offsets: field_offsets.clone(),
                            field_names: field_names.clone(),
                        },
                    },
                )
            }
            ExprInner::RustEnum { name, fields } => {
                let mut changed = false;
                let mut new_fields: Vec<Box<AilExpression>> = Vec::with_capacity(fields.len());
                for f in fields {
                    let (c, r) = f.replace_ail(old, new);
                    if c {
                        changed = true;
                        new_fields.push(Box::new(r));
                    } else {
                        new_fields.push(f.clone());
                    }
                }
                if !changed {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::RustEnum {
                            name: name.clone(),
                            fields: new_fields,
                        },
                    },
                )
            }
            ExprInner::Array { elements } => {
                let mut changed = false;
                let mut new_elements: Vec<Box<AilExpression>> = Vec::with_capacity(elements.len());
                for e in elements {
                    let (c, r) = e.replace_ail(old, new);
                    if c {
                        changed = true;
                        new_elements.push(Box::new(r));
                    } else {
                        new_elements.push(e.clone());
                    }
                }
                if !changed {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::Array {
                            elements: new_elements,
                        },
                    },
                )
            }
            ExprInner::FunctionLikeMacro {
                name,
                delimiter,
                args,
            } => {
                let Some(l) = args else {
                    return (false, self.clone());
                };
                let mut changed = false;
                let mut new_args: Vec<Box<AilExpression>> = Vec::with_capacity(l.len());
                for a in l {
                    let (c, r) = a.replace_ail(old, new);
                    if c {
                        changed = true;
                        new_args.push(Box::new(r));
                    } else {
                        new_args.push(a.clone());
                    }
                }
                if !changed {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::FunctionLikeMacro {
                            name: name.clone(),
                            delimiter: delimiter.clone(),
                            args: Some(new_args),
                        },
                    },
                )
            }
            ExprInner::Phi { src_and_vvars } => {
                // Phi entries hold ``VirtualVariable`` expressions in
                // the vvar slot; ``replace_ail(old, new)`` is meaningful
                // only when ``new`` is itself a ``VirtualVariable`` (Phi
                // semantics require the slot to stay a VVar or None).
                if !matches!(new.inner, ExprInner::VirtualVariable { .. }) {
                    return (false, self.clone());
                }
                let mut changed = false;
                let new_entries: Vec<PhiEntry> = src_and_vvars
                    .iter()
                    .map(|e| match &e.vvar {
                        Some(v) if v.likes(old) => {
                            changed = true;
                            PhiEntry {
                                src_addr: e.src_addr,
                                src_idx: e.src_idx,
                                vvar: Some(Box::new(new.clone())),
                            }
                        }
                        _ => e.clone(),
                    })
                    .collect();
                if !changed {
                    return (false, self.clone());
                }
                (
                    true,
                    AilExpression {
                        header: self.header.clone(),
                        inner: ExprInner::Phi {
                            src_and_vvars: new_entries,
                        },
                    },
                )
            }
            // Leaf-like variants (no operand subtrees to recurse into).
            _ => (false, self.clone()),
        }
    }

    /// Recursive ``has_atom`` -- walk operand subtrees looking for a
    /// node that ``__eq__``-matches ``atom`` (when ``identity`` is True)
    /// or ``likes``-matches it (when False).
    pub fn has_atom_ail(&self, atom: &AilExpression, identity: bool) -> bool {
        let matches_atom = |x: &AilExpression| -> bool {
            if identity {
                x.kind() == atom.kind() && x.header.idx == atom.header.idx && x.likes(atom)
            } else {
                x.likes(atom)
            }
        };
        if matches_atom(self) {
            return true;
        }
        let any =
            |children: &[&AilExpression]| children.iter().any(|c| c.has_atom_ail(atom, identity));
        let any_vec = |v: &[AilExpression]| v.iter().any(|c| c.has_atom_ail(atom, identity));
        match &self.inner {
            ExprInner::UnaryOp { operand, .. }
            | ExprInner::Convert { operand, .. }
            | ExprInner::Reinterpret { operand, .. } => any(&[operand]),
            ExprInner::BinaryOp { operands, .. } => {
                operands[0].has_atom_ail(atom, identity) || operands[1].has_atom_ail(atom, identity)
            }
            ExprInner::Load {
                addr, guard, alt, ..
            } => {
                if addr.has_atom_ail(atom, identity) {
                    return true;
                }
                if let Some(g) = guard
                    && g.has_atom_ail(atom, identity)
                {
                    return true;
                }
                if let Some(a) = alt
                    && a.has_atom_ail(atom, identity)
                {
                    return true;
                }
                false
            }
            ExprInner::ITE {
                cond,
                iffalse,
                iftrue,
                ..
            } => any(&[cond, iffalse, iftrue]),
            ExprInner::Extract { base, offset, .. } => any(&[base, offset]),
            ExprInner::Insert {
                base,
                offset,
                value,
                ..
            } => any(&[base, offset, value]),
            ExprInner::Call {
                args, arg_vvars, ..
            } => {
                if let Some(v) = args
                    && any_vec(v)
                {
                    return true;
                }
                if let Some(v) = arg_vvars
                    && any_vec(v)
                {
                    return true;
                }
                false
            }
            ExprInner::DirtyExpression {
                operands,
                guard,
                maddr,
                ..
            } => {
                if any_vec(operands) {
                    return true;
                }
                if let Some(g) = guard
                    && g.has_atom_ail(atom, identity)
                {
                    return true;
                }
                if let Some(m) = maddr
                    && m.has_atom_ail(atom, identity)
                {
                    return true;
                }
                false
            }
            ExprInner::VEXCCallExpression { operands, .. } => any_vec(operands),
            ExprInner::ComboRegister { registers, .. } => any_vec(registers),
            ExprInner::Array { elements, .. } => {
                elements.iter().any(|e| e.has_atom_ail(atom, identity))
            }
            ExprInner::RustEnum { fields, .. } => {
                fields.iter().any(|f| f.has_atom_ail(atom, identity))
            }
            ExprInner::BasePointerOffset { .. } | ExprInner::StackBaseOffset { .. } => false,
            _ => false,
        }
    }

    /// Recursive ``deep_copy`` -- replace ``idx`` with
    /// ``manager.next_atom()`` at every node. Used by clinic to
    /// re-number atoms when cloning blocks. Polymorphic Python-typed
    /// fields are cloned via Python ``copy.deepcopy``.
    pub fn deep_copy_ail(
        &self,
        py: Python<'_>,
        manager: &Bound<'_, PyAny>,
    ) -> PyResult<AilExpression> {
        let new_idx: i64 = manager.call_method0("next_atom")?.extract()?;
        // Mirror master's TaggedObject._transfer_varmap: when the
        // manager carries a VariableMap, copy any side-container entries
        // (variable, variable_offset, variant, returnty, ...) from the
        // old idx to the new one so deep-copied atoms keep their
        // associations.
        let vmap = manager.getattr("variable_map")?;
        if !vmap.is_none() {
            vmap.call_method1("transfer", (self.header.idx, new_idx))?;
        }
        let new_header = ExprHeader::new(
            new_idx,
            self.header.depth,
            self.header.bits,
            self.header.tags.clone(),
        );
        let recurse = |child: &AilExpression| -> PyResult<Box<AilExpression>> {
            Ok(Box::new(child.deep_copy_ail(py, manager)?))
        };
        let recurse_vec = |v: &Vec<AilExpression>| -> PyResult<Vec<AilExpression>> {
            v.iter().map(|x| x.deep_copy_ail(py, manager)).collect()
        };
        let recurse_opt = |o: &Option<Box<AilExpression>>| -> PyResult<Option<Box<AilExpression>>> {
            match o {
                None => Ok(None),
                Some(c) => Ok(Some(Box::new(c.deep_copy_ail(py, manager)?))),
            }
        };
        // Deep copy a CFGTarget: recursively deep-copy the inner expr.
        let dc_target = |t: &CFGTarget| -> PyResult<CFGTarget> {
            match t {
                CFGTarget::Expr(e) => Ok(CFGTarget::Expr(Box::new(e.deep_copy_ail(py, manager)?))),
                CFGTarget::Symbol(s) => Ok(CFGTarget::Symbol(s.clone())),
            }
        };
        let inner = match &self.inner {
            ExprInner::Const { value } => ExprInner::Const {
                value: value.clone(),
            },
            ExprInner::Tmp { tmp_idx } => ExprInner::Tmp { tmp_idx: *tmp_idx },
            ExprInner::Register { reg_offset } => ExprInner::Register {
                reg_offset: *reg_offset,
            },
            ExprInner::ComboRegister { registers } => ExprInner::ComboRegister {
                registers: recurse_vec(registers)?,
            },
            ExprInner::Phi { src_and_vvars } => ExprInner::Phi {
                src_and_vvars: src_and_vvars.clone(),
            },
            ExprInner::VirtualVariable {
                varid,
                category,
                oident,
                reg_vvars,
            } => ExprInner::VirtualVariable {
                varid: *varid,
                category: *category,
                oident: oident.clone(),
                reg_vvars: reg_vvars
                    .as_ref()
                    .map(|vec| vec.iter().map(|b| recurse(b)).collect::<PyResult<Vec<_>>>())
                    .transpose()?,
            },
            ExprInner::UnaryOp { op, operand } => ExprInner::UnaryOp {
                op: op.clone(),
                operand: recurse(operand)?,
            },
            ExprInner::Convert {
                operand,
                from_bits,
                to_bits,
                is_signed,
                from_type,
                to_type,
                rounding_mode,
            } => ExprInner::Convert {
                operand: recurse(operand)?,
                from_bits: *from_bits,
                to_bits: *to_bits,
                is_signed: *is_signed,
                from_type: *from_type,
                to_type: *to_type,
                rounding_mode: *rounding_mode,
            },
            ExprInner::Reinterpret {
                operand,
                from_bits,
                from_type,
                to_bits,
                to_type,
            } => ExprInner::Reinterpret {
                operand: recurse(operand)?,
                from_bits: *from_bits,
                from_type: from_type.clone(),
                to_bits: *to_bits,
                to_type: to_type.clone(),
            },
            ExprInner::BinaryOp {
                op,
                operands,
                signed,
                floating_point,
                rounding_mode,
                vector_count,
                vector_size,
            } => ExprInner::BinaryOp {
                op: op.clone(),
                operands: [recurse(&operands[0])?, recurse(&operands[1])?],
                signed: *signed,
                floating_point: *floating_point,
                rounding_mode: *rounding_mode,
                vector_count: *vector_count,
                vector_size: *vector_size,
            },
            ExprInner::Load {
                addr,
                size,
                endness,
                guard,
                alt,
            } => ExprInner::Load {
                addr: recurse(addr)?,
                size: *size,
                endness: endness.clone(),
                guard: recurse_opt(guard)?,
                alt: recurse_opt(alt)?,
            },
            ExprInner::Call {
                target,
                args,
                arg_vvars,
            } => ExprInner::Call {
                target: dc_target(target)?,
                args: match args {
                    Some(v) => Some(recurse_vec(v)?),
                    None => None,
                },
                arg_vvars: match arg_vvars {
                    Some(v) => Some(recurse_vec(v)?),
                    None => None,
                },
            },
            ExprInner::ITE {
                cond,
                iffalse,
                iftrue,
            } => ExprInner::ITE {
                cond: recurse(cond)?,
                iffalse: recurse(iffalse)?,
                iftrue: recurse(iftrue)?,
            },
            ExprInner::Extract {
                base,
                offset,
                endness,
            } => ExprInner::Extract {
                base: recurse(base)?,
                offset: recurse(offset)?,
                endness: endness.clone(),
            },
            ExprInner::Insert {
                base,
                offset,
                value,
                endness,
            } => ExprInner::Insert {
                base: recurse(base)?,
                offset: recurse(offset)?,
                value: recurse(value)?,
                endness: endness.clone(),
            },
            ExprInner::StringLiteral { data } => ExprInner::StringLiteral { data: data.clone() },
            ExprInner::BasePointerOffset { base, offset } => ExprInner::BasePointerOffset {
                base: base.clone(),
                offset: *offset,
            },
            ExprInner::StackBaseOffset { offset } => ExprInner::StackBaseOffset { offset: *offset },
            ExprInner::DirtyExpression {
                callee,
                operands,
                guard,
                mfx,
                maddr,
                msize,
            } => ExprInner::DirtyExpression {
                callee: callee.clone(),
                operands: recurse_vec(operands)?,
                guard: recurse_opt(guard)?,
                mfx: mfx.clone(),
                maddr: recurse_opt(maddr)?,
                msize: *msize,
            },
            ExprInner::VEXCCallExpression { callee, operands } => ExprInner::VEXCCallExpression {
                callee: callee.clone(),
                operands: recurse_vec(operands)?,
            },
            ExprInner::MultiStatementExpression { stmts, expr } => {
                ExprInner::MultiStatementExpression {
                    stmts: stmts
                        .iter()
                        .map(|s| s.deep_copy_ail_stmt(py, manager))
                        .collect::<PyResult<Vec<_>>>()?,
                    expr: recurse(expr)?,
                }
            }
            ExprInner::Struct {
                name,
                fields,
                field_offsets,
                field_names,
            } => ExprInner::Struct {
                name: name.clone(),
                fields: fields
                    .iter()
                    .map(|(off, e)| Ok::<_, PyErr>((*off, recurse(e)?)))
                    .collect::<PyResult<IndexMap<_, _>>>()?,
                field_offsets: field_offsets.clone(),
                field_names: field_names.clone(),
            },
            ExprInner::RustEnum { name, fields } => ExprInner::RustEnum {
                name: name.clone(),
                fields: fields
                    .iter()
                    .map(|f| recurse(f))
                    .collect::<PyResult<Vec<_>>>()?,
            },
            ExprInner::Array { elements } => ExprInner::Array {
                elements: elements
                    .iter()
                    .map(|e| recurse(e))
                    .collect::<PyResult<Vec<_>>>()?,
            },
            ExprInner::Let { defs, src } => ExprInner::Let {
                defs: defs
                    .iter()
                    .map(|s| Ok::<_, PyErr>(Box::new(s.deep_copy_ail_stmt(py, manager)?)))
                    .collect::<PyResult<Vec<_>>>()?,
                src: recurse(src)?,
            },
            ExprInner::Macro { name, delimiter } => ExprInner::Macro {
                name: name.clone(),
                delimiter: delimiter.clone(),
            },
            ExprInner::FunctionLikeMacro {
                name,
                delimiter,
                args,
            } => ExprInner::FunctionLikeMacro {
                name: name.clone(),
                delimiter: delimiter.clone(),
                args: args
                    .as_ref()
                    .map(|vec| vec.iter().map(|a| recurse(a)).collect::<PyResult<Vec<_>>>())
                    .transpose()?,
            },
        };
        Ok(AilExpression {
            header: new_header,
            inner,
        })
    }

    /// Lazy-compute the cached hash and return it.
    pub fn cached_hash_or_compute(&self) -> i64 {
        if let Some(h) = self.header.cached_hash.get() {
            return h;
        }
        let h = self._hash_core();
        self.header.cached_hash.set(h);
        h
    }

    /// Structural-with-identity equality. Two expressions ``likes`` each
    /// other when they are the same variant carrying the same identifying
    /// information AND their operands transitively ``likes`` each other.
    ///
    /// For SSA atoms ``VirtualVariable`` this means the ``varid`` must
    /// agree -- ``likes`` will distinguish two structurally identical
    /// reads of the same register that come from different definitions.
    /// Contrast with ``matches``: ``matches`` is the structural-only
    /// sibling that ignores ``varid`` (and other identifying fields) and
    /// only requires the *shape* of the expression to be the same.
    ///
    /// Rule of thumb:
    /// * ``likes`` = "is this the same value at the AIL level" -- used
    ///   by Python ``__eq__`` (after the idx-first short-circuit), by
    ///   rewriting passes that replace one node with an equivalent one,
    ///   and anywhere identity within the SSA-numbered IR matters.
    /// * ``matches`` = "do these two expressions have the same shape" --
    ///   used by deduplication / similarity passes that need to recognize
    ///   that the same source expression compiled into two different
    ///   SSA-numbered occurrences should be treated as identical.
    pub fn likes(&self, other: &AilExpression) -> bool {
        if self.kind() != other.kind() {
            return false;
        }
        // Treat ``NaN`` as equal to ``NaN`` to mirror the legacy Python
        // ``Const.likes`` (which short-circuits via ``self.value is
        // other.value``). With the default IEEE 754 ``PartialEq`` on
        // ``f64``, ``NaN != NaN`` causes structurally identical Const
        // wrappers around NaN to never converge in fixed-point loops
        // (e.g. ``BlockSimplifier`` / ``DivSimplifier``).
        fn const_values_eq(a: &ConstValue, b: &ConstValue) -> bool {
            match (a, b) {
                (ConstValue::Float(x), ConstValue::Float(y)) => {
                    x == y || (x.is_nan() && y.is_nan())
                }
                _ => a == b,
            }
        }
        match (&self.inner, &other.inner) {
            (ExprInner::Const { value: a, .. }, ExprInner::Const { value: b, .. }) => {
                const_values_eq(a, b) && self.header.bits == other.header.bits
            }
            (ExprInner::Tmp { tmp_idx: a, .. }, ExprInner::Tmp { tmp_idx: b, .. }) => {
                a == b && self.header.bits == other.header.bits
            }
            (
                ExprInner::Register { reg_offset: a, .. },
                ExprInner::Register { reg_offset: b, .. },
            ) => a == b && self.header.bits == other.header.bits,
            (
                ExprInner::ComboRegister { registers: a, .. },
                ExprInner::ComboRegister { registers: b, .. },
            ) => a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.likes(y)),
            (
                ExprInner::Phi {
                    src_and_vvars: a, ..
                },
                ExprInner::Phi {
                    src_and_vvars: b, ..
                },
            ) => {
                if self.header.bits != other.header.bits || a.len() != b.len() {
                    return false;
                }
                a.iter().zip(b.iter()).all(|(x, y)| {
                    if x.src_addr != y.src_addr || x.src_idx != y.src_idx {
                        return false;
                    }
                    match (&x.vvar, &y.vvar) {
                        (None, None) => true,
                        (Some(xv), Some(yv)) => xv.likes(yv),
                        _ => false,
                    }
                })
            }
            (
                ExprInner::VirtualVariable {
                    varid: a_id,
                    category: a_c,
                    oident: a_o,
                    ..
                },
                ExprInner::VirtualVariable {
                    varid: b_id,
                    category: b_c,
                    oident: b_o,
                    ..
                },
            ) => a_id == b_id && self.header.bits == other.header.bits && a_c == b_c && a_o == b_o,
            (
                ExprInner::UnaryOp {
                    op: a_op,
                    operand: a_op_,
                    ..
                },
                ExprInner::UnaryOp {
                    op: b_op,
                    operand: b_op_,
                    ..
                },
            ) => a_op == b_op && self.header.bits == other.header.bits && a_op_.likes(b_op_),
            (
                ExprInner::Convert {
                    operand: a_o,
                    from_bits: a_fb,
                    to_bits: a_tb,
                    is_signed: a_s,
                    from_type: a_ft,
                    to_type: a_tt,
                    ..
                },
                ExprInner::Convert {
                    operand: b_o,
                    from_bits: b_fb,
                    to_bits: b_tb,
                    is_signed: b_s,
                    from_type: b_ft,
                    to_type: b_tt,
                    ..
                },
            ) => {
                a_fb == b_fb
                    && a_tb == b_tb
                    && a_s == b_s
                    && a_ft == b_ft
                    && a_tt == b_tt
                    && self.header.bits == other.header.bits
                    && a_o.likes(b_o)
            }
            (
                ExprInner::Reinterpret {
                    operand: a_o,
                    from_bits: a_fb,
                    from_type: a_ft,
                    to_bits: a_tb,
                    to_type: a_tt,
                    ..
                },
                ExprInner::Reinterpret {
                    operand: b_o,
                    from_bits: b_fb,
                    from_type: b_ft,
                    to_bits: b_tb,
                    to_type: b_tt,
                    ..
                },
            ) => a_fb == b_fb && a_tb == b_tb && a_ft == b_ft && a_tt == b_tt && a_o.likes(b_o),
            (
                ExprInner::BinaryOp {
                    op: op_a,
                    operands: ops_a,
                    signed: s_a,
                    floating_point: fp_a,
                    ..
                },
                ExprInner::BinaryOp {
                    op: op_b,
                    operands: ops_b,
                    signed: s_b,
                    floating_point: fp_b,
                    ..
                },
            ) => {
                op_a == op_b
                    && s_a == s_b
                    && fp_a == fp_b
                    && self.header.bits == other.header.bits
                    && ops_a[0].likes(&ops_b[0])
                    && ops_a[1].likes(&ops_b[1])
            }
            (
                ExprInner::Load {
                    addr: a_addr,
                    size: a_size,
                    endness: a_end,
                    ..
                },
                ExprInner::Load {
                    addr: b_addr,
                    size: b_size,
                    endness: b_end,
                    ..
                },
            ) => a_size == b_size && a_end == b_end && a_addr.likes(b_addr),
            (
                ExprInner::Struct {
                    name: a_n,
                    fields: a_f,
                    field_offsets: a_o,
                    ..
                },
                ExprInner::Struct {
                    name: b_n,
                    fields: b_f,
                    field_offsets: b_o,
                    ..
                },
            ) => {
                if a_n != b_n || a_f.len() != b_f.len() || a_o != b_o {
                    return false;
                }
                for (off, e) in a_f {
                    let Some(other_e) = b_f.get(off) else {
                        return false;
                    };
                    if !e.likes(other_e) {
                        return false;
                    }
                }
                true
            }
            (
                ExprInner::RustEnum {
                    name: a_n,
                    fields: a_f,
                },
                ExprInner::RustEnum {
                    name: b_n,
                    fields: b_f,
                },
            ) => {
                a_n == b_n
                    && self.header.bits == other.header.bits
                    && a_f.len() == b_f.len()
                    && a_f.iter().zip(b_f.iter()).all(|(a, b)| a.likes(b))
            }
            (ExprInner::Array { elements: a_e }, ExprInner::Array { elements: b_e }) => {
                self.header.bits == other.header.bits
                    && a_e.len() == b_e.len()
                    && a_e.iter().zip(b_e.iter()).all(|(a, b)| a.likes(b))
            }
            (ExprInner::Let { src: a_s, .. }, ExprInner::Let { src: b_s, .. }) => a_s.likes(b_s),
            (
                ExprInner::Macro {
                    name: a_n,
                    delimiter: a_d,
                    ..
                },
                ExprInner::Macro {
                    name: b_n,
                    delimiter: b_d,
                    ..
                },
            ) => a_n == b_n && a_d == b_d && self.header.bits == other.header.bits,
            (
                ExprInner::FunctionLikeMacro {
                    name: a_n,
                    delimiter: a_d,
                    args: a_a,
                    ..
                },
                ExprInner::FunctionLikeMacro {
                    name: b_n,
                    delimiter: b_d,
                    args: b_a,
                    ..
                },
            ) => {
                if a_n != b_n || a_d != b_d || self.header.bits != other.header.bits {
                    return false;
                }
                match (a_a, b_a) {
                    (None, None) => true,
                    (Some(x), Some(y)) => {
                        x.len() == y.len() && x.iter().zip(y.iter()).all(|(a, b)| a.likes(b))
                    }
                    _ => false,
                }
            }
            (
                ExprInner::DirtyExpression {
                    callee: a_c,
                    operands: a_ops,
                    guard: a_g,
                    mfx: a_mfx,
                    maddr: a_ma,
                    msize: a_ms,
                },
                ExprInner::DirtyExpression {
                    callee: b_c,
                    operands: b_ops,
                    guard: b_g,
                    mfx: b_mfx,
                    maddr: b_ma,
                    msize: b_ms,
                },
            ) => {
                if a_c != b_c
                    || a_mfx != b_mfx
                    || a_ms != b_ms
                    || self.header.bits != other.header.bits
                {
                    return false;
                }
                let opt_likes =
                    |a: &Option<Box<AilExpression>>, b: &Option<Box<AilExpression>>| match (a, b) {
                        (None, None) => true,
                        (Some(x), Some(y)) => x.likes(y),
                        _ => false,
                    };
                opt_likes(a_g, b_g)
                    && opt_likes(a_ma, b_ma)
                    && a_ops.len() == b_ops.len()
                    && a_ops.iter().zip(b_ops.iter()).all(|(x, y)| x.likes(y))
            }
            (
                ExprInner::VEXCCallExpression {
                    callee: a_c,
                    operands: a_ops,
                },
                ExprInner::VEXCCallExpression {
                    callee: b_c,
                    operands: b_ops,
                },
            ) => {
                a_c == b_c
                    && self.header.bits == other.header.bits
                    && a_ops.len() == b_ops.len()
                    && a_ops.iter().zip(b_ops.iter()).all(|(x, y)| x.likes(y))
            }
            (
                ExprInner::MultiStatementExpression {
                    stmts: a_s,
                    expr: a_e,
                },
                ExprInner::MultiStatementExpression {
                    stmts: b_s,
                    expr: b_e,
                },
            ) => {
                a_s.len() == b_s.len()
                    && a_s.iter().zip(b_s.iter()).all(|(x, y)| x.likes(y))
                    && a_e.likes(b_e)
            }
            (
                ExprInner::Call {
                    target: a_t,
                    args: a_args,
                    ..
                },
                ExprInner::Call {
                    target: b_t,
                    args: b_args,
                    ..
                },
            ) => {
                // ``CFGTarget::likes`` already dispatches structurally;
                // for the Expr arm it routes through ``AilExpression::likes``.
                if !a_t.likes(b_t) {
                    return false;
                }
                match (a_args, b_args) {
                    (None, None) => true,
                    (Some(a), Some(b)) => {
                        a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.likes(y))
                    }
                    _ => false,
                }
            }
            (
                ExprInner::ITE {
                    cond: ac,
                    iffalse: af,
                    iftrue: at,
                    ..
                },
                ExprInner::ITE {
                    cond: bc,
                    iffalse: bf,
                    iftrue: bt,
                    ..
                },
            ) => {
                self.header.bits == other.header.bits
                    && ac.likes(bc)
                    && af.likes(bf)
                    && at.likes(bt)
            }
            (
                ExprInner::Extract {
                    base: ab,
                    offset: ao,
                    endness: ae,
                },
                ExprInner::Extract {
                    base: bb,
                    offset: bo,
                    endness: be,
                },
            ) => self.header.bits == other.header.bits && ae == be && ab.likes(bb) && ao.likes(bo),
            (
                ExprInner::Insert {
                    base: ab,
                    offset: ao,
                    value: av,
                    endness: ae,
                },
                ExprInner::Insert {
                    base: bb,
                    offset: bo,
                    value: bv,
                    endness: be,
                },
            ) => ae == be && ab.likes(bb) && ao.likes(bo) && av.likes(bv),
            (ExprInner::StringLiteral { data: a }, ExprInner::StringLiteral { data: b }) => a == b,
            (
                ExprInner::BasePointerOffset {
                    base: a_b,
                    offset: a_o,
                    ..
                },
                ExprInner::BasePointerOffset {
                    base: b_b,
                    offset: b_o,
                    ..
                },
            ) => self.header.bits == other.header.bits && a_b == b_b && a_o == b_o,
            (
                ExprInner::StackBaseOffset { offset: a },
                ExprInner::StackBaseOffset { offset: b },
            ) => a == b && self.header.bits == other.header.bits,
            _ => false,
        }
    }

    /// Structural-only equality. Unlike ``likes``, ``matches`` ignores
    /// identifying fields that distinguish two structurally identical
    /// occurrences of the same source-level expression:
    ///
    /// * ``VirtualVariable.matches`` ignores ``varid``. Two reads of the
    ///   same physical register through two different SSA definitions
    ///   ``matches`` but do not ``likes``.
    /// * Recursive variants (``BinaryOp``, ``UnaryOp``, ``Convert``,
    ///   ``Reinterpret``, ``Load``, ``ITE``, ``Call``, ``DirtyExpression``,
    ///   ``VEXCCallExpression``, ``MultiStatementExpression``) descend
    ///   into their sub-expressions via ``matches`` rather than ``likes``,
    ///   so the relaxation propagates.
    ///
    /// All other variants (Const/Tmp/Register/StringLiteral/...) carry
    /// no SSA identifying info, so ``matches`` reduces to ``likes`` for
    /// them. This mirrors the legacy Python AIL contract where most
    /// classes declare ``matches = likes`` and only a handful override.
    ///
    /// Primary user: deduplication/similarity passes such as
    /// ``DuplicationReverter`` and ``block_similarity.is_similar`` --
    /// they need to recognize that the two branches of an if/else that
    /// each compile the same source expression should be treated as
    /// duplicates even though SSA renumbering gave their values
    /// different ``varid``s.
    pub fn matches(&self, other: &AilExpression) -> bool {
        if self.kind() != other.kind() {
            return false;
        }
        match (&self.inner, &other.inner) {
            // -- VirtualVariable: matches ignores ``varid``. This is the
            // -- single most important relaxation -- it lets the dedup
            // -- passes recognize the same source-level read across two
            // -- SSA branches.
            (
                ExprInner::VirtualVariable {
                    category: a_c,
                    oident: a_o,
                    ..
                },
                ExprInner::VirtualVariable {
                    category: b_c,
                    oident: b_o,
                    ..
                },
            ) => self.header.bits == other.header.bits && a_c == b_c && a_o == b_o,
            // -- Phi: same shape, but per-source pairs only require the
            // -- *source* to match; the vvar id is ignored (per master's
            // -- ``Phi.matches``). The legacy contract walks the dicts
            // -- and only verifies the keys (sources) line up.
            (
                ExprInner::Phi {
                    src_and_vvars: a, ..
                },
                ExprInner::Phi {
                    src_and_vvars: b, ..
                },
            ) => {
                if self.header.bits != other.header.bits || a.len() != b.len() {
                    return false;
                }
                // Order-insensitive: every ``src`` (src_addr, src_idx)
                // in ``a`` must appear in ``b``. ``vvar_id`` payloads
                // are intentionally ignored (mirrors master's
                // ``Phi.matches``).
                'outer: for ea in a.iter() {
                    for eb in b.iter() {
                        if ea.src_addr == eb.src_addr && ea.src_idx == eb.src_idx {
                            continue 'outer;
                        }
                    }
                    return false;
                }
                true
            }
            // -- Recursive variants: descend via ``matches`` so the
            // -- relaxation propagates.
            (
                ExprInner::UnaryOp {
                    op: a_op,
                    operand: a_o,
                    ..
                },
                ExprInner::UnaryOp {
                    op: b_op,
                    operand: b_o,
                    ..
                },
            ) => a_op == b_op && self.header.bits == other.header.bits && a_o.matches(b_o),
            (
                ExprInner::Convert {
                    operand: a_o,
                    from_bits: a_fb,
                    to_bits: a_tb,
                    is_signed: a_s,
                    from_type: a_ft,
                    to_type: a_tt,
                    ..
                },
                ExprInner::Convert {
                    operand: b_o,
                    from_bits: b_fb,
                    to_bits: b_tb,
                    is_signed: b_s,
                    from_type: b_ft,
                    to_type: b_tt,
                    ..
                },
            ) => {
                a_fb == b_fb
                    && a_tb == b_tb
                    && a_s == b_s
                    && a_ft == b_ft
                    && a_tt == b_tt
                    && self.header.bits == other.header.bits
                    && a_o.matches(b_o)
            }
            (
                ExprInner::Reinterpret {
                    operand: a_o,
                    from_bits: a_fb,
                    from_type: a_ft,
                    to_bits: a_tb,
                    to_type: a_tt,
                    ..
                },
                ExprInner::Reinterpret {
                    operand: b_o,
                    from_bits: b_fb,
                    from_type: b_ft,
                    to_bits: b_tb,
                    to_type: b_tt,
                    ..
                },
            ) => a_fb == b_fb && a_tb == b_tb && a_ft == b_ft && a_tt == b_tt && a_o.matches(b_o),
            (
                ExprInner::BinaryOp {
                    op: op_a,
                    operands: ops_a,
                    signed: s_a,
                    floating_point: fp_a,
                    ..
                },
                ExprInner::BinaryOp {
                    op: op_b,
                    operands: ops_b,
                    signed: s_b,
                    floating_point: fp_b,
                    ..
                },
            ) => {
                op_a == op_b
                    && s_a == s_b
                    && fp_a == fp_b
                    && self.header.bits == other.header.bits
                    && ops_a[0].matches(&ops_b[0])
                    && ops_a[1].matches(&ops_b[1])
            }
            (
                ExprInner::Load {
                    addr: a_addr,
                    size: a_size,
                    endness: a_end,
                    ..
                },
                ExprInner::Load {
                    addr: b_addr,
                    size: b_size,
                    endness: b_end,
                    ..
                },
            ) => a_size == b_size && a_end == b_end && a_addr.matches(b_addr),
            (
                ExprInner::ITE {
                    cond: ac,
                    iffalse: af,
                    iftrue: at,
                    ..
                },
                ExprInner::ITE {
                    cond: bc,
                    iffalse: bf,
                    iftrue: bt,
                    ..
                },
            ) => {
                self.header.bits == other.header.bits
                    && ac.matches(bc)
                    && af.matches(bf)
                    && at.matches(bt)
            }
            (
                ExprInner::Extract {
                    base: ab,
                    offset: ao,
                    endness: ae,
                },
                ExprInner::Extract {
                    base: bb,
                    offset: bo,
                    endness: be,
                },
            ) => {
                self.header.bits == other.header.bits
                    && ae == be
                    && ab.matches(bb)
                    && ao.matches(bo)
            }
            (
                ExprInner::Insert {
                    base: ab,
                    offset: ao,
                    value: av,
                    endness: ae,
                },
                ExprInner::Insert {
                    base: bb,
                    offset: bo,
                    value: bv,
                    endness: be,
                },
            ) => ae == be && ab.matches(bb) && ao.matches(bo) && av.matches(bv),
            (
                ExprInner::Call {
                    target: a_t,
                    args: a_args,
                    ..
                },
                ExprInner::Call {
                    target: b_t,
                    args: b_args,
                    ..
                },
            ) => {
                if !a_t.matches(b_t) {
                    return false;
                }
                match (a_args, b_args) {
                    (None, None) => true,
                    (Some(a), Some(b)) => {
                        a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.matches(y))
                    }
                    _ => false,
                }
            }
            (
                ExprInner::DirtyExpression {
                    callee: a_c,
                    operands: a_ops,
                    guard: a_g,
                    mfx: a_mfx,
                    maddr: a_ma,
                    msize: a_ms,
                },
                ExprInner::DirtyExpression {
                    callee: b_c,
                    operands: b_ops,
                    guard: b_g,
                    mfx: b_mfx,
                    maddr: b_ma,
                    msize: b_ms,
                },
            ) => {
                if a_c != b_c
                    || a_mfx != b_mfx
                    || a_ms != b_ms
                    || self.header.bits != other.header.bits
                {
                    return false;
                }
                let opt_matches =
                    |a: &Option<Box<AilExpression>>, b: &Option<Box<AilExpression>>| match (a, b) {
                        (None, None) => true,
                        (Some(x), Some(y)) => x.matches(y),
                        _ => false,
                    };
                opt_matches(a_g, b_g)
                    && opt_matches(a_ma, b_ma)
                    && a_ops.len() == b_ops.len()
                    && a_ops.iter().zip(b_ops.iter()).all(|(x, y)| x.matches(y))
            }
            (
                ExprInner::VEXCCallExpression {
                    callee: a_c,
                    operands: a_ops,
                },
                ExprInner::VEXCCallExpression {
                    callee: b_c,
                    operands: b_ops,
                },
            ) => {
                a_c == b_c
                    && self.header.bits == other.header.bits
                    && a_ops.len() == b_ops.len()
                    && a_ops.iter().zip(b_ops.iter()).all(|(x, y)| x.matches(y))
            }
            (
                ExprInner::MultiStatementExpression {
                    stmts: a_s,
                    expr: a_e,
                },
                ExprInner::MultiStatementExpression {
                    stmts: b_s,
                    expr: b_e,
                },
            ) => {
                a_s.len() == b_s.len()
                    && a_s.iter().zip(b_s.iter()).all(|(x, y)| x.matches(y))
                    && a_e.matches(b_e)
            }
            // -- ComboRegister: recurses via matches but Python defines
            // -- ``matches = likes`` for it. Since likes already recurses
            // -- via ``likes`` and there's no varid in plain Register, the
            // -- two are equivalent. Keep the recursion explicit for
            // -- forward-consistency.
            (
                ExprInner::ComboRegister { registers: a, .. },
                ExprInner::ComboRegister { registers: b, .. },
            ) => a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.matches(y)),
            // -- All other variants: no identifying info distinguishes
            // -- ``matches`` from ``likes``. Defer to ``likes``.
            _ => self.likes(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Expression pyclass -- the only Python-facing class
// ---------------------------------------------------------------------------

#[pyclass(
    name = "Expression",
    module = "angr.rustylib.ailment",
    skip_from_py_object
)]
#[derive(Debug)]
pub struct Expression {
    pub expr: AilExpression,
    /// Cached Python int holding the variant tag, materialized once
    /// at construction so ``Expression.pykind`` reads are a single
    /// ``clone_ref`` (refcount bump) rather than a fresh PyObject
    /// allocation per access.
    pykind: Py<pyo3::types::PyAny>,
}

impl Clone for Expression {
    fn clone(&self) -> Self {
        Python::attach(|py| Self {
            expr: self.expr.clone(),
            pykind: self.pykind.clone_ref(py),
        })
    }
}

/// Interned ``Py<int>`` objects for every ``ExpressionKind`` value.
/// Built lazily on first ``Expression::wrap`` (which is always called
/// under the GIL via PyO3); per-instance construction is then a
/// single array index + ``clone_ref`` instead of an ``into_pyobject`` +
/// boundary trip. CPython interns small ints anyway, but PyO3
/// still pays the boundary on every call -- skipping that recovers
/// the ~50-75 ms construction tax seen in the per-instance
/// ``Py<int>`` cache.
static EXPR_PYKINDS: pyo3::sync::PyOnceLock<[Py<pyo3::types::PyAny>; 27]> =
    pyo3::sync::PyOnceLock::new();

fn expr_pykind_for(py: Python<'_>, kind: ExpressionKind) -> Py<pyo3::types::PyAny> {
    use pyo3::IntoPyObjectExt;
    let arr = EXPR_PYKINDS.get_or_init(py, || {
        std::array::from_fn(|i| {
            (i as u8)
                .into_py_any(py)
                .expect("u8 -> Py<int> cannot fail")
        })
    });
    arr[kind as usize].clone_ref(py)
}

impl Expression {
    pub fn wrap(expr: AilExpression) -> Self {
        let pykind = Python::attach(|py| expr_pykind_for(py, expr.kind()));
        Self { expr, pykind }
    }

    /// Public stringifier used by the Statement-side spike's ``__str__``
    /// dispatch. Same logic as the ``#[getter]``-exposed ``__str__``.
    pub fn render(&self, py: Python<'_>) -> PyResult<String> {
        self.__str__(py)
    }
}

#[pymethods]
impl Expression {
    // --- Per-variant constructor factories ----------------------------
    //
    // Each marker class's ``__new__`` calls one of these. Keeping them
    // as staticmethods makes the field/type contract explicit per
    // variant rather than going through a tagged ``__new__`` shape.

    #[staticmethod]
    #[pyo3(signature = (idx, value, bits, **kwargs))]
    fn _new_const(
        py: Python<'_>,
        idx: i64,
        value: Bound<'_, PyAny>,
        bits: u32,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let value = ConstValue::extract((&value).into())?;
        let _ = py;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 0, bits, tags),
            inner: ExprInner::Const { value },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, tmp_idx, bits, **kwargs))]
    fn _new_tmp(
        idx: i64,
        tmp_idx: i64,
        bits: u32,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 0, bits, tags),
            inner: ExprInner::Tmp { tmp_idx },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, varid, bits, category, oident=None, reg_vvars=None, **kwargs))]
    #[allow(clippy::too_many_arguments)]
    fn _new_virtual_variable(
        py: Python<'_>,
        idx: i64,
        varid: i64,
        bits: u32,
        category: Bound<'_, PyAny>,
        oident: Option<Bound<'_, PyAny>>,
        reg_vvars: Option<Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        use crate::ailment::enums::VirtualVariableCategory;
        let tags = Tags::from_kwargs(kwargs)?;
        let cat = if let Ok(c) = category.extract::<VirtualVariableCategory>() {
            c
        } else if let Ok(v) = category.extract::<i64>() {
            VirtualVariableCategory::from_int(v).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Unknown VirtualVariableCategory value: {}",
                    v
                ))
            })?
        } else {
            return Err(PyTypeError::new_err(
                "category must be a VirtualVariableCategory or int",
            ));
        };
        let oident = match oident {
            Some(o) if !o.is_none() => OIdent::from_py(py, &o, cat)?,
            _ => OIdent::None,
        };
        let reg_vvars = match reg_vvars {
            Some(o) if !o.is_none() => {
                let items: Vec<Bound<'_, PyAny>> = o
                    .try_iter()
                    .map_err(|_| {
                        PyTypeError::new_err(
                            "reg_vvars must be a list of VirtualVariable Expressions or None",
                        )
                    })?
                    .collect::<PyResult<Vec<_>>>()?;
                let mut decoded: Vec<Box<AilExpression>> = Vec::with_capacity(items.len());
                for (i, item) in items.into_iter().enumerate() {
                    let ail = extract_ail(&item)?;
                    if !matches!(ail.inner, ExprInner::VirtualVariable { .. }) {
                        return Err(PyTypeError::new_err(format!(
                            "reg_vvars[{}] must be a VirtualVariable Expression",
                            i
                        )));
                    }
                    decoded.push(Box::new(ail));
                }
                Some(decoded)
            }
            _ => None,
        };
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 0, bits, tags),
            inner: ExprInner::VirtualVariable {
                varid,
                category: cat,
                oident,
                reg_vvars,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, bits, src_and_vvars, **kwargs))]
    fn _new_phi(
        py: Python<'_>,
        idx: i64,
        bits: u32,
        src_and_vvars: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let entries = extract_phi_entries(py, &src_and_vvars)?;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 0, bits, tags),
            inner: ExprInner::Phi {
                src_and_vvars: entries,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, registers, **kwargs))]
    fn _new_combo_register(
        idx: i64,
        registers: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        // Each element must be an AIL Register Expression.
        let mut regs: Vec<AilExpression> = Vec::new();
        let mut bits: u32 = 0;
        for item in registers.try_iter()? {
            let item = item?;
            let ail = extract_ail(&item)?;
            if !matches!(ail.inner, ExprInner::Register { .. }) {
                return Err(PyTypeError::new_err(
                    "ComboRegister elements must be Register expressions",
                ));
            }
            bits = bits.saturating_add(ail.header.bits);
            regs.push(ail);
        }
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 0, bits, tags),
            inner: ExprInner::ComboRegister { registers: regs },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, reg_offset, bits, **kwargs))]
    fn _new_register(
        idx: i64,
        reg_offset: i64,
        bits: u32,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 0, bits, tags),
            inner: ExprInner::Register { reg_offset },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, op, operand, *, bits=None, **kwargs))]
    fn _new_unary_op(
        idx: i64,
        op: String,
        operand: Bound<'_, PyAny>,
        bits: Option<u32>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let operand_ail = extract_ail(&operand)?;
        let depth = operand_ail.header.depth + 1;
        let final_bits = bits.unwrap_or(operand_ail.header.bits);
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, final_bits, tags),
            inner: ExprInner::UnaryOp {
                op,
                operand: Box::new(operand_ail),
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (
        idx, from_bits, to_bits, is_signed, operand,
        from_type=None, to_type=None, rounding_mode=None,
        **kwargs
    ))]
    #[allow(clippy::too_many_arguments)]
    fn _new_convert(
        idx: i64,
        from_bits: u32,
        to_bits: u32,
        is_signed: bool,
        operand: Bound<'_, PyAny>,
        from_type: Option<ConvertType>,
        to_type: Option<ConvertType>,
        rounding_mode: Option<RoundingMode>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let operand_ail = extract_ail(&operand)?;
        let depth = operand_ail.header.depth + 1;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, to_bits, tags),
            inner: ExprInner::Convert {
                operand: Box::new(operand_ail),
                from_bits,
                to_bits,
                is_signed,
                from_type: from_type.unwrap_or(ConvertType::TYPE_INT),
                to_type: to_type.unwrap_or(ConvertType::TYPE_INT),
                rounding_mode,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, from_bits, from_type, to_bits, to_type, operand, **kwargs))]
    #[allow(clippy::too_many_arguments)]
    fn _new_reinterpret(
        idx: i64,
        from_bits: u32,
        from_type: String,
        to_bits: u32,
        to_type: String,
        operand: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let operand_ail = extract_ail(&operand)?;
        let depth = operand_ail.header.depth + 1;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, to_bits, tags),
            inner: ExprInner::Reinterpret {
                operand: Box::new(operand_ail),
                from_bits,
                from_type,
                to_bits,
                to_type,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (
        idx, op, operands, signed=false, *,
        bits=None, floating_point=false,
        rounding_mode=None,
        vector_count=None, vector_size=None, **kwargs
    ))]
    #[allow(clippy::too_many_arguments)]
    fn _new_binary_op(
        py: Python<'_>,
        idx: i64,
        op: String,
        operands: Bound<'_, PyAny>,
        signed: bool,
        bits: Option<u32>,
        floating_point: bool,
        rounding_mode: Option<RoundingMode>,
        vector_count: Option<i64>,
        vector_size: Option<i64>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;

        // Accept any 2-iterable.
        let items: Vec<Bound<'_, PyAny>> = operands.try_iter()?.collect::<PyResult<Vec<_>>>()?;
        if items.len() != 2 {
            return Err(PyTypeError::new_err(format!(
                "BinaryOp requires exactly 2 operands, got {}",
                items.len()
            )));
        }
        let lhs_ail = extract_ail(&items[0])?;
        let rhs_ail = extract_ail(&items[1])?;

        let depth = lhs_ail.header.depth.max(rhs_ail.header.depth) + 1;
        let final_bits = bits.unwrap_or(lhs_ail.header.bits);

        let _ = py;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, final_bits, tags),
            inner: ExprInner::BinaryOp {
                op,
                operands: [Box::new(lhs_ail), Box::new(rhs_ail)],
                signed,
                floating_point,
                rounding_mode,
                vector_count,
                vector_size,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, cond, iffalse, iftrue, **kwargs))]
    fn _new_ite(
        idx: i64,
        cond: Bound<'_, PyAny>,
        iffalse: Bound<'_, PyAny>,
        iftrue: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let c = extract_ail(&cond)?;
        let f = extract_ail(&iffalse)?;
        let t = extract_ail(&iftrue)?;
        let depth = c.header.depth.max(f.header.depth).max(t.header.depth) + 1;
        let bits = t.header.bits;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::ITE {
                cond: Box::new(c),
                iffalse: Box::new(f),
                iftrue: Box::new(t),
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, bits, base, offset, endness, **kwargs))]
    fn _new_extract(
        idx: i64,
        bits: u32,
        base: Bound<'_, PyAny>,
        offset: Bound<'_, PyAny>,
        endness: String,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let b = extract_ail(&base)?;
        let o = extract_ail(&offset)?;
        let depth = b.header.depth.max(o.header.depth) + 1;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::Extract {
                base: Box::new(b),
                offset: Box::new(o),
                endness,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, base, offset, value, endness, **kwargs))]
    fn _new_insert(
        idx: i64,
        base: Bound<'_, PyAny>,
        offset: Bound<'_, PyAny>,
        value: Bound<'_, PyAny>,
        endness: String,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let b = extract_ail(&base)?;
        let o = extract_ail(&offset)?;
        let v = extract_ail(&value)?;
        let depth = b.header.depth.max(o.header.depth) + 1;
        let bits = b.header.bits;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::Insert {
                base: Box::new(b),
                offset: Box::new(o),
                value: Box::new(v),
                endness,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, data, bits, **kwargs))]
    fn _new_string_literal(
        idx: i64,
        data: Bound<'_, PyAny>,
        bits: u32,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let data_str: String = data
            .extract()
            .map_err(|_| PyTypeError::new_err("StringLiteral data must be a str"))?;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 0, bits, tags),
            inner: ExprInner::StringLiteral { data: data_str },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, bits, base, offset, **kwargs))]
    fn _new_base_pointer_offset(
        idx: i64,
        bits: u32,
        base: Bound<'_, PyAny>,
        offset: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let base_str: String = base
            .extract()
            .map_err(|_| PyTypeError::new_err("BasePointerOffset base must be a str"))?;
        let offset_i: i64 = offset
            .extract()
            .map_err(|_| PyTypeError::new_err("BasePointerOffset offset must be an int"))?;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 1, bits, tags),
            inner: ExprInner::BasePointerOffset {
                base: base_str,
                offset: offset_i,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, bits, offset, **kwargs))]
    fn _new_stack_base_offset(
        idx: i64,
        bits: u32,
        offset: i128,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        // Sign-normalize the offset: when the supplied value has its
        // top bit set at the Const's declared width (callers regularly
        // pass ``-8`` as its u64 two's-complement form ``2^64 - 8``),
        // subtract ``2^bits`` to bring it into the signed range.
        // ``bits`` is at most 64 in practice so this happens in i128
        // to avoid overflow.
        let mut off = offset;
        if bits < 128 && off >= (1i128 << (bits - 1)) {
            off -= 1i128 << bits;
        }
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 1, bits, tags),
            inner: ExprInner::StackBaseOffset { offset: off },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, addr, size, endness, *, guard=None, alt=None, **kwargs))]
    #[allow(clippy::too_many_arguments)]
    fn _new_load(
        py: Python<'_>,
        idx: i64,
        addr: Bound<'_, PyAny>,
        size: i32,
        endness: String,
        guard: Option<Bound<'_, PyAny>>,
        alt: Option<Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let addr_ail = extract_ail(&addr)?;
        let depth = addr_ail.header.depth + 1;
        let bits = (size.wrapping_mul(8)) as u32;

        let guard_box = match guard {
            Some(g) if !g.is_none() => Some(Box::new(extract_ail(&g)?)),
            _ => None,
        };
        let alt_box = match alt {
            Some(a) if !a.is_none() => Some(Box::new(extract_ail(&a)?)),
            _ => None,
        };
        let _ = py;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::Load {
                addr: Box::new(addr_ail),
                size,
                endness,
                guard: guard_box,
                alt: alt_box,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, target, args=None, bits=None, arg_vvars=None, **kwargs))]
    fn _new_call(
        py: Python<'_>,
        idx: i64,
        target: Bound<'_, PyAny>,
        args: Option<Bound<'_, PyAny>>,
        bits: Option<u32>,
        arg_vvars: Option<Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        // target depth +1 -- if it's an Expression, use its depth; for
        // non-Expression targets (str), depth = 1.
        let target_depth = if let Ok(e) = target.cast::<Expression>() {
            e.borrow().expr.header.depth
        } else {
            0
        };
        let depth = target_depth + 1;
        let bits = bits.unwrap_or(0);
        let args_vec = match args {
            Some(a) if !a.is_none() => {
                let mut v = Vec::new();
                for item in a.try_iter()? {
                    v.push(extract_ail(&item?)?);
                }
                Some(v)
            }
            _ => None,
        };
        let arg_vvars_vec = match arg_vvars {
            Some(a) if !a.is_none() => {
                let mut v = Vec::new();
                for item in a.try_iter()? {
                    v.push(extract_ail(&item?)?);
                }
                Some(v)
            }
            _ => None,
        };
        let _ = py;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::Call {
                target: CFGTarget::from_py(&target)?,
                args: args_vec,
                arg_vvars: arg_vvars_vec,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, callee, operands, *, guard=None, mfx=None, maddr=None, msize=None, bits, **kwargs))]
    #[allow(clippy::too_many_arguments)]
    fn _new_dirty_expression(
        idx: i64,
        callee: String,
        operands: Bound<'_, PyAny>,
        guard: Option<Bound<'_, PyAny>>,
        mfx: Option<String>,
        maddr: Option<Bound<'_, PyAny>>,
        msize: Option<i64>,
        bits: u32,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let mut ops = Vec::new();
        for item in operands.try_iter()? {
            ops.push(extract_ail(&item?)?);
        }
        let guard_box = match guard {
            Some(g) if !g.is_none() => Some(Box::new(extract_ail(&g)?)),
            _ => None,
        };
        let maddr_box = match maddr {
            Some(m) if !m.is_none() => Some(Box::new(extract_ail(&m)?)),
            _ => None,
        };
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 1, bits, tags),
            inner: ExprInner::DirtyExpression {
                callee,
                operands: ops,
                guard: guard_box,
                mfx,
                maddr: maddr_box,
                msize,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, callee, operands, bits, **kwargs))]
    fn _new_vex_ccall_expression(
        idx: i64,
        callee: String,
        operands: Bound<'_, PyAny>,
        bits: u32,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let mut ops = Vec::new();
        let mut depth: u32 = 0;
        for item in operands.try_iter()? {
            let ail = extract_ail(&item?)?;
            depth = depth.max(ail.header.depth);
            ops.push(ail);
        }
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::VEXCCallExpression {
                callee,
                operands: ops,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, stmts, expr, **kwargs))]
    fn _new_multi_statement_expression(
        idx: i64,
        stmts: Bound<'_, PyAny>,
        expr: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let mut stmt_vec: Vec<crate::ailment::ail_stmt::AilStatement> = Vec::new();
        for x in stmts.try_iter()? {
            stmt_vec.push(crate::ailment::ail_stmt::extract_ail_stmt(&x?)?);
        }
        let expr_ail = extract_ail(&expr)?;
        let depth = expr_ail.header.depth + 1;
        let bits = expr_ail.header.bits;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::MultiStatementExpression {
                stmts: stmt_vec,
                expr: Box::new(expr_ail),
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, name, fields, field_offsets, bits, **kwargs))]
    fn _new_struct(
        py: Python<'_>,
        idx: i64,
        name: String,
        fields: Bound<'_, PyDict>,
        field_offsets: Bound<'_, PyDict>,
        bits: u32,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let mut decoded_fields: IndexMap<i64, Box<AilExpression>> =
            IndexMap::with_capacity(fields.len());
        let mut depth: u32 = 0;
        for (k, v) in fields.iter() {
            let off: i64 = k
                .extract()
                .map_err(|_| PyTypeError::new_err("Struct fields keys must be int offsets"))?;
            let ail = extract_ail(&v)?;
            depth = depth.max(ail.header.depth);
            decoded_fields.insert(off, Box::new(ail));
        }
        depth += 1;
        let mut decoded_offsets: IndexMap<String, i64> =
            IndexMap::with_capacity(field_offsets.len());
        let mut decoded_names: IndexMap<i64, String> = IndexMap::with_capacity(field_offsets.len());
        for (k, v) in field_offsets.iter() {
            let name: String = k
                .extract()
                .map_err(|_| PyTypeError::new_err("Struct field_offsets keys must be str names"))?;
            let off: i64 = v.extract().map_err(|_| {
                PyTypeError::new_err("Struct field_offsets values must be int offsets")
            })?;
            decoded_offsets.insert(name.clone(), off);
            decoded_names.insert(off, name);
        }
        let _ = py;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::Struct {
                name,
                fields: decoded_fields,
                field_offsets: decoded_offsets,
                field_names: decoded_names,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, name, fields, bits, **kwargs))]
    fn _new_rust_enum(
        idx: i64,
        name: String,
        fields: Bound<'_, PyAny>,
        bits: u32,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let mut decoded: Vec<Box<AilExpression>> = Vec::new();
        let mut depth: u32 = 0;
        for f in fields.try_iter()? {
            let f = f?;
            let ail = extract_ail(&f)?;
            depth = depth.max(ail.header.depth);
            decoded.push(Box::new(ail));
        }
        depth += 1;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::RustEnum {
                name,
                fields: decoded,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, elements, bits, **kwargs))]
    fn _new_array(
        idx: i64,
        elements: Bound<'_, PyAny>,
        bits: u32,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let mut decoded: Vec<Box<AilExpression>> = Vec::new();
        let mut depth: u32 = 0;
        for e in elements.try_iter()? {
            let e = e?;
            let ail = extract_ail(&e)?;
            depth = depth.max(ail.header.depth);
            decoded.push(Box::new(ail));
        }
        depth += 1;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::Array { elements: decoded },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, defs, src, **kwargs))]
    fn _new_let(
        py: Python<'_>,
        idx: i64,
        defs: Bound<'_, PyAny>,
        src: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let src_ail = extract_ail(&src)?;
        let depth = src_ail.header.depth + 1;
        let bits = src_ail.header.bits;
        let mut decoded_defs: Vec<Box<crate::ailment::ail_stmt::AilStatement>> = Vec::new();
        for x in defs.try_iter()? {
            let x = x?;
            decoded_defs.push(Box::new(crate::ailment::ail_stmt::extract_ail_stmt(&x)?));
        }
        let _ = py;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, depth, bits, tags),
            inner: ExprInner::Let {
                defs: decoded_defs,
                src: Box::new(src_ail),
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, name, delimiter=String::from("()"), **kwargs))]
    fn _new_macro(
        idx: i64,
        name: String,
        delimiter: String,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 1, 0, tags),
            inner: ExprInner::Macro { name, delimiter },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, name, args, bits=None, delimiter=String::from("()"), **kwargs))]
    fn _new_function_like_macro(
        py: Python<'_>,
        idx: i64,
        name: String,
        args: Bound<'_, PyAny>,
        bits: Option<u32>,
        delimiter: String,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let bits = bits.unwrap_or(0);
        let args_decoded = if args.is_none() {
            None
        } else {
            let mut decoded: Vec<Box<AilExpression>> = Vec::new();
            for x in args.try_iter()? {
                let x = x?;
                decoded.push(Box::new(extract_ail(&x)?));
            }
            Some(decoded)
        };
        let _ = py;
        Ok(Self::wrap(AilExpression {
            header: ExprHeader::new(idx, 1, bits, tags),
            inner: ExprInner::FunctionLikeMacro {
                name,
                delimiter,
                args: args_decoded,
            },
        }))
    }

    // --- Universal header accessors -----------------------------------

    #[getter]
    fn idx(&self) -> i64 {
        self.expr.header.idx
    }
    #[setter]
    fn set_idx(&mut self, v: i64) {
        self.expr.header.idx = v;
        self.expr.header.cached_hash.clear();
    }
    #[getter]
    fn bits(&self) -> u32 {
        self.expr.header.bits
    }
    #[setter]
    fn set_bits(&mut self, v: u32) {
        self.expr.header.bits = v;
        self.expr.header.cached_hash.clear();
    }
    #[getter]
    fn depth(&self) -> u32 {
        self.expr.header.depth
    }
    #[setter]
    fn set_depth(&mut self, v: u32) {
        self.expr.header.depth = v;
        self.expr.header.cached_hash.clear();
    }
    #[getter]
    fn size(&self) -> u32 {
        self.expr.header.bits / 8
    }
    #[getter]
    fn tags(slf: Bound<'_, Self>) -> TagsView {
        let inner = slf.borrow().expr.header.tags.clone();
        TagsView::with_parent(inner, slf.into_any().unbind())
    }
    /// Tags writeback hook for the parent-link on TagsView. ``TagsView``
    /// mutations flush back via ``setattr(parent, "tags", new_view)``.
    #[setter]
    fn set_tags(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        if let Ok(tv) = value.cast::<TagsView>() {
            self.expr.header.tags = tv.borrow().inner().clone();
        } else {
            self.expr.header.tags = Tags::from_mapping(Some(&value))?;
        }
        self.expr.header.cached_hash.clear();
        Ok(())
    }
    /// Variant discriminator. Python-side metaclass uses this for
    /// ``isinstance(load, Load)`` dispatch.
    #[getter]
    fn kind(&self) -> ExpressionKind {
        self.expr.kind()
    }

    /// String name of the variant, for repr/debug.
    #[getter]
    fn kind_name(&self) -> &'static str {
        self.expr.kind_str()
    }

    /// Cached ``Py<int>`` form of the kind tag. Pre-materialized at
    /// construction; access is a single ``clone_ref``.
    #[getter]
    fn pykind(&self, py: Python<'_>) -> Py<pyo3::types::PyAny> {
        self.pykind.clone_ref(py)
    }

    fn clear_hash(&self) {
        self.expr.header.cached_hash.clear();
    }

    // --- Per-variant accessors ----------------------------------------
    //
    // Each returns ``AttributeError`` when called on the wrong variant.
    // The Python markers don't enforce this (they trust the caller to
    // only read fields appropriate to the marker), but a stray read on
    // an unrelated Expression instance gets a clear error.

    /// Const.value (literal) / Insert.value (Expression operand).
    #[getter]
    fn value<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.expr.inner {
            ExprInner::Const { value, .. } => Ok(value.clone().into_pyobject(py)?),
            ExprInner::Insert { value, .. } => {
                Ok(Py::new(py, Expression::wrap((**value).clone()))?
                    .into_bound(py)
                    .into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'value' on this Expression")),
        }
    }
    #[setter]
    fn set_value(&mut self, new_value: Bound<'_, PyAny>) -> PyResult<()> {
        match &mut self.expr.inner {
            ExprInner::Const { value, .. } => {
                let new = ConstValue::extract((&new_value).into())?;
                self.expr.header.cached_hash.clear();
                *value = new;
                Ok(())
            }
            ExprInner::Insert { value, .. } => {
                let new = extract_ail(&new_value)?;
                self.expr.header.cached_hash.clear();
                **value = new;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'value' on this Expression")),
        }
    }

    /// ``Const.is_int`` (only int constants -- not floats).
    #[getter]
    fn is_int(&self) -> PyResult<bool> {
        match &self.expr.inner {
            ExprInner::Const { value, .. } => Ok(value.is_int()),
            _ => Err(PyAttributeError::new_err("no 'is_int' on this Expression")),
        }
    }

    /// ``Const.value_int`` -- the int value (errors on float constants).
    #[getter]
    fn value_int<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.expr.inner {
            ExprInner::Const { value, .. } => {
                if !value.is_int() {
                    return Err(PyTypeError::new_err(format!(
                        "Incorrect value type; expect int, got {:?}",
                        value
                    )));
                }
                value.clone().into_bound_py_any(py)
            }
            _ => Err(PyAttributeError::new_err(
                "no 'value_int' on this Expression",
            )),
        }
    }

    /// ``Const.value_float`` -- the float value (errors on int constants).
    #[getter]
    fn value_float(&self) -> PyResult<f64> {
        match &self.expr.inner {
            ExprInner::Const { value, .. } => match value {
                ConstValue::Float(v) => Ok(*v),
                _ => Err(PyTypeError::new_err(format!(
                    "Incorrect value type; expect float, got {:?}",
                    value
                ))),
            },
            _ => Err(PyAttributeError::new_err(
                "no 'value_float' on this Expression",
            )),
        }
    }

    /// ``Const.sign_bit`` -- the top bit of the int value at the
    /// Const's declared width. Computed as a bit-extract (not an
    /// arithmetic shift) so values stored as their u64 two's-complement
    /// form -- e.g. ``-8`` carried as ``2^64 - 8`` from the lifter --
    /// correctly report ``1``.
    #[getter]
    fn sign_bit(&self) -> PyResult<i128> {
        match &self.expr.inner {
            ExprInner::Const { value, .. } => {
                if !value.is_int() {
                    return Err(PyTypeError::new_err(
                        "Sign bit is only available for int constants.",
                    ));
                }
                let bits = self.expr.header.bits;
                let v = match value {
                    ConstValue::Int(v) => *v,
                    ConstValue::BigInt(s) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(format!(
                            "sign_bit on Const with BigInt value (hex {s}) is not supported"
                        )));
                    }
                    ConstValue::Float(_) => unreachable!(),
                };
                let mask = 1i128 << (bits - 1);
                Ok(if (v & mask) != 0 { 1 } else { 0 })
            }
            _ => Err(PyAttributeError::new_err(
                "no 'sign_bit' on this Expression",
            )),
        }
    }

    /// Tmp.tmp_idx (i64) / VirtualVariable.tmp_idx (Option<i64>, present
    /// when category is TMP).
    #[getter]
    fn tmp_idx(&self, py: Python<'_>) -> PyResult<Option<i64>> {
        let _ = py;
        match &self.expr.inner {
            ExprInner::Tmp { tmp_idx, .. } => Ok(Some(*tmp_idx)),
            ExprInner::VirtualVariable { oident, .. } if self.was_tmp() => match oident {
                OIdent::Int(v) => Ok(Some(*v)),
                _ => Ok(None),
            },
            ExprInner::VirtualVariable { .. } => Ok(None),
            _ => Err(PyAttributeError::new_err("no 'tmp_idx' on this Expression")),
        }
    }

    /// Register.reg_offset / VirtualVariable.reg_offset (when category is
    /// REGISTER, or parameter with REGISTER inner category).
    #[getter]
    fn reg_offset(&self, py: Python<'_>) -> PyResult<i64> {
        let _ = py;
        match &self.expr.inner {
            ExprInner::Register { reg_offset, .. } => Ok(*reg_offset),
            ExprInner::VirtualVariable { oident, .. } if self.was_reg() => match oident {
                OIdent::Int(v) => Ok(*v),
                _ => Err(PyTypeError::new_err("Is not a register")),
            },
            ExprInner::VirtualVariable { oident, .. } if self.was_parameter() => match oident {
                OIdent::Parameter(ParameterOIdent::Register(v)) => Ok(*v),
                _ => Err(PyTypeError::new_err("Is not a register")),
            },
            _ => Err(PyAttributeError::new_err(
                "no 'reg_offset' on this Expression",
            )),
        }
    }

    /// ComboRegister.registers -- list of Register Expression instances.
    #[getter]
    fn registers(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        match &self.expr.inner {
            ExprInner::ComboRegister { registers, .. } => {
                let l = PyList::empty(py);
                for r in registers {
                    let py_r = Py::new(py, Expression::wrap(r.clone()))?;
                    l.append(py_r)?;
                }
                Ok(l.unbind())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'registers' on this Expression",
            )),
        }
    }
    #[setter]
    fn set_registers(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let mut regs: Vec<AilExpression> = Vec::new();
        for item in value.try_iter()? {
            let item = item?;
            let ail = extract_ail(&item)?;
            if !matches!(ail.inner, ExprInner::Register { .. }) {
                return Err(PyTypeError::new_err(
                    "ComboRegister elements must be Register expressions",
                ));
            }
            regs.push(ail);
        }
        match &mut self.expr.inner {
            ExprInner::ComboRegister { registers, .. } => {
                self.expr.header.cached_hash.clear();
                *registers = regs;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'registers' on this Expression",
            )),
        }
    }

    /// Phi.src_and_vvars
    ///
    /// Returns a Python list of ``((src_addr, src_idx), vvar)`` tuples.
    /// The ``vvar`` slot is a ``VirtualVariable`` Expression (or
    /// ``None``).
    #[getter]
    fn src_and_vvars<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        match &self.expr.inner {
            ExprInner::Phi { src_and_vvars, .. } => {
                let list = PyList::empty(py);
                for entry in src_and_vvars {
                    let src_tuple = PyTuple::new(
                        py,
                        [
                            entry.src_addr.into_py_any(py)?,
                            match entry.src_idx {
                                Some(v) => v.into_py_any(py)?,
                                None => py.None(),
                            },
                        ],
                    )?;
                    let vvar_obj = match &entry.vvar {
                        Some(v) => Py::new(py, Expression::wrap((**v).clone()))?.into_any(),
                        None => py.None(),
                    };
                    let pair = PyTuple::new(py, [src_tuple.into_any().unbind(), vvar_obj])?;
                    list.append(pair)?;
                }
                Ok(list)
            }
            _ => Err(PyAttributeError::new_err(
                "no 'src_and_vvars' on this Expression",
            )),
        }
    }
    #[setter]
    fn set_src_and_vvars(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let py = value.py();
        let entries = extract_phi_entries(py, &value)?;
        match &mut self.expr.inner {
            ExprInner::Phi { src_and_vvars, .. } => {
                self.expr.header.cached_hash.clear();
                *src_and_vvars = entries;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'src_and_vvars' on this Expression",
            )),
        }
    }

    /// VirtualVariable.varid
    #[getter]
    fn varid(&self) -> PyResult<i64> {
        match &self.expr.inner {
            ExprInner::VirtualVariable { varid, .. } => Ok(*varid),
            _ => Err(PyAttributeError::new_err("no 'varid' on this Expression")),
        }
    }

    /// VirtualVariable.category
    #[getter]
    fn category(&self) -> PyResult<crate::ailment::enums::VirtualVariableCategory> {
        match &self.expr.inner {
            ExprInner::VirtualVariable { category, .. } => Ok(*category),
            _ => Err(PyAttributeError::new_err(
                "no 'category' on this Expression",
            )),
        }
    }

    /// VirtualVariable.oident
    #[getter]
    fn oident(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::VirtualVariable { oident, .. } => oident.to_py(py),
            _ => Err(PyAttributeError::new_err("no 'oident' on this Expression")),
        }
    }

    /// VirtualVariable.reg_vvars
    ///
    /// Returns ``None`` for non-COMBO_REGISTER vvars, an empty list for
    /// COMBO_REGISTER vvars whose sub-registers haven't been populated
    /// yet, and a list of ``VirtualVariable`` Expression wrappers
    /// otherwise. Each call mints fresh wrappers around clones of the
    /// inner ``AilExpression`` nodes (same pattern as ``.operands``).
    #[getter]
    fn reg_vvars<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyList>>> {
        match &self.expr.inner {
            ExprInner::VirtualVariable { reg_vvars, .. } => match reg_vvars {
                None => Ok(None),
                Some(vec) => {
                    let items: Vec<Bound<'py, PyAny>> = vec
                        .iter()
                        .map(|b| {
                            Ok::<_, PyErr>(
                                Py::new(py, Self::wrap((**b).clone()))?
                                    .into_bound(py)
                                    .into_any(),
                            )
                        })
                        .collect::<PyResult<_>>()?;
                    Ok(Some(PyList::new(py, items)?))
                }
            },
            _ => Err(PyAttributeError::new_err(
                "no 'reg_vvars' on this Expression",
            )),
        }
    }

    // --- VirtualVariable derived getters ------------------------------

    fn _vv_category(&self) -> Option<crate::ailment::enums::VirtualVariableCategory> {
        match &self.expr.inner {
            ExprInner::VirtualVariable { category, .. } => Some(*category),
            _ => None,
        }
    }

    /// VirtualVariable.was_reg
    #[getter]
    fn was_reg(&self) -> bool {
        use crate::ailment::enums::VirtualVariableCategory::*;
        matches!(self._vv_category(), Some(REGISTER))
    }
    /// VirtualVariable.was_stack
    #[getter]
    fn was_stack(&self) -> bool {
        use crate::ailment::enums::VirtualVariableCategory::*;
        matches!(self._vv_category(), Some(STACK))
    }
    /// VirtualVariable.was_parameter
    #[getter]
    fn was_parameter(&self) -> bool {
        use crate::ailment::enums::VirtualVariableCategory::*;
        matches!(self._vv_category(), Some(PARAMETER))
    }
    /// VirtualVariable.was_tmp
    #[getter]
    fn was_tmp(&self) -> bool {
        use crate::ailment::enums::VirtualVariableCategory::*;
        matches!(self._vv_category(), Some(TMP))
    }
    /// VirtualVariable.was_combo_reg
    #[getter]
    fn was_combo_reg(&self) -> bool {
        use crate::ailment::enums::VirtualVariableCategory::*;
        matches!(self._vv_category(), Some(COMBO_REGISTER))
    }

    /// VirtualVariable.parameter_category
    #[getter]
    fn parameter_category(
        &self,
        py: Python<'_>,
    ) -> PyResult<Option<crate::ailment::enums::VirtualVariableCategory>> {
        let _ = py;
        match &self.expr.inner {
            ExprInner::VirtualVariable {
                oident: OIdent::Parameter(p),
                ..
            } => Ok(Some(p.inner_category())),
            _ => Ok(None),
        }
    }

    /// VirtualVariable.parameter_reg_offset
    #[getter]
    fn parameter_reg_offset(&self, py: Python<'_>) -> PyResult<Option<i64>> {
        let _ = py;
        match &self.expr.inner {
            ExprInner::VirtualVariable {
                oident: OIdent::Parameter(ParameterOIdent::Register(v)),
                ..
            } => Ok(Some(*v)),
            _ => Ok(None),
        }
    }

    /// VirtualVariable.parameter_stack_offset
    #[getter]
    fn parameter_stack_offset(&self, py: Python<'_>) -> PyResult<Option<i64>> {
        let _ = py;
        match &self.expr.inner {
            ExprInner::VirtualVariable {
                oident: OIdent::Parameter(ParameterOIdent::Stack(v)),
                ..
            } => Ok(Some(*v)),
            _ => Ok(None),
        }
    }

    /// VirtualVariable.stack_offset
    #[getter]
    fn stack_offset(&self, py: Python<'_>) -> PyResult<i64> {
        let _ = py;
        match &self.expr.inner {
            ExprInner::VirtualVariable {
                oident: OIdent::Int(v),
                ..
            } if self.was_stack() => Ok(*v),
            ExprInner::VirtualVariable {
                oident: OIdent::Parameter(ParameterOIdent::Stack(v)),
                ..
            } if self.was_parameter() => Ok(*v),
            _ => Err(PyTypeError::new_err("Is not a stack variable")),
        }
    }

    /// VirtualVariable.reg_offsets (combo register)
    #[getter]
    fn reg_offsets<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        let make_tuple = |offs: &[i64]| -> PyResult<Bound<'py, PyTuple>> {
            let items: Vec<Py<PyAny>> = offs
                .iter()
                .map(|x| x.into_py_any(py))
                .collect::<PyResult<_>>()?;
            PyTuple::new(py, items)
        };
        if self.was_combo_reg()
            && let ExprInner::VirtualVariable {
                oident: OIdent::RegList(offs),
                ..
            } = &self.expr.inner
        {
            return make_tuple(offs);
        }
        if self.was_parameter()
            && let ExprInner::VirtualVariable {
                oident: OIdent::Parameter(ParameterOIdent::ComboRegister(offs)),
                ..
            } = &self.expr.inner
        {
            return make_tuple(offs);
        }
        Err(PyTypeError::new_err("Is not a combo register"))
    }

    /// UnaryOp.op / BinaryOp.op / Call.op (== "call") /
    /// DirtyExpression.op / VEXCCallExpression.op (== callee) /
    /// Let.op (== "let") / Macro.op + FunctionLikeMacro.op (== "call")
    #[getter]
    fn op(&self) -> PyResult<String> {
        match &self.expr.inner {
            ExprInner::UnaryOp { op, .. } | ExprInner::BinaryOp { op, .. } => Ok(op.clone()),
            ExprInner::Convert { .. } => Ok("Convert".to_string()),
            ExprInner::Reinterpret { .. } => Ok("Reinterpret".to_string()),
            ExprInner::Call { .. } => Ok("call".to_string()),
            ExprInner::Macro { .. } | ExprInner::FunctionLikeMacro { .. } => {
                Ok("macro_call".to_string())
            }
            ExprInner::DirtyExpression { callee, .. }
            | ExprInner::VEXCCallExpression { callee, .. } => Ok(callee.clone()),
            ExprInner::Let { .. } => Ok("let".to_string()),
            _ => Err(PyAttributeError::new_err("no 'op' on this Expression")),
        }
    }

    /// ``verbose_op`` -- defaults to ``op`` for the regular operator
    /// variants (UnaryOp / BinaryOp / Convert / Reinterpret) so
    /// callers that look up an op-handler via
    /// ``mapping[expr.verbose_op]`` find a match regardless of variant.
    /// The legacy per-class pyclasses exposed it on every op-shaped
    /// expression with the same content as ``op``.
    #[getter]
    fn verbose_op(&self) -> PyResult<String> {
        match &self.expr.inner {
            ExprInner::Call { .. } => Ok("call".to_string()),
            ExprInner::Macro { .. } | ExprInner::FunctionLikeMacro { .. } => {
                Ok("macro_call".to_string())
            }
            ExprInner::DirtyExpression { callee, .. }
            | ExprInner::VEXCCallExpression { callee, .. } => Ok(callee.clone()),
            ExprInner::Let { .. } => Ok("let".to_string()),
            ExprInner::UnaryOp { op, .. } | ExprInner::BinaryOp { op, .. } => Ok(op.clone()),
            ExprInner::Convert { .. } => Ok("Convert".to_string()),
            ExprInner::Reinterpret { .. } => Ok("Reinterpret".to_string()),
            _ => Err(PyAttributeError::new_err(
                "no 'verbose_op' on this Expression",
            )),
        }
    }

    /// DirtyExpression.callee / VEXCCallExpression.callee
    #[getter]
    fn callee(&self) -> PyResult<String> {
        match &self.expr.inner {
            ExprInner::DirtyExpression { callee, .. }
            | ExprInner::VEXCCallExpression { callee, .. } => Ok(callee.clone()),
            _ => Err(PyAttributeError::new_err("no 'callee' on this Expression")),
        }
    }
    #[setter]
    fn set_callee(&mut self, value: String) -> PyResult<()> {
        match &mut self.expr.inner {
            ExprInner::DirtyExpression { callee, .. }
            | ExprInner::VEXCCallExpression { callee, .. } => {
                self.expr.header.cached_hash.clear();
                *callee = value;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'callee' on this Expression")),
        }
    }

    /// DirtyExpression.operands / VEXCCallExpression.operands /
    /// BinaryOp.operands / UnaryOp.operands (single-element list,
    /// legacy quirk) / Convert.operands / Reinterpret.operands (same
    /// single-element wrap for legacy compat). DirtyExpression returns
    /// a list; VEXCCall returns a tuple; BinaryOp returns a 2-tuple;
    /// the single-operand variants return a 1-element list mirroring
    /// the legacy per-class pyclass contract.
    #[getter]
    fn operands<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.expr.inner {
            ExprInner::DirtyExpression { operands, .. } => {
                let l = PyList::empty(py);
                for o in operands {
                    let py_o = Py::new(py, Expression::wrap(o.clone()))?;
                    l.append(py_o)?;
                }
                Ok(l.into_any())
            }
            ExprInner::VEXCCallExpression { operands, .. } => {
                let items: Vec<Py<Expression>> = operands
                    .iter()
                    .map(|x| Py::new(py, Expression::wrap(x.clone())))
                    .collect::<PyResult<Vec<_>>>()?;
                Ok(PyTuple::new(py, items)?.into_any())
            }
            ExprInner::BinaryOp { operands, .. } => {
                let lhs = Py::new(py, Expression::wrap((*operands[0]).clone()))?;
                let rhs = Py::new(py, Expression::wrap((*operands[1]).clone()))?;
                Ok(PyTuple::new(py, [lhs.into_any(), rhs.into_any()])?.into_any())
            }
            ExprInner::UnaryOp { operand, .. }
            | ExprInner::Convert { operand, .. }
            | ExprInner::Reinterpret { operand, .. } => {
                // Legacy quirk: per-class pyclass exposed ``operands``
                // as ``[self.operand]`` so callers doing
                // ``expr.operands[0]`` could uniformly index.
                let l = PyList::empty(py);
                let py_o = Py::new(py, Expression::wrap((**operand).clone()))?;
                l.append(py_o)?;
                Ok(l.into_any())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'operands' on this Expression",
            )),
        }
    }
    #[setter]
    fn set_operands(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let mut v = Vec::new();
        for item in value.try_iter()? {
            v.push(extract_ail(&item?)?);
        }
        match &mut self.expr.inner {
            ExprInner::DirtyExpression { operands, .. }
            | ExprInner::VEXCCallExpression { operands, .. } => {
                self.expr.header.cached_hash.clear();
                *operands = v;
                Ok(())
            }
            ExprInner::BinaryOp { operands, .. } => {
                if v.len() != 2 {
                    return Err(PyTypeError::new_err(format!(
                        "BinaryOp.operands requires exactly 2, got {}",
                        v.len()
                    )));
                }
                self.expr.header.cached_hash.clear();
                let rhs = Box::new(v.pop().unwrap());
                let lhs = Box::new(v.pop().unwrap());
                *operands = [lhs, rhs];
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'operands' on this Expression",
            )),
        }
    }

    /// DirtyExpression.mfx
    #[getter]
    fn mfx(&self) -> PyResult<Option<String>> {
        match &self.expr.inner {
            ExprInner::DirtyExpression { mfx, .. } => Ok(mfx.clone()),
            _ => Err(PyAttributeError::new_err("no 'mfx' on this Expression")),
        }
    }

    /// DirtyExpression.maddr
    #[getter]
    fn maddr(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.expr.inner {
            ExprInner::DirtyExpression { maddr, .. } => match maddr {
                Some(m) => Ok(Some(
                    Py::new(py, Expression::wrap((**m).clone()))?.into_any(),
                )),
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err("no 'maddr' on this Expression")),
        }
    }

    /// DirtyExpression.msize
    #[getter]
    fn msize(&self) -> PyResult<Option<i64>> {
        match &self.expr.inner {
            ExprInner::DirtyExpression { msize, .. } => Ok(*msize),
            _ => Err(PyAttributeError::new_err("no 'msize' on this Expression")),
        }
    }

    /// MultiStatementExpression.stmts -- materializes a fresh
    /// ``list[Statement]`` on each read; setter accepts any iterable
    /// of ``Statement`` instances.
    #[getter]
    fn stmts<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        match &self.expr.inner {
            ExprInner::MultiStatementExpression { stmts, .. } => {
                let l = PyList::empty(py);
                for s in stmts {
                    let py_s = Py::new(py, crate::ailment::ail_stmt::Statement::wrap(s.clone()))?;
                    l.append(py_s)?;
                }
                Ok(l)
            }
            _ => Err(PyAttributeError::new_err("no 'stmts' on this Expression")),
        }
    }
    #[setter]
    fn set_stmts(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let mut v = Vec::new();
        for item in value.try_iter()? {
            v.push(crate::ailment::ail_stmt::extract_ail_stmt(&item?)?);
        }
        match &mut self.expr.inner {
            ExprInner::MultiStatementExpression { stmts, .. } => {
                self.expr.header.cached_hash.clear();
                *stmts = v;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'stmts' on this Expression")),
        }
    }

    /// Struct.name / RustEnum.name / Macro.name / FunctionLikeMacro.name
    #[getter]
    fn name(&self) -> PyResult<String> {
        match &self.expr.inner {
            ExprInner::Struct { name, .. }
            | ExprInner::RustEnum { name, .. }
            | ExprInner::Macro { name, .. }
            | ExprInner::FunctionLikeMacro { name, .. } => Ok(name.clone()),
            _ => Err(PyAttributeError::new_err("no 'name' on this Expression")),
        }
    }

    /// Struct.fields (dict) / RustEnum.fields (list)
    #[getter]
    fn fields<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.expr.inner {
            ExprInner::Struct { fields, .. } => {
                let d = PyDict::new(py);
                for (off, e) in fields {
                    let val = Py::new(py, Self::wrap((**e).clone()))?;
                    d.set_item(*off, val)?;
                }
                Ok(d.into_any())
            }
            ExprInner::RustEnum { fields, .. } => {
                let items: Vec<Bound<'py, PyAny>> = fields
                    .iter()
                    .map(|b| {
                        Ok::<_, PyErr>(
                            Py::new(py, Self::wrap((**b).clone()))?
                                .into_bound(py)
                                .into_any(),
                        )
                    })
                    .collect::<PyResult<_>>()?;
                Ok(PyList::new(py, items)?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'fields' on this Expression")),
        }
    }
    #[setter]
    fn set_fields(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        match &mut self.expr.inner {
            ExprInner::Struct { fields, .. } => {
                let dict = value
                    .cast_into::<PyDict>()
                    .map_err(|_| PyTypeError::new_err("fields must be a dict"))?;
                let mut decoded: IndexMap<i64, Box<AilExpression>> =
                    IndexMap::with_capacity(dict.len());
                for (k, v) in dict.iter() {
                    let off: i64 = k.extract().map_err(|_| {
                        PyTypeError::new_err("Struct fields keys must be int offsets")
                    })?;
                    decoded.insert(off, Box::new(extract_ail(&v)?));
                }
                self.expr.header.cached_hash.clear();
                *fields = decoded;
                Ok(())
            }
            ExprInner::RustEnum { fields, .. } => {
                let mut decoded: Vec<Box<AilExpression>> = Vec::new();
                for f in value.try_iter()? {
                    let f = f?;
                    decoded.push(Box::new(extract_ail(&f)?));
                }
                self.expr.header.cached_hash.clear();
                *fields = decoded;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'fields' on this Expression")),
        }
    }

    /// Struct.field_offsets
    #[getter]
    fn field_offsets<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        match &self.expr.inner {
            ExprInner::Struct { field_offsets, .. } => {
                let d = PyDict::new(py);
                for (name, off) in field_offsets {
                    d.set_item(name, *off)?;
                }
                Ok(d)
            }
            _ => Err(PyAttributeError::new_err(
                "no 'field_offsets' on this Expression",
            )),
        }
    }

    /// Struct.field_names
    #[getter]
    fn field_names<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        match &self.expr.inner {
            ExprInner::Struct { field_names, .. } => {
                let d = PyDict::new(py);
                for (off, name) in field_names {
                    d.set_item(*off, name)?;
                }
                Ok(d)
            }
            _ => Err(PyAttributeError::new_err(
                "no 'field_names' on this Expression",
            )),
        }
    }

    /// Struct.get_field(name) -- dotted-path lookup through nested Structs
    fn get_field(&self, py: Python<'_>, name: String) -> PyResult<Option<Py<PyAny>>> {
        let ExprInner::Struct {
            fields,
            field_offsets,
            ..
        } = &self.expr.inner
        else {
            return Err(PyAttributeError::new_err(
                "get_field is only valid on Struct",
            ));
        };
        let parts: Vec<&str> = name.split('.').collect();
        let Some(off) = field_offsets.get(parts[0]) else {
            return Ok(None);
        };
        let Some(field) = fields.get(off) else {
            return Ok(None);
        };
        if parts.len() == 1 {
            return Ok(Some(Py::new(py, Self::wrap((**field).clone()))?.into_any()));
        }
        if matches!(field.inner, ExprInner::Struct { .. }) {
            return Self::wrap((**field).clone()).get_field(py, parts[1..].join("."));
        }
        Ok(None)
    }

    /// Array.elements
    ///
    /// Returns a fresh ``list[Expression]`` built from the inner
    /// ``Vec<Box<AilExpression>>`` -- each call mints new ``Py<Expression>``
    /// wrappers, matching the wrapper-minting semantics of ``.operands``.
    #[getter]
    fn elements<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        match &self.expr.inner {
            ExprInner::Array { elements } => {
                let items: Vec<Bound<'py, PyAny>> = elements
                    .iter()
                    .map(|b| {
                        Ok::<_, PyErr>(
                            Py::new(py, Self::wrap((**b).clone()))?
                                .into_bound(py)
                                .into_any(),
                        )
                    })
                    .collect::<PyResult<_>>()?;
                PyList::new(py, items)
            }
            _ => Err(PyAttributeError::new_err(
                "no 'elements' on this Expression",
            )),
        }
    }
    #[setter]
    fn set_elements(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        match &mut self.expr.inner {
            ExprInner::Array { elements } => {
                let mut decoded: Vec<Box<AilExpression>> = Vec::new();
                for e in value.try_iter()? {
                    let e = e?;
                    decoded.push(Box::new(extract_ail(&e)?));
                }
                self.expr.header.cached_hash.clear();
                *elements = decoded;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'elements' on this Expression",
            )),
        }
    }

    /// Array.length
    #[getter]
    fn length(&self) -> PyResult<usize> {
        match &self.expr.inner {
            ExprInner::Array { elements } => Ok(elements.len()),
            _ => Err(PyAttributeError::new_err("no 'length' on this Expression")),
        }
    }

    /// Let.defs
    ///
    /// Returns a fresh ``list[Statement]`` built from the inner
    /// ``Vec<Box<AilStatement>>`` -- each call mints new
    /// ``Py<Statement>`` wrappers around clones of the inner
    /// statements, matching the wrapper-minting semantics of
    /// ``.operands`` / ``Array.elements``.
    #[getter]
    fn defs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        match &self.expr.inner {
            ExprInner::Let { defs, .. } => {
                let items: Vec<Bound<'py, PyAny>> = defs
                    .iter()
                    .map(|b| {
                        Ok::<_, PyErr>(
                            Py::new(py, crate::ailment::ail_stmt::Statement::wrap((**b).clone()))?
                                .into_bound(py)
                                .into_any(),
                        )
                    })
                    .collect::<PyResult<_>>()?;
                PyList::new(py, items)
            }
            _ => Err(PyAttributeError::new_err("no 'defs' on this Expression")),
        }
    }

    /// Let.src
    #[getter]
    fn src(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::Let { src, .. } => {
                Ok(Py::new(py, Expression::wrap((**src).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'src' on this Expression")),
        }
    }

    /// Macro.delimiter / FunctionLikeMacro.delimiter
    #[getter]
    fn delimiter(&self) -> PyResult<String> {
        match &self.expr.inner {
            ExprInner::Macro { delimiter, .. } | ExprInner::FunctionLikeMacro { delimiter, .. } => {
                Ok(delimiter.clone())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'delimiter' on this Expression",
            )),
        }
    }

    /// FunctionLikeMacro.args
    #[getter]
    fn args<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        match &self.expr.inner {
            ExprInner::Call { args, .. } => match args {
                None => Ok(None),
                Some(v) => {
                    let items: Vec<Py<Expression>> = v
                        .iter()
                        .map(|x| Py::new(py, Expression::wrap(x.clone())))
                        .collect::<PyResult<Vec<_>>>()?;
                    Ok(Some(PyTuple::new(py, items)?.into_any()))
                }
            },
            ExprInner::FunctionLikeMacro { args, .. } => match args {
                None => Ok(None),
                Some(v) => {
                    let items: Vec<Bound<'py, PyAny>> = v
                        .iter()
                        .map(|b| {
                            Ok::<_, PyErr>(
                                Py::new(py, Expression::wrap((**b).clone()))?
                                    .into_bound(py)
                                    .into_any(),
                            )
                        })
                        .collect::<PyResult<_>>()?;
                    Ok(Some(PyList::new(py, items)?.into_any()))
                }
            },
            _ => Err(PyAttributeError::new_err("no 'args' on this Expression")),
        }
    }
    #[setter]
    fn set_args(&mut self, value: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        match &mut self.expr.inner {
            ExprInner::Call { args, .. } => {
                let new_vec = match value {
                    Some(v) if !v.is_none() => {
                        let mut out = Vec::new();
                        for item in v.try_iter()? {
                            out.push(extract_ail(&item?)?);
                        }
                        Some(out)
                    }
                    _ => None,
                };
                self.expr.header.cached_hash.clear();
                *args = new_vec;
                Ok(())
            }
            ExprInner::FunctionLikeMacro { args, .. } => {
                let new_vec = match value {
                    Some(v) if !v.is_none() => {
                        let mut out = Vec::new();
                        for item in v.try_iter()? {
                            out.push(Box::new(extract_ail(&item?)?));
                        }
                        Some(out)
                    }
                    _ => None,
                };
                self.expr.header.cached_hash.clear();
                *args = new_vec;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'args' on this Expression")),
        }
    }

    /// MultiStatementExpression.expr
    #[getter]
    fn expr(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::MultiStatementExpression { expr, .. } => {
                Ok(Py::new(py, Expression::wrap((**expr).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'expr' on this Expression")),
        }
    }
    #[setter]
    fn set_expr(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let ail = extract_ail(&value)?;
        match &mut self.expr.inner {
            ExprInner::MultiStatementExpression { expr, .. } => {
                self.expr.header.cached_hash.clear();
                **expr = ail;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'expr' on this Expression")),
        }
    }

    /// Call.target / Macro.target (legacy returns name as PyString -- analyses
    /// that branch on ``isinstance(target, str)`` keep working).
    #[getter]
    fn target(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::Call { target, .. } => target.to_py(py),
            ExprInner::Macro { name, .. } | ExprInner::FunctionLikeMacro { name, .. } => {
                Ok(pyo3::types::PyString::new(py, name).into_any().unbind())
            }
            _ => Err(PyAttributeError::new_err("no 'target' on this Expression")),
        }
    }
    #[setter]
    fn set_target(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let new_target = CFGTarget::from_py(&value)?;
        match &mut self.expr.inner {
            ExprInner::Call { target, .. } => {
                self.expr.header.cached_hash.clear();
                *target = new_target;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'target' on this Expression")),
        }
    }

    /// Call.arg_vvars / Macro.arg_vvars (always None) -- tuple of
    /// VirtualVariable Expression instances
    #[getter]
    fn arg_vvars<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyTuple>>> {
        match &self.expr.inner {
            ExprInner::Call { arg_vvars, .. } => match arg_vvars {
                None => Ok(None),
                Some(v) => {
                    let items: Vec<Py<Expression>> = v
                        .iter()
                        .map(|x| Py::new(py, Expression::wrap(x.clone())))
                        .collect::<PyResult<Vec<_>>>()?;
                    Ok(Some(PyTuple::new(py, items)?))
                }
            },
            ExprInner::Macro { .. } | ExprInner::FunctionLikeMacro { .. } => Ok(None),
            _ => Err(PyAttributeError::new_err(
                "no 'arg_vvars' on this Expression",
            )),
        }
    }
    #[setter]
    fn set_arg_vvars(&mut self, value: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        let new_vec = match value {
            Some(v) if !v.is_none() => {
                let mut out = Vec::new();
                for item in v.try_iter()? {
                    out.push(extract_ail(&item?)?);
                }
                Some(out)
            }
            _ => None,
        };
        match &mut self.expr.inner {
            ExprInner::Call { arg_vvars, .. } => {
                *arg_vvars = new_vec;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'arg_vvars' on this Expression",
            )),
        }
    }

    /// UnaryOp.operand / Convert.operand / Reinterpret.operand
    #[getter]
    fn operand(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::UnaryOp { operand, .. }
            | ExprInner::Convert { operand, .. }
            | ExprInner::Reinterpret { operand, .. } => {
                let inner = Expression::wrap((**operand).clone());
                Ok(Py::new(py, inner)?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'operand' on this Expression")),
        }
    }
    #[setter]
    fn set_operand(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let ail = extract_ail(&value)?;
        match &mut self.expr.inner {
            ExprInner::UnaryOp { operand, .. }
            | ExprInner::Convert { operand, .. }
            | ExprInner::Reinterpret { operand, .. } => {
                self.expr.header.cached_hash.clear();
                **operand = ail;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'operand' on this Expression")),
        }
    }

    /// Convert.from_bits / Reinterpret.from_bits
    #[allow(clippy::wrong_self_convention)]
    #[getter]
    fn from_bits(&self) -> PyResult<u32> {
        match &self.expr.inner {
            ExprInner::Convert { from_bits, .. } | ExprInner::Reinterpret { from_bits, .. } => {
                Ok(*from_bits)
            }
            _ => Err(PyAttributeError::new_err(
                "no 'from_bits' on this Expression",
            )),
        }
    }

    /// Convert.to_bits / Reinterpret.to_bits
    #[getter]
    fn to_bits(&self) -> PyResult<u32> {
        match &self.expr.inner {
            ExprInner::Convert { to_bits, .. } | ExprInner::Reinterpret { to_bits, .. } => {
                Ok(*to_bits)
            }
            _ => Err(PyAttributeError::new_err("no 'to_bits' on this Expression")),
        }
    }

    /// Convert.is_signed
    #[getter]
    fn is_signed(&self) -> PyResult<bool> {
        match &self.expr.inner {
            ExprInner::Convert { is_signed, .. } => Ok(*is_signed),
            _ => Err(PyAttributeError::new_err(
                "no 'is_signed' on this Expression",
            )),
        }
    }

    /// Convert.from_type / Reinterpret.from_type (different types -- Reinterpret is a String)
    #[allow(clippy::wrong_self_convention)]
    #[getter]
    fn from_type<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.expr.inner {
            ExprInner::Convert { from_type, .. } => Ok(from_type.into_pyobject(py)?.into_any()),
            ExprInner::Reinterpret { from_type, .. } => {
                Ok(from_type.clone().into_bound_py_any(py)?)
            }
            _ => Err(PyAttributeError::new_err(
                "no 'from_type' on this Expression",
            )),
        }
    }

    /// Convert.to_type / Reinterpret.to_type
    #[getter]
    fn to_type<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.expr.inner {
            ExprInner::Convert { to_type, .. } => Ok(to_type.into_pyobject(py)?.into_any()),
            ExprInner::Reinterpret { to_type, .. } => Ok(to_type.clone().into_bound_py_any(py)?),
            _ => Err(PyAttributeError::new_err("no 'to_type' on this Expression")),
        }
    }

    /// Convert.rounding_mode / BinaryOp.rounding_mode
    #[getter]
    fn rounding_mode(&self) -> Option<RoundingMode> {
        match &self.expr.inner {
            ExprInner::Convert { rounding_mode, .. }
            | ExprInner::BinaryOp { rounding_mode, .. } => *rounding_mode,
            _ => None,
        }
    }

    /// BinaryOp.signed
    #[getter]
    fn signed(&self) -> PyResult<bool> {
        match &self.expr.inner {
            ExprInner::BinaryOp { signed, .. } => Ok(*signed),
            _ => Err(PyAttributeError::new_err("no 'signed' on this Expression")),
        }
    }

    /// BinaryOp.floating_point
    #[getter]
    fn floating_point(&self) -> PyResult<bool> {
        match &self.expr.inner {
            ExprInner::BinaryOp { floating_point, .. } => Ok(*floating_point),
            _ => Err(PyAttributeError::new_err(
                "no 'floating_point' on this Expression",
            )),
        }
    }

    /// BinaryOp.vector_count
    #[getter]
    fn vector_count(&self) -> PyResult<Option<i64>> {
        match &self.expr.inner {
            ExprInner::BinaryOp { vector_count, .. } => Ok(*vector_count),
            _ => Err(PyAttributeError::new_err(
                "no 'vector_count' on this Expression",
            )),
        }
    }

    /// BinaryOp.vector_size
    #[getter]
    fn vector_size(&self) -> PyResult<Option<i64>> {
        match &self.expr.inner {
            ExprInner::BinaryOp { vector_size, .. } => Ok(*vector_size),
            _ => Err(PyAttributeError::new_err(
                "no 'vector_size' on this Expression",
            )),
        }
    }

    /// Load.addr
    #[getter]
    fn addr(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::Load { addr, .. } => {
                let inner = Expression::wrap((**addr).clone());
                Ok(Py::new(py, inner)?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'addr' on this Expression")),
        }
    }
    #[setter]
    fn set_addr(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let ail = extract_ail(&value)?;
        match &mut self.expr.inner {
            ExprInner::Load { addr, .. } => {
                self.expr.header.cached_hash.clear();
                **addr = ail;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'addr' on this Expression")),
        }
    }

    /// Load.endness / Extract.endness / Insert.endness
    #[getter]
    fn endness(&self) -> PyResult<String> {
        match &self.expr.inner {
            ExprInner::Load { endness, .. }
            | ExprInner::Extract { endness, .. }
            | ExprInner::Insert { endness, .. } => Ok(endness.clone()),
            _ => Err(PyAttributeError::new_err("no 'endness' on this Expression")),
        }
    }

    /// Load.guard / DirtyExpression.guard
    #[getter]
    fn guard(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.expr.inner {
            ExprInner::Load { guard, .. } | ExprInner::DirtyExpression { guard, .. } => match guard
            {
                Some(g) => {
                    let inner = Expression::wrap((**g).clone());
                    Ok(Some(Py::new(py, inner)?.into_any()))
                }
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err("no 'guard' on this Expression")),
        }
    }
    #[setter]
    fn set_guard(&mut self, value: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        let new = match value {
            Some(v) if !v.is_none() => Some(Box::new(extract_ail(&v)?)),
            _ => None,
        };
        match &mut self.expr.inner {
            ExprInner::Load { guard, .. } | ExprInner::DirtyExpression { guard, .. } => {
                self.expr.header.cached_hash.clear();
                *guard = new;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'guard' on this Expression")),
        }
    }

    /// ITE.cond
    #[getter]
    fn cond(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::ITE { cond, .. } => {
                Ok(Py::new(py, Expression::wrap((**cond).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'cond' on this Expression")),
        }
    }
    #[setter]
    fn set_cond(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let ail = extract_ail(&value)?;
        match &mut self.expr.inner {
            ExprInner::ITE { cond, .. } => {
                self.expr.header.cached_hash.clear();
                **cond = ail;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'cond' on this Expression")),
        }
    }

    /// ITE.iftrue
    #[getter]
    fn iftrue(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::ITE { iftrue, .. } => {
                Ok(Py::new(py, Expression::wrap((**iftrue).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'iftrue' on this Expression")),
        }
    }
    #[setter]
    fn set_iftrue(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let ail = extract_ail(&value)?;
        match &mut self.expr.inner {
            ExprInner::ITE { iftrue, .. } => {
                self.expr.header.cached_hash.clear();
                **iftrue = ail;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'iftrue' on this Expression")),
        }
    }

    /// ITE.iffalse
    #[getter]
    fn iffalse(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::ITE { iffalse, .. } => {
                Ok(Py::new(py, Expression::wrap((**iffalse).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'iffalse' on this Expression")),
        }
    }
    #[setter]
    fn set_iffalse(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let ail = extract_ail(&value)?;
        match &mut self.expr.inner {
            ExprInner::ITE { iffalse, .. } => {
                self.expr.header.cached_hash.clear();
                **iffalse = ail;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'iffalse' on this Expression")),
        }
    }

    /// Extract.base (Expression) / Insert.base (Expression) /
    /// BasePointerOffset.base (str) /
    /// StackBaseOffset.base (== ``"stack_base"``, the legacy contract).
    #[getter]
    fn base(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::Extract { base, .. } | ExprInner::Insert { base, .. } => {
                Ok(Py::new(py, Expression::wrap((**base).clone()))?.into_any())
            }
            ExprInner::BasePointerOffset { base, .. } => {
                Ok(pyo3::types::PyString::new(py, base).into_any().unbind())
            }
            ExprInner::StackBaseOffset { .. } => Ok(pyo3::types::PyString::new(py, "stack_base")
                .into_any()
                .unbind()),
            _ => Err(PyAttributeError::new_err("no 'base' on this Expression")),
        }
    }
    #[setter]
    fn set_base(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        match &mut self.expr.inner {
            ExprInner::Extract { base, .. } | ExprInner::Insert { base, .. } => {
                let ail = extract_ail(&value)?;
                self.expr.header.cached_hash.clear();
                **base = ail;
                Ok(())
            }
            ExprInner::BasePointerOffset { base, .. } => {
                let s: String = value
                    .extract()
                    .map_err(|_| PyTypeError::new_err("BasePointerOffset base must be a str"))?;
                self.expr.header.cached_hash.clear();
                *base = s;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'base' on this Expression")),
        }
    }

    /// Extract.offset (Expression) / Insert.offset (Expression) /
    /// BasePointerOffset.offset (int) /
    /// StackBaseOffset.offset (int).
    #[getter]
    fn offset(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.expr.inner {
            ExprInner::Extract { offset, .. } | ExprInner::Insert { offset, .. } => {
                Ok(Py::new(py, Expression::wrap((**offset).clone()))?.into_any())
            }
            ExprInner::BasePointerOffset { offset, .. } => {
                let i = (*offset).into_bound_py_any(py)?;
                Ok(i.unbind())
            }
            ExprInner::StackBaseOffset { offset } => {
                let i = (*offset).into_bound_py_any(py)?;
                Ok(i.unbind())
            }
            _ => Err(PyAttributeError::new_err("no 'offset' on this Expression")),
        }
    }
    #[setter]
    fn set_offset(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        match &mut self.expr.inner {
            ExprInner::Extract { offset, .. } | ExprInner::Insert { offset, .. } => {
                let ail = extract_ail(&value)?;
                self.expr.header.cached_hash.clear();
                **offset = ail;
                Ok(())
            }
            ExprInner::BasePointerOffset { offset, .. } => {
                let i: i64 = value
                    .extract()
                    .map_err(|_| PyTypeError::new_err("BasePointerOffset offset must be an int"))?;
                self.expr.header.cached_hash.clear();
                *offset = i;
                Ok(())
            }
            ExprInner::StackBaseOffset { offset } => {
                self.expr.header.cached_hash.clear();
                *offset = value.extract::<i128>()?;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'offset' on this Expression")),
        }
    }

    /// StringLiteral.data
    #[getter]
    fn data(&self) -> PyResult<String> {
        match &self.expr.inner {
            ExprInner::StringLiteral { data } => Ok(data.clone()),
            _ => Err(PyAttributeError::new_err("no 'data' on this Expression")),
        }
    }

    /// Load.alt
    #[getter]
    fn alt(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.expr.inner {
            ExprInner::Load { alt, .. } => match alt {
                Some(a) => {
                    let inner = Expression::wrap((**a).clone());
                    Ok(Some(Py::new(py, inner)?.into_any()))
                }
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err("no 'alt' on this Expression")),
        }
    }

    // --- Equality / hash ---------------------------------------------

    fn __hash__(&self) -> i64 {
        self.expr.cached_hash_or_compute()
    }

    /// Internal hash hook -- callers go through ``__hash__``, but
    /// ``angr.ailment.tagged_object`` and a handful of analyses reach
    /// for ``_hash_core`` directly. Recomputes from scratch each call
    /// (does not consult the cache) to match the legacy contract.
    fn _hash_core(&self) -> i64 {
        self.expr._hash_core()
    }

    /// Structural equality (ignores ``idx``). Same logic as ``__eq__``
    /// after the kind/idx short-circuit; exposed as a method because
    /// ~160 callers in angr/analyses use ``a.likes(b)`` rather than
    /// ``a == b``.
    fn likes(&self, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(o) = other.cast::<Expression>() else {
            return Ok(false);
        };
        Ok(self.expr.likes(&o.borrow().expr))
    }

    /// Structural-only equality. See ``AilExpression::matches`` for the
    /// full contract. In one line: ``matches`` is ``likes`` with SSA
    /// identifying info (notably ``VirtualVariable.varid``) stripped,
    /// so two structurally identical expressions originating from
    /// different SSA definitions compare equal. Used by dedup/similarity
    /// passes; not used by Python ``__eq__``.
    fn matches(&self, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(o) = other.cast::<Expression>() else {
            return Ok(false);
        };
        Ok(self.expr.matches(&o.borrow().expr))
    }

    /// ``replace(old, new)`` -- substitute any ``likes``-matching node
    /// in the operand subtrees. Returns ``(replaced, new_expr)`` to
    /// match the legacy contract; analyses use ``replaced`` to gate
    /// further work.
    fn replace<'py>(
        slf: PyRef<'py, Self>,
        old_expr: &Bound<'py, PyAny>,
        new_expr: &Bound<'py, PyAny>,
    ) -> PyResult<(bool, Py<PyAny>)> {
        let py = slf.py();
        let old_ail = extract_ail(old_expr)?;
        // Top-level match: return the supplied ``new_expr`` Python
        // object verbatim so callers that check ``replacement is new``
        // keep working.
        if slf.expr.likes(&old_ail) {
            return Ok((true, new_expr.clone().unbind()));
        }
        let new_ail = extract_ail(new_expr)?;
        let (changed, rebuilt) = slf.expr.replace_ail(&old_ail, &new_ail);
        if !changed {
            return Ok((false, slf.into_pyobject(py)?.into_any().unbind()));
        }
        Ok((true, Py::new(py, Expression::wrap(rebuilt))?.into_any()))
    }

    /// ``has_atom(atom, identity=True)`` -- recursive subtree search.
    #[pyo3(signature = (atom, identity=true))]
    fn has_atom(&self, atom: &Bound<'_, PyAny>, identity: bool) -> PyResult<bool> {
        let atom_ail = extract_ail(atom)?;
        Ok(self.expr.has_atom_ail(&atom_ail, identity))
    }

    /// ``copy()`` -- shallow clone (same ``idx``). Mirrors the legacy
    /// per-class ``copy`` contract: produce a new Python wrapper over
    /// the same AIL tree without re-numbering.
    fn copy(&self, py: Python<'_>) -> PyResult<Py<Self>> {
        Py::new(py, self.clone())
    }

    /// ``deep_copy(manager)`` -- recursive clone with fresh ``idx``
    /// from ``manager.next_atom()`` at every node. Used by clinic to
    /// re-number atoms when cloning blocks.
    fn deep_copy(&self, py: Python<'_>, manager: &Bound<'_, PyAny>) -> PyResult<Py<Self>> {
        let new = self.expr.deep_copy_ail(py, manager)?;
        Py::new(py, Expression::wrap(new))
    }

    /// Python ``copy.copy`` protocol -- delegates to ``copy()``.
    fn __copy__(&self, py: Python<'_>) -> PyResult<Py<Self>> {
        self.copy(py)
    }

    /// Python ``copy.deepcopy`` protocol -- routes through ``deep_copy``
    /// with a stand-in ``Manager`` from ``angr.ailment._reconstruct``.
    fn __deepcopy__<'py>(slf: Bound<'py, Self>, memo: Bound<'py, PyAny>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let helper = py
            .import("angr.ailment._reconstruct")?
            .getattr("deepcopy_via_deep_copy")?;
        Ok(helper.call1((slf, memo))?.unbind())
    }

    /// Python ``pickle`` protocol. Routes through ``to_bytes`` /
    /// ``from_bytes`` to preserve the full ``AilExpression`` shape.
    /// NB: the spike's ``Wire`` format is lossy for polymorphic
    /// Python-typed fields (Phi.src_and_vvars, VirtualVariable.oident,
    /// Call.target, ...) -- pickled trees that exercise those fields
    /// will round-trip as strings until the bulk serialization upgrade.
    fn __reduce__<'py>(slf: Bound<'py, Self>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let bytes = slf.borrow().to_bytes(py)?;
        let helper = py
            .import("angr.ailment._reconstruct")?
            .getattr("reconstruct_phase_d_expression")?;
        let args = PyTuple::new(py, [bytes.into_any()])?;
        let tup = PyTuple::new(py, [helper.unbind().into_any(), args.into_any().unbind()])?;
        Ok(tup.into_any().unbind())
    }

    fn __eq__(slf: Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        if slf.is(other) {
            return Ok(true);
        }
        let Ok(o) = other.cast::<Expression>() else {
            return Ok(false);
        };
        let s = slf.borrow();
        let o = o.borrow();
        if s.expr.kind() != o.expr.kind() {
            return Ok(false);
        }
        if s.expr.header.idx != o.expr.header.idx {
            return Ok(false);
        }
        Ok(s.expr.likes(&o.expr))
    }

    // --- Repr ---------------------------------------------------------

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        // A few variants render differently for repr vs str (matching the
        // legacy per-class pyclasses). Default to __str__ otherwise.
        match &self.expr.inner {
            ExprInner::FunctionLikeMacro { name, args, .. } => {
                let args_s = match args {
                    Some(v) => {
                        let parts: Vec<String> = v
                            .iter()
                            .map(|a| {
                                Py::new(py, Expression::wrap((**a).clone()))
                                    .and_then(|p| Ok(p.bind(py).repr()?.to_string()))
                                    .unwrap_or_default()
                            })
                            .collect();
                        format!("[{}]", parts.join(", "))
                    }
                    None => "None".into(),
                };
                Ok(format!("Macro(name={}, args={})", name, args_s))
            }
            ExprInner::Macro { name, .. } => Ok(format!("Macro(name={})", name)),
            _ => self.__str__(py),
        }
    }

    fn __str__(&self, py: Python<'_>) -> PyResult<String> {
        match &self.expr.inner {
            ExprInner::Const { value, .. } => {
                let v = value.clone().into_pyobject(py)?;
                Ok(format!("{}<{}>", v.str()?, self.expr.header.bits))
            }
            ExprInner::Tmp { tmp_idx, .. } => Ok(format!("t{}", tmp_idx)),
            ExprInner::Register { reg_offset, .. } => {
                Ok(format!("reg{}<{}>", reg_offset, self.expr.header.bits))
            }
            ExprInner::ComboRegister { registers, .. } => {
                let parts: Vec<String> = registers
                    .iter()
                    .map(|r| Expression::wrap(r.clone()).__str__(py).unwrap_or_default())
                    .collect();
                Ok(format!("ComboRegister({})", parts.join(", ")))
            }
            ExprInner::Phi { src_and_vvars, .. } => {
                let parts: Vec<String> = src_and_vvars
                    .iter()
                    .map(|e| {
                        let src_idx = match e.src_idx {
                            Some(v) => v.to_string(),
                            None => "None".into(),
                        };
                        let vv = match &e.vvar {
                            Some(v) => Expression::wrap((**v).clone())
                                .__str__(py)
                                .unwrap_or_else(|_| "<err>".into()),
                            None => "None".into(),
                        };
                        format!("(({}, {}), {})", e.src_addr, src_idx, vv)
                    })
                    .collect();
                Ok(format!("Phi([{}])", parts.join(", ")))
            }
            ExprInner::VirtualVariable {
                varid,
                category,
                oident,
                ..
            } => {
                use crate::ailment::enums::VirtualVariableCategory;
                let _ = py;
                let size = self.expr.header.bits / 8;
                let ori_str = match (category, oident) {
                    (VirtualVariableCategory::REGISTER, OIdent::Int(v)) => {
                        format!("{{r{}|{}b}}", v, size)
                    }
                    (VirtualVariableCategory::STACK, OIdent::Int(v)) => {
                        format!("{{s{}|{}b}}", v, size)
                    }
                    (VirtualVariableCategory::COMBO_REGISTER, OIdent::RegList(offs)) => {
                        let parts: Vec<String> = offs.iter().map(|x| x.to_string()).collect();
                        format!("{{combo_reg ({})}}", parts.join(", "))
                    }
                    _ => String::new(),
                };
                Ok(format!("vvar_{}{}", varid, ori_str))
            }
            ExprInner::UnaryOp { op, operand, .. } => {
                let o = Expression::wrap((**operand).clone()).__str__(py)?;
                Ok(format!("({} {})", op, o))
            }
            ExprInner::Convert {
                operand,
                from_bits,
                to_bits,
                is_signed,
                from_type,
                to_type,
                ..
            } => {
                let o = Expression::wrap((**operand).clone()).__str__(py)?;
                let ft = if *from_type == ConvertType::TYPE_FP {
                    "F"
                } else {
                    ""
                };
                let tt = if *to_type == ConvertType::TYPE_FP {
                    "F"
                } else {
                    ""
                };
                let s = if *is_signed { "s" } else { "" };
                Ok(format!(
                    "Conv({}{}->{}{}{}, {})",
                    from_bits, ft, s, to_bits, tt, o
                ))
            }
            ExprInner::Reinterpret {
                operand,
                from_bits,
                from_type,
                to_bits,
                to_type,
                ..
            } => {
                let o = Expression::wrap((**operand).clone()).__str__(py)?;
                Ok(format!(
                    "Reinterpret({}{}->{}{}, {})",
                    from_type, from_bits, to_type, to_bits, o
                ))
            }
            ExprInner::BinaryOp { op, operands, .. } => {
                let lhs = Expression::wrap((*operands[0]).clone()).__str__(py)?;
                let rhs = Expression::wrap((*operands[1]).clone()).__str__(py)?;
                Ok(format!("({} {} {})", lhs, op, rhs))
            }
            ExprInner::Load {
                addr,
                size,
                endness,
                ..
            } => {
                let a = Expression::wrap((**addr).clone()).__str__(py)?;
                Ok(format!(
                    "Load(addr={}, size={}, endness={})",
                    a, size, endness
                ))
            }
            ExprInner::Call { target, args, .. } => {
                let args_str = match args {
                    None => String::new(),
                    Some(v) => {
                        let parts: Vec<String> = v
                            .iter()
                            .map(|x| Expression::wrap(x.clone()).__str__(py).unwrap_or_default())
                            .collect();
                        format!("({})", parts.join(", "))
                    }
                };
                let target_str = match target {
                    CFGTarget::Expr(e) => Expression::wrap((**e).clone()).__str__(py)?,
                    CFGTarget::Symbol(s) => s.clone(),
                };
                Ok(format!("Call({}, {})", target_str, args_str))
            }
            ExprInner::ITE {
                cond,
                iffalse,
                iftrue,
                ..
            } => {
                let c = Expression::wrap((**cond).clone()).__str__(py)?;
                let t = Expression::wrap((**iftrue).clone()).__str__(py)?;
                let f = Expression::wrap((**iffalse).clone()).__str__(py)?;
                Ok(format!("(({}) ? ({}) : ({}))", c, t, f))
            }
            ExprInner::Extract { base, offset, .. } => {
                let b = Expression::wrap((**base).clone()).__str__(py)?;
                let o = Expression::wrap((**offset).clone()).__str__(py)?;
                Ok(format!(
                    "Extract({}, {}bits@{})",
                    b, self.expr.header.bits, o
                ))
            }
            ExprInner::Insert {
                base,
                offset,
                value,
                ..
            } => {
                let b = Expression::wrap((**base).clone()).__str__(py)?;
                let o = Expression::wrap((**offset).clone()).__str__(py)?;
                let v = Expression::wrap((**value).clone()).__str__(py)?;
                Ok(format!("Insert({}, {}, {})", b, o, v))
            }
            ExprInner::StringLiteral { data } => {
                let _ = py;
                Ok(format!("StringLiteral({:?})", data))
            }
            ExprInner::BasePointerOffset { base, offset, .. } => {
                let _ = py;
                Ok(format!("{}{:+}", base, offset))
            }
            ExprInner::StackBaseOffset { offset } => Ok(format!("sp{:+}", offset)),
            ExprInner::DirtyExpression {
                callee, operands, ..
            } => {
                let parts: Vec<String> = operands
                    .iter()
                    .map(|o| Expression::wrap(o.clone()).__str__(py).unwrap_or_default())
                    .collect();
                Ok(format!("[D] {}({})", callee, parts.join(", ")))
            }
            ExprInner::VEXCCallExpression { callee, operands } => {
                let parts: Vec<String> = operands
                    .iter()
                    .map(|o| Expression::wrap(o.clone()).__str__(py).unwrap_or_default())
                    .collect();
                Ok(format!("{}({})", callee, parts.join(", ")))
            }
            ExprInner::MultiStatementExpression { stmts, expr } => {
                let mut parts: Vec<String> = Vec::new();
                for s in stmts {
                    parts.push(crate::ailment::ail_stmt::Statement::wrap(s.clone()).render(py)?);
                }
                parts.push(Expression::wrap((**expr).clone()).__str__(py)?);
                Ok(format!("({})", parts.join(", ")))
            }
            ExprInner::Struct { name, fields, .. } => {
                let parts: Vec<String> = fields
                    .iter()
                    .map(|(off, e)| {
                        Ok::<_, PyErr>(format!(
                            "{}: {}",
                            off,
                            Expression::wrap((**e).clone()).__str__(py)?
                        ))
                    })
                    .collect::<PyResult<_>>()?;
                Ok(format!("{} {{{}}}", name, parts.join(", ")))
            }
            ExprInner::RustEnum { name, fields } => {
                let parts: Vec<String> = fields
                    .iter()
                    .map(|f| Expression::wrap((**f).clone()).__str__(py))
                    .collect::<PyResult<_>>()?;
                Ok(format!("{}({})", name, parts.join(", ")))
            }
            ExprInner::Array { elements } => {
                let parts: Vec<String> = elements
                    .iter()
                    .map(|e| Expression::wrap((**e).clone()).__str__(py))
                    .collect::<PyResult<_>>()?;
                Ok(format!("[{}]", parts.join(", ")))
            }
            ExprInner::Let { src, .. } => Ok(format!(
                "let (_) = {}",
                Expression::wrap((**src).clone()).__str__(py)?
            )),
            ExprInner::Macro {
                name, delimiter, ..
            } => {
                let mut chars = delimiter.chars();
                let open = chars.next().unwrap_or('(');
                let close = chars.next().unwrap_or(')');
                Ok(format!("{}!{}{}", name, open, close))
            }
            ExprInner::FunctionLikeMacro {
                name,
                delimiter,
                args,
                ..
            } => {
                let mut chars = delimiter.chars();
                let open = chars.next().unwrap_or('(');
                let close = chars.next().unwrap_or(')');
                let args_s = match args {
                    Some(v) => {
                        let parts: Vec<String> = v
                            .iter()
                            .map(|a| Expression::wrap((**a).clone()).__str__(py))
                            .collect::<PyResult<_>>()?;
                        parts.join(", ")
                    }
                    None => "".into(),
                };
                Ok(format!("{}!{}{}{}", name, open, args_s, close))
            }
        }
    }

    // --- Byte serialization ------------------------------------------
    //
    // Stub for the spike: round-trips Const only (the simplest variant)
    // via a minimal hand-coded format. The full serialization story is
    // a follow-up commit -- the bulk migration will switch to postcard
    // deriving on AilExpression directly.

    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = postcard::to_stdvec(&serialize::Wire::from(&self.expr))
            .map_err(|e| PyTypeError::new_err(format!("serialize: {}", e)))?;
        Ok(PyBytes::new(py, &bytes))
    }

    #[classmethod]
    fn from_bytes<'py>(
        _cls: &Bound<'_, pyo3::types::PyType>,
        py: Python<'py>,
        data: &[u8],
    ) -> PyResult<Py<Expression>> {
        let wire: serialize::Wire = postcard::from_bytes(data)
            .map_err(|e| PyTypeError::new_err(format!("deserialize: {}", e)))?;
        Py::new(py, Expression::wrap(wire.into_ail()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate that ``src_and_vvars`` is a list of ``((src_addr, block_idx),
/// vvar_or_None)`` pairs where each vvar slot is either ``None`` or a
/// ``VirtualVariable`` ``Expression``. Phi semantics require this; any
/// other expression type indicates a bug at the producer site. The
/// error message includes the offending kind/value plus a Python
/// traceback (via ``traceback.format_stack``) so the upstream call site
/// is easy to locate.
/// Parse a Python iterable of ``((src_addr, src_idx), vvar)`` pairs into
/// a typed ``Vec<PhiEntry>``. The ``vvar`` slot must be ``None`` or a
/// ``VirtualVariable`` Expression -- anything else raises ``TypeError``
/// with a Python traceback so the upstream producer is easy to find.
fn extract_phi_entries(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<Vec<PhiEntry>> {
    let type_name = |obj: &Bound<'_, PyAny>| -> String {
        obj.get_type()
            .qualname()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string())
    };
    let repr = |obj: &Bound<'_, PyAny>| -> String {
        obj.repr()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| "<unrepresentable>".to_string())
    };
    let iter = obj.try_iter().map_err(|_| {
        phi_validation_error(
            py,
            &format!(
                "Phi.src_and_vvars must be iterable, got type {}",
                type_name(obj)
            ),
        )
    })?;
    let mut out: Vec<PhiEntry> = Vec::new();
    for (idx, item_res) in iter.enumerate() {
        let item = item_res?;
        let Ok(pair) = item.cast::<PyTuple>() else {
            return Err(phi_validation_error(
                py,
                &format!(
                    "Phi.src_and_vvars[{}] is not a 2-tuple (got type {})",
                    idx,
                    type_name(&item)
                ),
            ));
        };
        if pair.len() != 2 {
            return Err(phi_validation_error(
                py,
                &format!(
                    "Phi.src_and_vvars[{}] tuple has {} elements, expected 2",
                    idx,
                    pair.len()
                ),
            ));
        }
        let src = pair.get_item(0)?;
        let Ok(src_tuple) = src.cast::<PyTuple>() else {
            return Err(phi_validation_error(
                py,
                &format!(
                    "Phi.src_and_vvars[{}] src is not a 2-tuple (got type {})",
                    idx,
                    type_name(&src)
                ),
            ));
        };
        if src_tuple.len() != 2 {
            return Err(phi_validation_error(
                py,
                &format!(
                    "Phi.src_and_vvars[{}] src tuple has {} elements, expected 2",
                    idx,
                    src_tuple.len()
                ),
            ));
        }
        let src_addr: i64 = src_tuple.get_item(0)?.extract().map_err(|_| {
            phi_validation_error(
                py,
                &format!("Phi.src_and_vvars[{}] src_addr must be int", idx),
            )
        })?;
        let src_idx_obj = src_tuple.get_item(1)?;
        let src_idx: Option<i64> = if src_idx_obj.is_none() {
            None
        } else {
            Some(src_idx_obj.extract().map_err(|_| {
                phi_validation_error(
                    py,
                    &format!("Phi.src_and_vvars[{}] src_idx must be int or None", idx),
                )
            })?)
        };
        let vvar_obj = pair.get_item(1)?;
        let vvar: Option<Box<AilExpression>> = if vvar_obj.is_none() {
            None
        } else if let Ok(e) = vvar_obj.cast::<Expression>() {
            let inner = e.borrow().expr.clone();
            if !matches!(inner.inner, ExprInner::VirtualVariable { .. }) {
                return Err(phi_validation_error(
                    py,
                    &format!(
                        "Phi.src_and_vvars[{}] vvar slot must be a VirtualVariable, got kind={:?} repr={}",
                        idx,
                        inner.kind(),
                        repr(&vvar_obj),
                    ),
                ));
            }
            Some(Box::new(inner))
        } else {
            return Err(phi_validation_error(
                py,
                &format!(
                    "Phi.src_and_vvars[{}] vvar slot must be a VirtualVariable or None (got type {}, repr {})",
                    idx,
                    type_name(&vvar_obj),
                    repr(&vvar_obj),
                ),
            ));
        };
        out.push(PhiEntry {
            src_addr,
            src_idx,
            vvar,
        });
    }
    Ok(out)
}

/// Build a ``TypeError`` whose message includes a Python ``traceback.
/// format_stack`` dump so the upstream producer of the bad Phi shape
/// is easy to spot.
fn phi_validation_error(py: Python<'_>, msg: &str) -> PyErr {
    let trace = py
        .import("traceback")
        .and_then(|tb| tb.call_method0("format_stack"))
        .and_then(|frames| {
            let parts: Vec<String> = frames
                .try_iter()?
                .map(|f| f.and_then(|x| x.extract::<String>()))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(parts.join(""))
        })
        .unwrap_or_default();
    PyTypeError::new_err(format!("{}\n  Producer traceback:\n{}", msg, trace))
}

/// Extract an [`AilExpression`] from a Python object that must be an
/// ``Expression`` instance. Clones the inner Rust struct (deep copy of
/// the variant; operand subtrees are heap-cloned).
pub fn extract_ail(obj: &Bound<'_, PyAny>) -> PyResult<AilExpression> {
    let e: PyRef<'_, Expression> = obj
        .cast::<Expression>()
        .map_err(|_| PyTypeError::new_err("expected an Expression"))?
        .borrow();
    Ok(e.expr.clone())
}

// ---------------------------------------------------------------------------
// Minimal serialization (spike-only)
// ---------------------------------------------------------------------------

pub mod serialize {
    use super::{
        AilExpression, CFGTarget, ConstValue, ExprHeader, ExprInner, Expression, OIdent,
        ParameterOIdent,
    };
    use crate::ailment::enums::{ConvertType, RoundingMode};
    use crate::ailment::tags::Tags;
    use indexmap::IndexMap;
    use pyo3::IntoPyObjectExt;
    use pyo3::prelude::*;
    use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct Hdr {
        pub idx: i64,
        pub bits: u32,
        pub depth: u32,
        pub tags: Tags,
    }

    /// Typed serialization wrapper for polymorphic Python-typed slots
    /// (SimVariable, calling-convention, rounding-mode, oident, ...).
    ///
    /// AIL Expressions embed losslessly via the recursive ``Expr``
    /// variant; primitive Python types (int/float/str/bytes/bool) map
    /// to their direct counterparts; lists/tuples/dicts recurse;
    /// anything else falls back to ``pickle.dumps`` -- which covers
    /// SimVariables, calling conventions, prototypes, etc.
    ///
    /// Replaces the spike-local ``*_repr: String`` stringification on
    /// the lossy Wire fields and the ``variable_repr: Option<String>``
    /// fallbacks. With ``PolyValue`` every polymorphic slot round-trips
    /// with full fidelity.
    #[derive(Serialize, Deserialize)]
    pub enum PolyValue {
        None,
        /// Recursive Phase D Expression embedding.
        Expr(Box<Wire>),
        /// Pickle bytes for arbitrary Python objects.
        Pickle(Vec<u8>),
        Bool(bool),
        Int(i64),
        /// Hex (no `0x` prefix, optional `-`) for ints outside i64.
        BigInt(String),
        Float(f64),
        Str(String),
        Bytes(Vec<u8>),
        Tuple(Vec<PolyValue>),
        List(Vec<PolyValue>),
        Dict(Vec<(PolyValue, PolyValue)>),
    }

    impl PolyValue {
        pub fn from_pyany(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
            let py = obj.py();
            if obj.is_none() {
                return Ok(Self::None);
            }
            // Phase D Expression -- recursive Wire embedding.
            if let Ok(e) = obj.cast::<Expression>() {
                return Ok(Self::Expr(Box::new(Wire::from(&e.borrow().expr))));
            }
            // PyBool BEFORE PyInt (bool is a subclass of int).
            if let Ok(b) = obj.cast::<PyBool>() {
                return Ok(Self::Bool(b.is_true()));
            }
            if let Ok(_i) = obj.cast::<PyInt>() {
                if let Ok(v) = obj.extract::<i64>() {
                    return Ok(Self::Int(v));
                }
                // Outside i64 range -- preserve as hex.
                let s: String = obj
                    .call_method1("__format__", ("x",))
                    .and_then(|x| x.extract())?;
                return Ok(Self::BigInt(s));
            }
            if let Ok(f) = obj.cast::<PyFloat>() {
                return Ok(Self::Float(f.value()));
            }
            if let Ok(s) = obj.cast::<PyString>() {
                return Ok(Self::Str(s.extract()?));
            }
            if let Ok(b) = obj.cast::<PyBytes>() {
                return Ok(Self::Bytes(b.as_bytes().to_vec()));
            }
            if let Ok(t) = obj.cast::<PyTuple>() {
                let mut v = Vec::with_capacity(t.len());
                for x in t.iter() {
                    v.push(PolyValue::from_pyany(&x)?);
                }
                return Ok(Self::Tuple(v));
            }
            if let Ok(l) = obj.cast::<PyList>() {
                let mut v = Vec::with_capacity(l.len());
                for x in l.iter() {
                    v.push(PolyValue::from_pyany(&x)?);
                }
                return Ok(Self::List(v));
            }
            if let Ok(d) = obj.cast::<PyDict>() {
                let mut v = Vec::with_capacity(d.len());
                for (k, vv) in d.iter() {
                    v.push((PolyValue::from_pyany(&k)?, PolyValue::from_pyany(&vv)?));
                }
                return Ok(Self::Dict(v));
            }
            // Fallback: pickle.
            let pickle = py.import("pickle")?;
            let bytes: Vec<u8> = pickle
                .call_method1("dumps", (obj,))?
                .cast::<PyBytes>()?
                .as_bytes()
                .to_vec();
            Ok(Self::Pickle(bytes))
        }

        pub fn into_pyany(self, py: Python<'_>) -> PyResult<Py<PyAny>> {
            match self {
                Self::None => Ok(py.None()),
                Self::Expr(w) => {
                    let e = Expression::wrap(w.into_ail());
                    Ok(Py::new(py, e)?.into_any())
                }
                Self::Pickle(bytes) => {
                    let pickle = py.import("pickle")?;
                    Ok(pickle
                        .call_method1("loads", (PyBytes::new(py, &bytes),))?
                        .unbind())
                }
                Self::Bool(b) => Ok(b.into_bound_py_any(py)?.unbind()),
                Self::Int(i) => Ok(i.into_bound_py_any(py)?.unbind()),
                Self::BigInt(s) => {
                    let builtins = py.import("builtins")?;
                    Ok(builtins.getattr("int")?.call1((s.as_str(), 16))?.unbind())
                }
                Self::Float(f) => Ok(f.into_bound_py_any(py)?.unbind()),
                Self::Str(s) => Ok(PyString::new(py, &s).into_any().unbind()),
                Self::Bytes(b) => Ok(PyBytes::new(py, &b).into_any().unbind()),
                Self::Tuple(v) => {
                    let items: Vec<Py<PyAny>> = v
                        .into_iter()
                        .map(|x| x.into_pyany(py))
                        .collect::<PyResult<Vec<_>>>()?;
                    Ok(PyTuple::new(py, items)?.into_any().unbind())
                }
                Self::List(v) => {
                    let l = PyList::empty(py);
                    for x in v {
                        l.append(x.into_pyany(py)?)?;
                    }
                    Ok(l.into_any().unbind())
                }
                Self::Dict(v) => {
                    let d = PyDict::new(py);
                    for (k, vv) in v {
                        d.set_item(k.into_pyany(py)?, vv.into_pyany(py)?)?;
                    }
                    Ok(d.into_any().unbind())
                }
            }
        }

        /// Convenience: convert ``Option<Py<PyAny>>`` to ``Option<PolyValue>``,
        /// preserving ``None``.
        pub fn from_opt(o: &Option<Py<PyAny>>, py: Python<'_>) -> PyResult<Option<Self>> {
            match o {
                None => Ok(None),
                Some(v) => Ok(Some(Self::from_pyany(v.bind(py))?)),
            }
        }

        pub fn into_opt(o: Option<Self>, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
            match o {
                None => Ok(None),
                Some(v) => Ok(Some(v.into_pyany(py)?)),
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    pub enum Wire {
        Const {
            h: Hdr,
            value: ConstValue,
        },
        Tmp {
            h: Hdr,
            tmp_idx: i64,
        },
        Register {
            h: Hdr,
            reg_offset: i64,
        },
        ComboRegister {
            h: Hdr,
            registers: Vec<Wire>,
        },
        Phi {
            h: Hdr,
            src_and_vvars: PolyValue,
        },
        VirtualVariable {
            h: Hdr,
            varid: i64,
            category: u8,
            oident: PolyValue,
            reg_vvars: Option<Vec<Wire>>,
        },
        UnaryOp {
            h: Hdr,
            op: String,
            operand: Box<Wire>,
        },
        Convert {
            h: Hdr,
            operand: Box<Wire>,
            from_bits: u32,
            to_bits: u32,
            is_signed: bool,
            from_type: ConvertType,
            to_type: ConvertType,
            rounding_mode: Option<RoundingMode>,
        },
        Reinterpret {
            h: Hdr,
            operand: Box<Wire>,
            from_bits: u32,
            from_type: String,
            to_bits: u32,
            to_type: String,
        },
        BinaryOp {
            h: Hdr,
            op: String,
            lhs: Box<Wire>,
            rhs: Box<Wire>,
            signed: bool,
            floating_point: bool,
            vector_count: Option<i64>,
            vector_size: Option<i64>,
            rounding_mode: Option<RoundingMode>,
        },
        Load {
            h: Hdr,
            addr: Box<Wire>,
            size: i32,
            endness: String,
            guard: Option<Box<Wire>>,
            alt: Option<Box<Wire>>,
        },
        Call {
            h: Hdr,
            target: PolyValue,
            args: Option<Vec<Wire>>,
            arg_vvars: Option<Vec<Wire>>,
        },
        ITE {
            h: Hdr,
            cond: Box<Wire>,
            iffalse: Box<Wire>,
            iftrue: Box<Wire>,
        },
        Extract {
            h: Hdr,
            base: Box<Wire>,
            offset: Box<Wire>,
            endness: String,
        },
        Insert {
            h: Hdr,
            base: Box<Wire>,
            offset: Box<Wire>,
            value: Box<Wire>,
            endness: String,
        },
        StringLiteral {
            h: Hdr,
            data: String,
        },
        BasePointerOffset {
            h: Hdr,
            base: String,
            offset: i64,
        },
        StackBaseOffset {
            h: Hdr,
            offset: i128,
        },
        DirtyExpression {
            h: Hdr,
            callee: String,
            operands: Vec<Wire>,
            guard: Option<Box<Wire>>,
            mfx: Option<String>,
            maddr: Option<Box<Wire>>,
            msize: Option<i64>,
        },
        VEXCCallExpression {
            h: Hdr,
            callee: String,
            operands: Vec<Wire>,
        },
        /// Full-fidelity round-trip via the Statement-side ``StmtWire``
        /// (Statements joined the fat-enum design in a later commit).
        MultiStatementExpression {
            h: Hdr,
            stmts: Vec<crate::ailment::ail_stmt::StmtWire>,
            expr: Box<Wire>,
        },
        Struct {
            h: Hdr,
            name: String,
            /// Insertion-ordered ``(offset, expression)`` pairs.
            fields: Vec<(i64, Wire)>,
            /// Insertion-ordered ``(name, offset)`` pairs. ``field_names``
            /// is omitted -- it's derivable as the reverse of this map
            /// during ``into_ail``.
            field_offsets: Vec<(String, i64)>,
        },
        RustEnum {
            h: Hdr,
            name: String,
            fields: Vec<Wire>,
        },
        Array {
            h: Hdr,
            elements: Vec<Wire>,
        },
        Let {
            h: Hdr,
            defs: Vec<crate::ailment::ail_stmt::StmtWire>,
            src: Box<Wire>,
        },
        Macro {
            h: Hdr,
            name: String,
            delimiter: String,
        },
        FunctionLikeMacro {
            h: Hdr,
            name: String,
            delimiter: String,
            args: Option<Vec<Wire>>,
        },
    }

    impl Wire {
        pub fn from(ail: &AilExpression) -> Self {
            let hdr = Hdr {
                idx: ail.header.idx,
                bits: ail.header.bits,
                depth: ail.header.depth,
                tags: ail.header.tags.clone(),
            };
            match &ail.inner {
                ExprInner::Const { value } => Wire::Const {
                    h: hdr,
                    value: value.clone(),
                },
                ExprInner::Tmp { tmp_idx } => Wire::Tmp {
                    h: hdr,
                    tmp_idx: *tmp_idx,
                },
                ExprInner::Register { reg_offset } => Wire::Register {
                    h: hdr,
                    reg_offset: *reg_offset,
                },
                ExprInner::ComboRegister { registers } => Wire::ComboRegister {
                    h: hdr,
                    registers: registers.iter().map(Wire::from).collect(),
                },
                ExprInner::Phi { src_and_vvars } => {
                    // Project the typed ``Vec<PhiEntry>`` into the
                    // existing ``PolyValue`` wire shape -- each entry
                    // becomes a 2-tuple
                    // ``((src_addr, src_idx), VirtualVariable_wire | None)``.
                    let items: Vec<PolyValue> = src_and_vvars
                        .iter()
                        .map(|e| {
                            let src_tuple = PolyValue::Tuple(vec![
                                PolyValue::Int(e.src_addr),
                                match e.src_idx {
                                    Some(v) => PolyValue::Int(v),
                                    None => PolyValue::None,
                                },
                            ]);
                            let vvar_value = match &e.vvar {
                                Some(v) => PolyValue::Expr(Box::new(Wire::from(v.as_ref()))),
                                None => PolyValue::None,
                            };
                            PolyValue::Tuple(vec![src_tuple, vvar_value])
                        })
                        .collect();
                    Wire::Phi {
                        h: hdr,
                        src_and_vvars: PolyValue::List(items),
                    }
                }
                ExprInner::VirtualVariable {
                    varid,
                    category,
                    oident,
                    reg_vvars,
                } => {
                    // Project the typed ``OIdent`` into the existing
                    // ``PolyValue`` wire shape so cached AIL blobs stay
                    // compatible.
                    fn ident_to_poly(o: &OIdent) -> PolyValue {
                        match o {
                            OIdent::None => PolyValue::None,
                            OIdent::Int(v) => PolyValue::Int(*v),
                            OIdent::RegList(offs) => {
                                PolyValue::Tuple(offs.iter().map(|x| PolyValue::Int(*x)).collect())
                            }
                            OIdent::Parameter(p) => {
                                let inner_cat = p.inner_category() as i64;
                                let inner = match p {
                                    ParameterOIdent::Register(v) | ParameterOIdent::Stack(v) => {
                                        PolyValue::Int(*v)
                                    }
                                    ParameterOIdent::ComboRegister(offs) => PolyValue::Tuple(
                                        offs.iter().map(|x| PolyValue::Int(*x)).collect(),
                                    ),
                                };
                                PolyValue::Tuple(vec![PolyValue::Int(inner_cat), inner])
                            }
                        }
                    }
                    Wire::VirtualVariable {
                        h: hdr,
                        varid: *varid,
                        category: *category as u8,
                        oident: ident_to_poly(oident),
                        reg_vvars: reg_vvars
                            .as_ref()
                            .map(|vec| vec.iter().map(|b| Wire::from(b.as_ref())).collect()),
                    }
                }
                ExprInner::UnaryOp { op, operand } => Wire::UnaryOp {
                    h: hdr,
                    op: op.clone(),
                    operand: Box::new(Wire::from(operand)),
                },
                ExprInner::Convert {
                    operand,
                    from_bits,
                    to_bits,
                    is_signed,
                    from_type,
                    to_type,
                    rounding_mode,
                } => Wire::Convert {
                    h: hdr,
                    operand: Box::new(Wire::from(operand)),
                    from_bits: *from_bits,
                    to_bits: *to_bits,
                    is_signed: *is_signed,
                    from_type: *from_type,
                    to_type: *to_type,
                    rounding_mode: *rounding_mode,
                },
                ExprInner::Reinterpret {
                    operand,
                    from_bits,
                    from_type,
                    to_bits,
                    to_type,
                } => Wire::Reinterpret {
                    h: hdr,
                    operand: Box::new(Wire::from(operand)),
                    from_bits: *from_bits,
                    from_type: from_type.clone(),
                    to_bits: *to_bits,
                    to_type: to_type.clone(),
                },
                ExprInner::BinaryOp {
                    op,
                    operands,
                    signed,
                    floating_point,
                    vector_count,
                    vector_size,
                    rounding_mode,
                } => Wire::BinaryOp {
                    h: hdr,
                    op: op.clone(),
                    lhs: Box::new(Wire::from(&operands[0])),
                    rhs: Box::new(Wire::from(&operands[1])),
                    signed: *signed,
                    floating_point: *floating_point,
                    vector_count: *vector_count,
                    vector_size: *vector_size,
                    rounding_mode: *rounding_mode,
                },
                ExprInner::Load {
                    addr,
                    size,
                    endness,
                    guard,
                    alt,
                } => Wire::Load {
                    h: hdr,
                    addr: Box::new(Wire::from(addr)),
                    size: *size,
                    endness: endness.clone(),
                    guard: guard.as_ref().map(|g| Box::new(Wire::from(g))),
                    alt: alt.as_ref().map(|a| Box::new(Wire::from(a))),
                },
                ExprInner::Call {
                    target,
                    args,
                    arg_vvars,
                } => Wire::Call {
                    h: hdr,
                    target: match target {
                        CFGTarget::Expr(e) => PolyValue::Expr(Box::new(Wire::from(e.as_ref()))),
                        CFGTarget::Symbol(s) => PolyValue::Str(s.clone()),
                    },
                    args: args.as_ref().map(|v| v.iter().map(Wire::from).collect()),
                    arg_vvars: arg_vvars
                        .as_ref()
                        .map(|v| v.iter().map(Wire::from).collect()),
                },
                ExprInner::ITE {
                    cond,
                    iffalse,
                    iftrue,
                } => Wire::ITE {
                    h: hdr,
                    cond: Box::new(Wire::from(cond)),
                    iffalse: Box::new(Wire::from(iffalse)),
                    iftrue: Box::new(Wire::from(iftrue)),
                },
                ExprInner::Extract {
                    base,
                    offset,
                    endness,
                } => Wire::Extract {
                    h: hdr,
                    base: Box::new(Wire::from(base)),
                    offset: Box::new(Wire::from(offset)),
                    endness: endness.clone(),
                },
                ExprInner::Insert {
                    base,
                    offset,
                    value,
                    endness,
                } => Wire::Insert {
                    h: hdr,
                    base: Box::new(Wire::from(base)),
                    offset: Box::new(Wire::from(offset)),
                    value: Box::new(Wire::from(value)),
                    endness: endness.clone(),
                },
                ExprInner::StringLiteral { data } => Wire::StringLiteral {
                    h: hdr,
                    data: data.clone(),
                },
                ExprInner::BasePointerOffset { base, offset } => Wire::BasePointerOffset {
                    h: hdr,
                    base: base.clone(),
                    offset: *offset,
                },
                ExprInner::StackBaseOffset { offset } => Wire::StackBaseOffset {
                    h: hdr,
                    offset: *offset,
                },
                ExprInner::DirtyExpression {
                    callee,
                    operands,
                    guard,
                    mfx,
                    maddr,
                    msize,
                } => Wire::DirtyExpression {
                    h: hdr,
                    callee: callee.clone(),
                    operands: operands.iter().map(Wire::from).collect(),
                    guard: guard.as_ref().map(|g| Box::new(Wire::from(g))),
                    mfx: mfx.clone(),
                    maddr: maddr.as_ref().map(|m| Box::new(Wire::from(m))),
                    msize: *msize,
                },
                ExprInner::VEXCCallExpression { callee, operands } => Wire::VEXCCallExpression {
                    h: hdr,
                    callee: callee.clone(),
                    operands: operands.iter().map(Wire::from).collect(),
                },
                ExprInner::MultiStatementExpression { stmts, expr } => {
                    Wire::MultiStatementExpression {
                        h: hdr,
                        stmts: stmts
                            .iter()
                            .map(crate::ailment::ail_stmt::StmtWire::from)
                            .collect(),
                        expr: Box::new(Wire::from(expr)),
                    }
                }
                ExprInner::Struct {
                    name,
                    fields,
                    field_offsets,
                    ..
                } => Wire::Struct {
                    h: hdr,
                    name: name.clone(),
                    fields: fields
                        .iter()
                        .map(|(off, e)| (*off, Wire::from(e.as_ref())))
                        .collect(),
                    field_offsets: field_offsets
                        .iter()
                        .map(|(n, off)| (n.clone(), *off))
                        .collect(),
                },
                ExprInner::RustEnum { name, fields } => Wire::RustEnum {
                    h: hdr,
                    name: name.clone(),
                    fields: fields.iter().map(|b| Wire::from(b.as_ref())).collect(),
                },
                ExprInner::Array { elements } => Wire::Array {
                    h: hdr,
                    elements: elements.iter().map(|b| Wire::from(b.as_ref())).collect(),
                },
                ExprInner::Let { defs, src } => Wire::Let {
                    h: hdr,
                    defs: defs
                        .iter()
                        .map(|b| crate::ailment::ail_stmt::StmtWire::from(b.as_ref()))
                        .collect(),
                    src: Box::new(Wire::from(src)),
                },
                ExprInner::Macro { name, delimiter } => Wire::Macro {
                    h: hdr,
                    name: name.clone(),
                    delimiter: delimiter.clone(),
                },
                ExprInner::FunctionLikeMacro {
                    name,
                    delimiter,
                    args,
                } => Wire::FunctionLikeMacro {
                    h: hdr,
                    name: name.clone(),
                    delimiter: delimiter.clone(),
                    args: args
                        .as_ref()
                        .map(|v| v.iter().map(|b| Wire::from(b.as_ref())).collect()),
                },
            }
        }

        pub fn into_ail(self) -> AilExpression {
            fn rebuild_header(h: Hdr) -> ExprHeader {
                ExprHeader::new(h.idx, h.depth, h.bits, h.tags)
            }
            match self {
                Wire::Const { h, value } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Const { value },
                },
                Wire::Tmp { h, tmp_idx } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Tmp { tmp_idx },
                },
                Wire::Register { h, reg_offset } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Register { reg_offset },
                },
                Wire::ComboRegister { h, registers } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::ComboRegister {
                        registers: registers.into_iter().map(Wire::into_ail).collect(),
                    },
                },
                Wire::Phi { h, src_and_vvars } => {
                    // Inverse of the projection in ``Wire::from``: walk
                    // the wire ``PolyValue::List`` of 2-tuples and
                    // reconstruct typed ``PhiEntry``s.
                    let entries: Vec<crate::ailment::ail_expr::PhiEntry> = match src_and_vvars {
                        PolyValue::List(items) => items
                            .into_iter()
                            .map(|item| match item {
                                PolyValue::Tuple(pair) => {
                                    let mut it = pair.into_iter();
                                    let src = it.next().unwrap_or(PolyValue::None);
                                    let vvar_pv = it.next().unwrap_or(PolyValue::None);
                                    let (src_addr, src_idx) = match src {
                                        PolyValue::Tuple(srcs) => {
                                            let mut sit = srcs.into_iter();
                                            let a = match sit.next() {
                                                Some(PolyValue::Int(v)) => v,
                                                _ => 0,
                                            };
                                            let b = match sit.next() {
                                                Some(PolyValue::Int(v)) => Some(v),
                                                _ => None,
                                            };
                                            (a, b)
                                        }
                                        _ => (0, None),
                                    };
                                    let vvar = match vvar_pv {
                                        PolyValue::Expr(wire) => Some(Box::new(wire.into_ail())),
                                        _ => None,
                                    };
                                    crate::ailment::ail_expr::PhiEntry {
                                        src_addr,
                                        src_idx,
                                        vvar,
                                    }
                                }
                                _ => crate::ailment::ail_expr::PhiEntry {
                                    src_addr: 0,
                                    src_idx: None,
                                    vvar: None,
                                },
                            })
                            .collect(),
                        _ => Vec::new(),
                    };
                    AilExpression {
                        header: rebuild_header(h),
                        inner: ExprInner::Phi {
                            src_and_vvars: entries,
                        },
                    }
                }
                Wire::VirtualVariable {
                    h,
                    varid,
                    category,
                    oident,
                    reg_vvars,
                } => Python::attach(|py| {
                    use crate::ailment::enums::VirtualVariableCategory;
                    let cat = VirtualVariableCategory::from_int(category as i64)
                        .unwrap_or(VirtualVariableCategory::UNKNOWN);
                    // Inverse of ``ident_to_poly`` in ``Wire::from``.
                    fn poly_to_ident(pv: PolyValue, cat: VirtualVariableCategory) -> OIdent {
                        use VirtualVariableCategory::*;
                        match (cat, pv) {
                            (UNKNOWN, _) | (_, PolyValue::None) => OIdent::None,
                            (REGISTER | STACK | MEMORY | TMP, PolyValue::Int(v)) => OIdent::Int(v),
                            (COMBO_REGISTER, PolyValue::Tuple(items)) => {
                                let offs = items
                                    .into_iter()
                                    .filter_map(|x| match x {
                                        PolyValue::Int(v) => Some(v),
                                        _ => None,
                                    })
                                    .collect();
                                OIdent::RegList(offs)
                            }
                            (PARAMETER, PolyValue::Tuple(items)) => {
                                let mut it = items.into_iter();
                                let inner_cat_pv = it.next().unwrap_or(PolyValue::None);
                                let inner_payload = it.next().unwrap_or(PolyValue::None);
                                let inner_cat = match inner_cat_pv {
                                    PolyValue::Int(v) => {
                                        VirtualVariableCategory::from_int(v).unwrap_or(UNKNOWN)
                                    }
                                    _ => UNKNOWN,
                                };
                                let p = match (inner_cat, inner_payload) {
                                    (REGISTER, PolyValue::Int(v)) => ParameterOIdent::Register(v),
                                    (STACK, PolyValue::Int(v)) => ParameterOIdent::Stack(v),
                                    (COMBO_REGISTER, PolyValue::Tuple(items)) => {
                                        let offs = items
                                            .into_iter()
                                            .filter_map(|x| match x {
                                                PolyValue::Int(v) => Some(v),
                                                _ => None,
                                            })
                                            .collect();
                                        ParameterOIdent::ComboRegister(offs)
                                    }
                                    _ => return OIdent::None,
                                };
                                OIdent::Parameter(p)
                            }
                            _ => OIdent::None,
                        }
                    }
                    let oident_typed = poly_to_ident(oident, cat);
                    let _ = py;
                    AilExpression {
                        header: rebuild_header(h),
                        inner: ExprInner::VirtualVariable {
                            varid,
                            category: cat,
                            oident: oident_typed,
                            reg_vvars: reg_vvars.map(|vec| {
                                vec.into_iter().map(|w| Box::new(w.into_ail())).collect()
                            }),
                        },
                    }
                }),
                Wire::UnaryOp { h, op, operand } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::UnaryOp {
                        op,
                        operand: Box::new(operand.into_ail()),
                    },
                },
                Wire::Convert {
                    h,
                    operand,
                    from_bits,
                    to_bits,
                    is_signed,
                    from_type,
                    to_type,
                    rounding_mode,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Convert {
                        operand: Box::new(operand.into_ail()),
                        from_bits,
                        to_bits,
                        is_signed,
                        from_type,
                        to_type,
                        rounding_mode,
                    },
                },
                Wire::Reinterpret {
                    h,
                    operand,
                    from_bits,
                    from_type,
                    to_bits,
                    to_type,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Reinterpret {
                        operand: Box::new(operand.into_ail()),
                        from_bits,
                        from_type,
                        to_bits,
                        to_type,
                    },
                },
                Wire::BinaryOp {
                    h,
                    op,
                    lhs,
                    rhs,
                    signed,
                    floating_point,
                    vector_count,
                    vector_size,
                    rounding_mode,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::BinaryOp {
                        op,
                        operands: [Box::new(lhs.into_ail()), Box::new(rhs.into_ail())],
                        signed,
                        floating_point,
                        rounding_mode,
                        vector_count,
                        vector_size,
                    },
                },
                Wire::Load {
                    h,
                    addr,
                    size,
                    endness,
                    guard,
                    alt,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Load {
                        addr: Box::new(addr.into_ail()),
                        size,
                        endness,
                        guard: guard.map(|g| Box::new(g.into_ail())),
                        alt: alt.map(|a| Box::new(a.into_ail())),
                    },
                },
                Wire::Call {
                    h,
                    target,
                    args,
                    arg_vvars,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Call {
                        target: match target {
                            PolyValue::Expr(wire) => CFGTarget::Expr(Box::new(wire.into_ail())),
                            PolyValue::Str(s) => CFGTarget::Symbol(s),
                            PolyValue::Int(i) => CFGTarget::Symbol(format!("{}", i)),
                            PolyValue::BigInt(s) => CFGTarget::Symbol(format!("0x{}", s)),
                            _ => CFGTarget::Symbol("<unsupported call target>".to_string()),
                        },
                        args: args.map(|v| v.into_iter().map(Wire::into_ail).collect()),
                        arg_vvars: arg_vvars.map(|v| v.into_iter().map(Wire::into_ail).collect()),
                    },
                },
                Wire::ITE {
                    h,
                    cond,
                    iffalse,
                    iftrue,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::ITE {
                        cond: Box::new(cond.into_ail()),
                        iffalse: Box::new(iffalse.into_ail()),
                        iftrue: Box::new(iftrue.into_ail()),
                    },
                },
                Wire::Extract {
                    h,
                    base,
                    offset,
                    endness,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Extract {
                        base: Box::new(base.into_ail()),
                        offset: Box::new(offset.into_ail()),
                        endness,
                    },
                },
                Wire::Insert {
                    h,
                    base,
                    offset,
                    value,
                    endness,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Insert {
                        base: Box::new(base.into_ail()),
                        offset: Box::new(offset.into_ail()),
                        value: Box::new(value.into_ail()),
                        endness,
                    },
                },
                Wire::StringLiteral { h, data } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::StringLiteral { data },
                },
                Wire::BasePointerOffset { h, base, offset } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::BasePointerOffset { base, offset },
                },
                Wire::StackBaseOffset { h, offset } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::StackBaseOffset { offset },
                },
                Wire::DirtyExpression {
                    h,
                    callee,
                    operands,
                    guard,
                    mfx,
                    maddr,
                    msize,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::DirtyExpression {
                        callee,
                        operands: operands.into_iter().map(Wire::into_ail).collect(),
                        guard: guard.map(|g| Box::new(g.into_ail())),
                        mfx,
                        maddr: maddr.map(|m| Box::new(m.into_ail())),
                        msize,
                    },
                },
                Wire::VEXCCallExpression {
                    h,
                    callee,
                    operands,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::VEXCCallExpression {
                        callee,
                        operands: operands.into_iter().map(Wire::into_ail).collect(),
                    },
                },
                Wire::MultiStatementExpression { h, stmts, expr } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::MultiStatementExpression {
                        stmts: stmts
                            .into_iter()
                            .map(crate::ailment::ail_stmt::StmtWire::into_ail)
                            .collect(),
                        expr: Box::new(expr.into_ail()),
                    },
                },
                Wire::Struct {
                    h,
                    name,
                    fields,
                    field_offsets,
                } => {
                    let fields_map: IndexMap<i64, Box<AilExpression>> = fields
                        .into_iter()
                        .map(|(off, w)| (off, Box::new(w.into_ail())))
                        .collect();
                    let mut offsets_map: IndexMap<String, i64> = IndexMap::new();
                    let mut names_map: IndexMap<i64, String> = IndexMap::new();
                    for (n, off) in field_offsets {
                        offsets_map.insert(n.clone(), off);
                        names_map.insert(off, n);
                    }
                    AilExpression {
                        header: rebuild_header(h),
                        inner: ExprInner::Struct {
                            name,
                            fields: fields_map,
                            field_offsets: offsets_map,
                            field_names: names_map,
                        },
                    }
                }
                Wire::RustEnum { h, name, fields } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::RustEnum {
                        name,
                        fields: fields.into_iter().map(|w| Box::new(w.into_ail())).collect(),
                    },
                },
                Wire::Array { h, elements } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Array {
                        elements: elements
                            .into_iter()
                            .map(|w| Box::new(w.into_ail()))
                            .collect(),
                    },
                },
                Wire::Let { h, defs, src } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Let {
                        defs: defs.into_iter().map(|w| Box::new(w.into_ail())).collect(),
                        src: Box::new(src.into_ail()),
                    },
                },
                Wire::Macro { h, name, delimiter } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::Macro { name, delimiter },
                },
                Wire::FunctionLikeMacro {
                    h,
                    name,
                    delimiter,
                    args,
                } => AilExpression {
                    header: rebuild_header(h),
                    inner: ExprInner::FunctionLikeMacro {
                        name,
                        delimiter,
                        args: args.map(|v| v.into_iter().map(|w| Box::new(w.into_ail())).collect()),
                    },
                },
            }
        }
    }
}

// Silence the unused-imports warning for PyList; will be used in the
// bulk migration's Vec<AilExpression>-shaped variants.
#[allow(dead_code)]
fn _list_placeholder(l: &Bound<'_, PyList>) {
    let _ = l;
}
