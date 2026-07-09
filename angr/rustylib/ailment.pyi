"""Type stubs for ``angr.rustylib.ailment`` -- the Rust port of the AIL
data classes.

The per-class hierarchy is collapsed into a single ``Expression``
pyclass (wrapping the inline ``AilExpression`` / ``ExprInner`` fat
enum) and a single ``Statement`` pyclass (wrapping ``AilStatement`` /
``StmtInner``). Per-variant marker classes (``Const``, ``BinaryOp``,
``Assignment``, ...) live on the Python side in
``angr.ailment.expression`` and ``angr.ailment.statement`` and dispatch
via metaclass ``__instancecheck__`` on the variant tag.

The rustlib surface is intentionally minimal:

* ``Expression`` / ``Statement`` -- the universal pyclasses
* ``Block`` -- the AIL Block container
* ``VirtualVariableCategory`` / ``ConvertType`` -- the AIL enums
* ``TagsView`` / ``TagsKeyIter`` -- the tag plumbing

Variant-specific properties (``Const.value``, ``BinaryOp.op``, ...)
are accessible on the ``Expression`` / ``Statement`` instance through
the same getter names the legacy per-class pyclasses exposed -- the
attribute is dispatched on the variant tag and raises
``AttributeError`` when called on the wrong variant.
"""

from collections.abc import Iterator
from typing import Any, ClassVar, Self

# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

class TagsView:
    def __init__(self) -> None: ...
    def __getitem__(self, key: str) -> Any: ...
    def __setitem__(self, key: str, value: Any) -> None: ...
    def __delitem__(self, key: str) -> None: ...
    def __contains__(self, key: str) -> bool: ...
    def __iter__(self) -> Iterator[str]: ...
    def __len__(self) -> int: ...
    def keys(self) -> TagsKeyIter: ...
    def values(self) -> list[Any]: ...
    def items(self) -> list[tuple[str, Any]]: ...
    def get(self, key: str, default: Any = ...) -> Any: ...
    def pop(self, key: str, default: Any = ...) -> Any: ...
    def update(self, other: Any) -> None: ...
    def clear(self) -> None: ...
    def copy(self) -> dict[str, Any]:
        """``copy()`` -- shallow clone (same idx)."""
    def __eq__(self, other: object) -> bool: ...

class TagsKeyIter:
    def __iter__(self) -> Iterator[str]: ...
    def __next__(self) -> str: ...

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VirtualVariableCategory:
    REGISTER: ClassVar[VirtualVariableCategory]
    STACK: ClassVar[VirtualVariableCategory]
    PARAMETER: ClassVar[VirtualVariableCategory]
    TMP: ClassVar[VirtualVariableCategory]
    COMBO_REGISTER: ClassVar[VirtualVariableCategory]
    UNKNOWN: ClassVar[VirtualVariableCategory]
    @staticmethod
    def from_int(value: int) -> VirtualVariableCategory | None: ...
    @property
    def value(self) -> int:
        """Const.value (literal) / Insert.value (Expression operand)."""

class ConvertType:
    TYPE_INT: ClassVar[ConvertType]
    TYPE_FP: ClassVar[ConvertType]
    @property
    def value(self) -> int:
        """Const.value (literal) / Insert.value (Expression operand)."""
    @property
    def name(self) -> str:
        """Label.name"""
    @staticmethod
    def _from_int_py(v: int) -> ConvertType: ...

class ExpressionKind:
    Const: ClassVar[ExpressionKind]
    Tmp: ClassVar[ExpressionKind]
    Register: ClassVar[ExpressionKind]
    ComboRegister: ClassVar[ExpressionKind]
    VirtualVariable: ClassVar[ExpressionKind]
    Phi: ClassVar[ExpressionKind]
    UnaryOp: ClassVar[ExpressionKind]
    BinaryOp: ClassVar[ExpressionKind]
    Convert: ClassVar[ExpressionKind]
    Reinterpret: ClassVar[ExpressionKind]
    Load: ClassVar[ExpressionKind]
    ITE: ClassVar[ExpressionKind]
    Extract: ClassVar[ExpressionKind]
    Insert: ClassVar[ExpressionKind]
    Call: ClassVar[ExpressionKind]
    DirtyExpression: ClassVar[ExpressionKind]
    VEXCCallExpression: ClassVar[ExpressionKind]
    MultiStatementExpression: ClassVar[ExpressionKind]
    StringLiteral: ClassVar[ExpressionKind]
    Struct: ClassVar[ExpressionKind]
    RustEnum: ClassVar[ExpressionKind]
    Array: ClassVar[ExpressionKind]
    Let: ClassVar[ExpressionKind]
    Macro: ClassVar[ExpressionKind]
    FunctionLikeMacro: ClassVar[ExpressionKind]
    BasePointerOffset: ClassVar[ExpressionKind]
    StackBaseOffset: ClassVar[ExpressionKind]
    @property
    def value(self) -> int:
        """Const.value (literal) / Insert.value (Expression operand)."""
    @property
    def name(self) -> str:
        """Label.name"""
    def __int__(self) -> int: ...
    def __hash__(self) -> int: ...
    @staticmethod
    def _from_int_py(v: int) -> ExpressionKind: ...

class StatementKind:
    Assignment: ClassVar[StatementKind]
    WeakAssignment: ClassVar[StatementKind]
    Label: ClassVar[StatementKind]
    Store: ClassVar[StatementKind]
    Jump: ClassVar[StatementKind]
    ConditionalJump: ClassVar[StatementKind]
    SideEffectStatement: ClassVar[StatementKind]
    Return: ClassVar[StatementKind]
    CAS: ClassVar[StatementKind]
    DirtyStatement: ClassVar[StatementKind]
    NoOp: ClassVar[StatementKind]
    @property
    def value(self) -> int:
        """Const.value (literal) / Insert.value (Expression operand)."""
    @property
    def name(self) -> str:
        """Label.name"""
    def __int__(self) -> int: ...
    def __hash__(self) -> int: ...
    @staticmethod
    def _from_int_py(v: int) -> StatementKind: ...

class RoundingMode:
    RM_NearestTiesEven: ClassVar[RoundingMode]
    RM_TowardsNegativeInf: ClassVar[RoundingMode]
    RM_TowardsPositiveInf: ClassVar[RoundingMode]
    RM_TowardsZero: ClassVar[RoundingMode]
    @property
    def value(self) -> int:
        """Const.value (literal) / Insert.value (Expression operand)."""
    @property
    def name(self) -> str:
        """Label.name"""
    def __int__(self) -> int: ...
    def __hash__(self) -> int: ...
    @staticmethod
    def _from_int_py(v: int) -> RoundingMode: ...

# ---------------------------------------------------------------------------
# Expression -- single fat-enum pyclass
# ---------------------------------------------------------------------------

class Expression:
    """Universal AIL Expression pyclass.

    Backs every per-variant Expression marker (Const, BinaryOp,
    Load, ...) via the inline ``ExprInner`` fat enum. The variant tag is
    exposed as the ``kind`` property; per-variant accessors below raise
    ``AttributeError`` when called on the wrong variant.
    """

    # Constructors are the per-variant ``_new_*`` staticmethods below; the
    # Python marker classes (``angr.ailment.expression.Const`` etc.)
    # forward their constructor arguments to them. Statically the marker
    # names alias this class, so accept anything here.
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

    # --- Header accessors (common to every variant) --------------------
    idx: int
    bits: int
    """SideEffectStatement.bits (derived from ``expr.bits``) / CAS.bits (sum of ``old_lo.bits`` + ``old_hi.bits``)."""
    depth: int
    """Assignment/WeakAssignment/Store/CJump/SES/Return/CAS/Dirty depth"""
    variable_offset: int
    @property
    def size(self) -> int:
        """Store.size"""
    @property
    def tags(self) -> TagsView: ...
    @tags.setter
    def tags(self, value: Any) -> None: ...
    @property
    def kind(self) -> ExpressionKind:
        """Variant discriminator. Python-side metaclass uses this for ``isinstance(x, Assignment)`` dispatch."""
    @property
    def kind_name(self) -> str:
        """String name of the variant, for repr/debug."""
    @property
    def pykind(self) -> int:
        """Cached ``Py<int>`` form of the kind tag. Pre-materialized at construction; access is a single ``clone_ref``."""
    def clear_hash(self) -> None: ...
    # ``variable`` / ``variable_offset`` are side-channel utility accessors
    # shared across the atom-shaped variants; kept on the base rather than
    # duplicated onto each atom.
    @property
    def variable(self) -> Any | None: ...

    # --- Variant factories ---------------------------------------------
    # One per ``ExprInner`` variant; the Python marker classes
    # (``angr.ailment.expression.Const`` etc.) forward to these.
    @staticmethod
    def _new_const(idx: int, value: Any, bits: int, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_tmp(idx: int, tmp_idx: int, bits: int, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_register(idx: int, reg_offset: int, bits: int, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_combo_register(idx: int, registers: Any, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_phi(idx: int, bits: int, src_and_vvars: Any, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_virtual_variable(
        idx: int,
        varid: int,
        bits: int,
        category: VirtualVariableCategory,
        oident: Any | None = ...,
        reg_vvars: Any | None = ...,
        **tags: Any,
    ) -> Expression: ...
    @staticmethod
    def _new_unary_op(idx: int, op: str, operand: Expression, bits: int | None = ..., **tags: Any) -> Expression: ...
    @staticmethod
    def _new_convert(
        idx: int,
        from_bits: int,
        to_bits: int,
        is_signed: bool,
        operand: Expression,
        from_type: ConvertType | None = ...,
        to_type: ConvertType | None = ...,
        rounding_mode: RoundingMode | None = ...,
        **tags: Any,
    ) -> Expression: ...
    @staticmethod
    def _new_reinterpret(
        idx: int,
        from_bits: int,
        from_type: str,
        to_bits: int,
        to_type: str,
        operand: Expression,
        **tags: Any,
    ) -> Expression: ...
    @staticmethod
    def _new_binary_op(
        idx: int,
        op: str,
        operands: Any,
        signed: bool = ...,
        *,
        bits: int | None = ...,
        floating_point: bool = ...,
        rounding_mode: RoundingMode | None = ...,
        vector_count: int | None = ...,
        vector_size: int | None = ...,
        **tags: Any,
    ) -> Expression: ...
    @staticmethod
    def _new_ite(idx: int, cond: Expression, iffalse: Expression, iftrue: Expression, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_extract(
        idx: int, bits: int, base: Expression, offset: Expression, endness: str, **tags: Any
    ) -> Expression: ...
    @staticmethod
    def _new_insert(
        idx: int, base: Expression, offset: Expression, value: Expression, endness: str, **tags: Any
    ) -> Expression: ...
    @staticmethod
    def _new_string_literal(idx: int, data: str, bits: int, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_base_pointer_offset(idx: int, bits: int, base: str, offset: Any, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_stack_base_offset(idx: int, bits: int, offset: Any, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_load(
        idx: int,
        addr: Expression,
        size: int,
        endness: str,
        guard: Expression | None = ...,
        alt: Expression | None = ...,
        **tags: Any,
    ) -> Expression: ...
    @staticmethod
    def _new_call(
        idx: int,
        target: Any,
        args: Any | None = ...,
        bits: int | None = ...,
        arg_vvars: Any | None = ...,
        **tags: Any,
    ) -> Expression: ...
    @staticmethod
    def _new_dirty_expression(
        idx: int,
        callee: str,
        operands: Any,
        guard: Expression | None = ...,
        mfx: str | None = ...,
        maddr: Expression | None = ...,
        msize: int | None = ...,
        bits: int = ...,
        **tags: Any,
    ) -> Expression: ...
    @staticmethod
    def _new_vex_ccall_expression(idx: int, callee: str, operands: Any, bits: int, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_multi_statement_expression(idx: int, stmts: Any, expr: Expression, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_struct(idx: int, name: str, fields: Any, field_offsets: Any, bits: int, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_rust_enum(idx: int, name: str, fields: Any, bits: int, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_array(idx: int, elements: Any, bits: int, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_let(idx: int, defs: Any, src: Expression, **tags: Any) -> Expression: ...
    @staticmethod
    def _new_macro(idx: int, name: str, delimiter: str = ..., **tags: Any) -> Expression: ...
    @staticmethod
    def _new_function_like_macro(
        idx: int, name: str, args: Any, bits: int | None = ..., delimiter: str = ..., **tags: Any
    ) -> Expression: ...

    # --- Equality / hash / methods -------------------------------------
    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def likes(self, other: Any) -> bool:
        """Structural-with-identity equality. See ``AilStatement::likes`` for the full contract. Backs Python ``Statement.__eq__`` after the idx-first short-circuit and is used by rewriting passes that swap a statement for an SSA-equivalent one; in particular, two statements that operate on the same source-level register through different SSA ``varid``s will *not* ``likes`` each other."""
    def matches(self, other: Any) -> bool:
        """Structural-only equality. See ``AilStatement::matches`` for the full contract. In one line: ``matches`` is ``likes`` with SSA identifying info on sub-expressions stripped, so two statements that compile from the same source but landed in different SSA numberings compare equal. Primary callers are dedup / similarity passes; not used by Python ``__eq__``."""
    def replace(self, old_expr: Any, new_expr: Any) -> tuple[bool, Expression]:
        """``replace(old, new)`` -- substitute any expression node in operand subtrees that ``__eq__``-matches ``old``."""
    def has_atom(self, atom: Any, identity: bool = True) -> bool:
        """``has_atom(atom, identity=True)`` -- recursive subtree search."""
    def copy(self) -> Self:
        """``copy()`` -- shallow clone (same idx)."""
    def deep_copy(self, manager: Any) -> Self:
        """``deep_copy(manager)`` -- recursive clone with fresh idx."""
    def __copy__(self) -> Self:
        """Python ``copy.copy`` protocol -- delegates to ``copy()``."""
    def __deepcopy__(self, memo: Any) -> Self:
        """Python ``copy.deepcopy`` protocol -- routes through ``deep_copy`` with a stand-in ``Manager`` from ``angr.ailment._deepcopy``."""
    def __reduce__(self) -> tuple[Any, ...]:
        """Python ``pickle`` protocol via ``to_bytes`` / ``from_bytes``. Same lossy-field caveat as ``Expression.__reduce__``."""
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

    # --- Serialization -------------------------------------------------
    def to_bytes(self) -> bytes: ...
    @classmethod
    def from_bytes(cls, data: bytes) -> Expression:
        """Inverse of ``to_bytes``; the pickle path (``__reduce__``) restores through this classmethod."""

# ---------------------------------------------------------------------------
# Statement -- single fat-enum pyclass
# ---------------------------------------------------------------------------

class Statement:
    """Universal AIL Statement pyclass.

    Backs every per-variant Statement marker (Assignment, Store,
    Jump, ...) via the inline ``StmtInner`` fat enum. Per-variant
    accessors raise ``AttributeError`` on the wrong variant.
    """

    # Constructors are the per-variant ``_new_*`` staticmethods below; the
    # Python marker classes (``angr.ailment.statement.Assignment`` etc.)
    # forward their constructor arguments to them. Statically the marker
    # names alias this class, so accept anything here.
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

    # --- Header accessors (common to every variant) -------------------
    idx: int
    @property
    def tags(self) -> TagsView: ...
    @tags.setter
    def tags(self, value: Any) -> None: ...
    @property
    def kind(self) -> StatementKind:
        """Variant discriminator. Python-side metaclass uses this for ``isinstance(x, Assignment)`` dispatch."""
    @property
    def kind_name(self) -> str:
        """String name of the variant, for repr/debug."""
    @property
    def pykind(self) -> int:
        """Cached ``Py<int>`` form of the kind tag. Pre-materialized at construction; access is a single ``clone_ref``."""
    @property
    def depth(self) -> int:
        """Assignment/WeakAssignment/Store/CJump/SES/Return/CAS/Dirty depth"""
    def clear_hash(self) -> None: ...
    # Utility query available on any statement (true only for Assignments
    # whose source is a ``Phi``); kept on the base.
    @property
    def is_phi_assignment(self) -> bool:
        """True iff this is an SSA phi assignment: an ``Assignment`` whose ``dst`` is a ``VirtualVariable`` and whose ``src`` is a ``Phi``.  Cheap projection for the hot ``is_phi_assignment`` helpers in ``angr.utils.ail`` / ``angr.utils.ssa``: answers the question in one FFI call without materializing ``dst`` / ``src`` wrappers (each of which deep-clones its whole subtree)."""

    # --- Variant factories ---------------------------------------------
    # One per ``StmtInner`` variant; the Python marker classes
    # (``angr.ailment.statement.Assignment`` etc.) forward to these.
    @staticmethod
    def _new_assignment(idx: int, dst: Expression, src: Expression, **tags: Any) -> Statement: ...
    @staticmethod
    def _new_weak_assignment(idx: int, dst: Expression, src: Expression, **tags: Any) -> Statement: ...
    @staticmethod
    def _new_label(idx: int, name: str, **tags: Any) -> Statement: ...
    @staticmethod
    def _new_store(
        idx: int,
        addr: Expression,
        data: Expression,
        size: int,
        endness: str,
        guard: Expression | None = ...,
        **tags: Any,
    ) -> Statement: ...
    @staticmethod
    def _new_jump(idx: int, target: Any, target_idx: int | None = ..., **tags: Any) -> Statement: ...
    @staticmethod
    def _new_conditional_jump(
        idx: int,
        condition: Expression,
        true_target: Any | None,
        false_target: Any | None,
        *,
        true_target_idx: int | None = ...,
        false_target_idx: int | None = ...,
        **tags: Any,
    ) -> Statement: ...
    @staticmethod
    def _new_side_effect_statement(
        idx: int,
        expr: Expression,
        ret_expr: Expression | None = ...,
        fp_ret_expr: Expression | None = ...,
        **tags: Any,
    ) -> Statement: ...
    @staticmethod
    def _new_return(idx: int, ret_exprs: Any, **tags: Any) -> Statement: ...
    @staticmethod
    def _new_cas(
        idx: int,
        addr: Expression,
        data_lo: Expression,
        data_hi: Expression | None,
        expd_lo: Expression,
        expd_hi: Expression | None,
        old_lo: Expression,
        old_hi: Expression | None,
        endness: str,
        **tags: Any,
    ) -> Statement: ...
    @staticmethod
    def _new_dirty_statement(idx: int, dirty: Expression, **tags: Any) -> Statement: ...
    @staticmethod
    def _new_no_op(idx: int, **tags: Any) -> Statement: ...

    # --- Equality / hash / methods -------------------------------------
    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def likes(self, other: Any) -> bool:
        """Structural-with-identity equality. See ``AilStatement::likes`` for the full contract. Backs Python ``Statement.__eq__`` after the idx-first short-circuit and is used by rewriting passes that swap a statement for an SSA-equivalent one; in particular, two statements that operate on the same source-level register through different SSA ``varid``s will *not* ``likes`` each other."""
    def matches(self, other: Any) -> bool:
        """Structural-only equality. See ``AilStatement::matches`` for the full contract. In one line: ``matches`` is ``likes`` with SSA identifying info on sub-expressions stripped, so two statements that compile from the same source but landed in different SSA numberings compare equal. Primary callers are dedup / similarity passes; not used by Python ``__eq__``."""
    def replace(self, old_expr: Any, new_expr: Any) -> tuple[bool, Statement]:
        """``replace(old, new)`` -- substitute any expression node in operand subtrees that ``__eq__``-matches ``old``."""
    def has_atom(self, atom: Any, identity: bool = True) -> bool:
        """``has_atom(atom, identity=True)`` -- recursive subtree search."""
    def copy(self) -> Self:
        """``copy()`` -- shallow clone (same idx)."""
    def deep_copy(self, manager: Any) -> Self:
        """``deep_copy(manager)`` -- recursive clone with fresh idx."""
    def __copy__(self) -> Self:
        """Python ``copy.copy`` protocol -- delegates to ``copy()``."""
    def __deepcopy__(self, memo: Any) -> Self:
        """Python ``copy.deepcopy`` protocol -- routes through ``deep_copy`` with a stand-in ``Manager`` from ``angr.ailment._deepcopy``."""
    def __reduce__(self) -> tuple[Any, ...]:
        """Python ``pickle`` protocol via ``to_bytes`` / ``from_bytes``. Same lossy-field caveat as ``Expression.__reduce__``."""
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

    # --- Serialization -------------------------------------------------
    def to_bytes(self) -> bytes: ...
    @classmethod
    def from_bytes(cls, data: bytes) -> Statement:
        """Inverse of ``to_bytes``; the pickle path (``__reduce__``) restores through this classmethod."""

# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------

class Block:
    addr: int
    """Store.addr / CAS.addr"""
    original_size: int | None
    idx: int | None
    statements: list[Statement]
    def __init__(
        self,
        addr: int,
        original_size: int | None = ...,
        *,
        statements: list[Statement] | None = ...,
        idx: int | None = ...,
    ) -> None: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __copy__(self) -> Self:
        """Python ``copy.copy`` protocol -- delegates to ``copy()``."""
    def __deepcopy__(self, memo: Any) -> Self:
        """Python ``copy.deepcopy`` protocol -- routes through ``deep_copy`` with a stand-in ``Manager`` from ``angr.ailment._deepcopy``."""
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...
    def copy(self, statements: list[Statement] | None = ...) -> Self:
        """``copy()`` -- shallow clone (same idx)."""
    def dbg_repr(self, indent: int = ...) -> str: ...

# ---------------------------------------------------------------------------
# Expression variant marker classes
# ---------------------------------------------------------------------------
#
# At runtime these are ``angr.ailment.expression`` marker classes whose
# ``isinstance`` dispatches on the variant tag; every instance is really an
# ``Expression``. For the type checker each variant subclasses ``Expression``
# (directly, or via the ``Atom`` / ``Op`` union markers) so that ``isinstance``
# narrows and constructors carry the right signature. All variant accessors are
# inherited from ``Expression`` -- only the constructor and any class-level
# marker attributes are declared here.

class Atom(Expression):
    """isinstance-only union marker for atom-shaped expressions."""

class Op(Expression):
    """isinstance-only union marker for op-shaped expressions."""

    @property
    def op(self) -> str:
        """UnaryOp.op / BinaryOp.op / Call.op (== "call") / DirtyExpression.op / VEXCCallExpression.op (== callee) / Let.op (== "let") / Macro.op + FunctionLikeMacro.op (== "call")"""
    @property
    def verbose_op(self) -> str:
        """``verbose_op`` -- defaults to ``op`` for the regular operator variants (UnaryOp / BinaryOp / Convert / Reinterpret) so callers that look up an op-handler via ``mapping[expr.verbose_op]`` find a match regardless of variant. The legacy per-class pyclasses exposed it on every op-shaped expression with the same content as ``op``."""

# --- Atom subclasses -------------------------------------------------------

class Const(Atom):
    value: Any
    """Const.value (literal) / Insert.value (Expression operand)."""
    @property
    def value_int(self) -> int:
        """``Const.value_int`` -- the int value (errors on float constants)."""
    @property
    def value_float(self) -> float:
        """``Const.value_float`` -- the float value (errors on int constants)."""
    @property
    def is_int(self) -> bool:
        """``Const.is_int`` (only int constants -- not floats)."""
    @property
    def sign_bit(self) -> int:
        """``Const.sign_bit`` -- the top bit of the int value at the Const's declared width. Computed as a bit-extract (not an arithmetic shift) so values stored as their u64 two's-complement form -- e.g. ``-8`` carried as ``2^64 - 8`` from the lifter -- correctly report ``1``."""
    def __init__(self, idx: int | None, value: int, bits: int, **tags: Any) -> None: ...

class Tmp(Atom):
    @property
    def tmp_idx(self) -> int:
        """Tmp.tmp_idx (i64) / VirtualVariable.tmp_idx (Option<i64>, present when category is TMP)."""
    def __init__(self, idx: int | None, tmp_idx: int, bits: int, **tags: Any) -> None: ...

class Register(Atom):
    @property
    def reg_offset(self) -> int:
        """Register.reg_offset / VirtualVariable.reg_offset (when category is REGISTER, or parameter with REGISTER inner category)."""
    def __init__(self, idx: int | None, reg_offset: int, bits: int, **tags: Any) -> None: ...

class ComboRegister(Atom):
    registers: list[Expression]
    """ComboRegister.registers -- list of Register Expression instances."""
    def __init__(self, idx: int | None, registers: list[Expression], **tags: Any) -> None: ...

class VirtualVariable(Atom):
    @property
    def varid(self) -> int:
        """VirtualVariable.varid"""
    @property
    def category(self) -> VirtualVariableCategory:
        """VirtualVariable.category"""
    @property
    def oident(self) -> Any:
        """VirtualVariable.oident"""
    @property
    def reg_vvars(self) -> dict[int, Expression]:
        """VirtualVariable.reg_vvars  Returns ``None`` for non-COMBO_REGISTER vvars, an empty list for COMBO_REGISTER vvars whose sub-registers haven't been populated yet, and a list of ``VirtualVariable`` Expression wrappers otherwise. Each call mints fresh wrappers around clones of the inner ``AilExpression`` nodes (same pattern as ``.operands``)."""
    @property
    def was_reg(self) -> bool:
        """VirtualVariable.was_reg"""
    @property
    def was_stack(self) -> bool:
        """VirtualVariable.was_stack"""
    @property
    def was_parameter(self) -> bool:
        """VirtualVariable.was_parameter"""
    @property
    def was_tmp(self) -> bool:
        """VirtualVariable.was_tmp"""
    @property
    def was_combo_reg(self) -> bool:
        """VirtualVariable.was_combo_reg"""
    @property
    def reg_offset(self) -> int:
        """Register.reg_offset / VirtualVariable.reg_offset (when category is REGISTER, or parameter with REGISTER inner category)."""
    @property
    def reg_offsets(self) -> tuple[int, ...]:
        """VirtualVariable.reg_offsets (combo register)"""
    @property
    def stack_offset(self) -> int:
        """VirtualVariable.stack_offset"""
    # ``int`` on TMP-category vvars; None otherwise (at runtime).
    @property
    def tmp_idx(self) -> int:
        """Tmp.tmp_idx (i64) / VirtualVariable.tmp_idx (Option<i64>, present when category is TMP)."""
    @property
    def parameter_category(self) -> VirtualVariableCategory | None:
        """VirtualVariable.parameter_category"""
    @property
    def parameter_reg_offset(self) -> int | None:
        """VirtualVariable.parameter_reg_offset"""
    @property
    def parameter_stack_offset(self) -> int | None:
        """VirtualVariable.parameter_stack_offset"""
    def __init__(
        self,
        idx: int | None,
        varid: int,
        bits: int,
        category: VirtualVariableCategory,
        oident: Any | None = ...,
        reg_vvars: dict[int, Expression] | None = ...,
        **tags: Any,
    ) -> None: ...

class Phi(Atom):
    src_and_vvars: Any
    """Phi.src_and_vvars  Returns a Python list of ``((src_addr, src_idx), vvar)`` tuples. The ``vvar`` slot is a ``VirtualVariable`` Expression (or ``None``)."""
    @property
    def op(self) -> str:
        """UnaryOp.op / BinaryOp.op / Call.op (== "call") / DirtyExpression.op / VEXCCallExpression.op (== callee) / Let.op (== "let") / Macro.op + FunctionLikeMacro.op (== "call")"""
    @property
    def verbose_op(self) -> str:
        """``verbose_op`` -- defaults to ``op`` for the regular operator variants (UnaryOp / BinaryOp / Convert / Reinterpret) so callers that look up an op-handler via ``mapping[expr.verbose_op]`` find a match regardless of variant. The legacy per-class pyclasses exposed it on every op-shaped expression with the same content as ``op``."""
    def __init__(self, idx: int | None, bits: int, src_and_vvars: Any, **tags: Any) -> None: ...

# --- Op subclasses ---------------------------------------------------------

class UnaryOp(Op):
    operand: Expression
    """UnaryOp.operand / Convert.operand / Reinterpret.operand"""
    operands: Any
    """DirtyExpression.operands / VEXCCallExpression.operands / BinaryOp.operands / UnaryOp.operands (single-element list, legacy quirk) / Convert.operands / Reinterpret.operands (same single-element wrap for legacy compat). DirtyExpression returns a list; VEXCCall returns a tuple; BinaryOp returns a 2-tuple; the single-operand variants return a 1-element list mirroring the legacy per-class pyclass contract."""
    def __init__(self, idx: int | None, op: str, operand: Expression, bits: int | None = ..., **tags: Any) -> None: ...

class BinaryOp(Op):
    COMPARISON_NEGATION: ClassVar[dict[str, str]]
    operands: Any
    """DirtyExpression.operands / VEXCCallExpression.operands / BinaryOp.operands / UnaryOp.operands (single-element list, legacy quirk) / Convert.operands / Reinterpret.operands (same single-element wrap for legacy compat). DirtyExpression returns a list; VEXCCall returns a tuple; BinaryOp returns a 2-tuple; the single-operand variants return a 1-element list mirroring the legacy per-class pyclass contract."""
    @property
    def signed(self) -> bool:
        """BinaryOp.signed"""
    @property
    def floating_point(self) -> bool:
        """BinaryOp.floating_point"""
    @property
    def rounding_mode(self) -> Any | None:
        """Convert.rounding_mode / BinaryOp.rounding_mode"""
    @property
    def vector_count(self) -> int | None:
        """BinaryOp.vector_count"""
    @property
    def vector_size(self) -> int | None:
        """BinaryOp.vector_size"""
    def __init__(
        self,
        idx: int | None,
        op: str,
        operands: Any,
        signed: bool = ...,
        *,
        bits: int | None = ...,
        floating_point: bool = ...,
        rounding_mode: RoundingMode | None = ...,
        vector_count: int | None = ...,
        vector_size: int | None = ...,
        **tags: Any,
    ) -> None: ...

class Convert(Op):
    TYPE_INT: ClassVar[ConvertType]
    TYPE_FP: ClassVar[ConvertType]
    operand: Expression
    """UnaryOp.operand / Convert.operand / Reinterpret.operand"""
    operands: Any
    """DirtyExpression.operands / VEXCCallExpression.operands / BinaryOp.operands / UnaryOp.operands (single-element list, legacy quirk) / Convert.operands / Reinterpret.operands (same single-element wrap for legacy compat). DirtyExpression returns a list; VEXCCall returns a tuple; BinaryOp returns a 2-tuple; the single-operand variants return a 1-element list mirroring the legacy per-class pyclass contract."""
    @property
    def from_bits(self) -> int:
        """Convert.from_bits / Reinterpret.from_bits"""
    @property
    def to_bits(self) -> int:
        """Convert.to_bits / Reinterpret.to_bits"""
    @property
    def is_signed(self) -> bool:
        """Convert.is_signed"""
    @property
    def from_type(self) -> Any:
        """Convert.from_type / Reinterpret.from_type (different types -- Reinterpret is a String)"""
    @property
    def to_type(self) -> Any:
        """Convert.to_type / Reinterpret.to_type"""
    @property
    def rounding_mode(self) -> Any | None:
        """Convert.rounding_mode / BinaryOp.rounding_mode"""
    def __init__(
        self,
        idx: int | None,
        from_bits: int,
        to_bits: int,
        is_signed: bool,
        operand: Expression,
        from_type: ConvertType | None = ...,
        to_type: ConvertType | None = ...,
        rounding_mode: RoundingMode | None = ...,
        **tags: Any,
    ) -> None: ...

class Reinterpret(Op):
    operand: Expression
    """UnaryOp.operand / Convert.operand / Reinterpret.operand"""
    operands: Any
    """DirtyExpression.operands / VEXCCallExpression.operands / BinaryOp.operands / UnaryOp.operands (single-element list, legacy quirk) / Convert.operands / Reinterpret.operands (same single-element wrap for legacy compat). DirtyExpression returns a list; VEXCCall returns a tuple; BinaryOp returns a 2-tuple; the single-operand variants return a 1-element list mirroring the legacy per-class pyclass contract."""
    @property
    def from_bits(self) -> int:
        """Convert.from_bits / Reinterpret.from_bits"""
    @property
    def to_bits(self) -> int:
        """Convert.to_bits / Reinterpret.to_bits"""
    @property
    def from_type(self) -> Any:
        """Convert.from_type / Reinterpret.from_type (different types -- Reinterpret is a String)"""
    @property
    def to_type(self) -> Any:
        """Convert.to_type / Reinterpret.to_type"""
    def __init__(
        self,
        idx: int | None,
        from_bits: int,
        from_type: str,
        to_bits: int,
        to_type: str,
        operand: Expression,
        **tags: Any,
    ) -> None: ...

class Let(Op):
    @property
    def defs(self) -> list[Any]:
        """Let.defs  Returns a fresh ``list[Statement]`` built from the inner ``Vec<Arc<AilStatement>>`` -- each call mints new ``Py<Statement>`` wrappers around clones of the inner statements, matching the wrapper-minting semantics of ``.operands`` / ``Array.elements``."""
    @property
    def src(self) -> Expression:
        """Assignment.src / WeakAssignment.src"""
    def __init__(self, idx: int | None, defs: Any, src: Expression, **tags: Any) -> None: ...

# --- Expression subclasses -------------------------------------------------

class Array(Expression):
    elements: Any
    """Array.elements  Returns a fresh ``list[Expression]`` built from the inner ``Vec<Arc<AilExpression>>`` -- each call mints new ``Py<Expression>`` wrappers, matching the wrapper-minting semantics of ``.operands``."""
    @property
    def length(self) -> int:
        """Array.length"""
    def __init__(self, idx: int | None, elements: Any, bits: int, **tags: Any) -> None: ...

class BasePointerOffset(Expression):
    base: Any
    """Extract.base (Expression) / Insert.base (Expression) / BasePointerOffset.base (str) / StackBaseOffset.base (== ``"stack_base"``, the legacy contract)."""
    offset: Any
    """Extract.offset (Expression) / Insert.offset (Expression) / BasePointerOffset.offset (int) / StackBaseOffset.offset (int)."""
    def __init__(self, idx: int | None, bits: int, base: str, offset: Any, **tags: Any) -> None: ...

class StackBaseOffset(Expression):
    base: Any
    """Extract.base (Expression) / Insert.base (Expression) / BasePointerOffset.base (str) / StackBaseOffset.base (== ``"stack_base"``, the legacy contract)."""
    offset: Any
    """Extract.offset (Expression) / Insert.offset (Expression) / BasePointerOffset.offset (int) / StackBaseOffset.offset (int)."""
    def __init__(self, idx: int | None, bits: int, offset: Any, **tags: Any) -> None: ...

class Call(Expression):
    """Call expression. Represents a function call that produces a value.

    When used as a standalone statement (not part of an assignment), wrap it in a SideEffectStatement.
    """

    target: Any
    """Jump.target / ConditionalJump callers reach for true_target/false_target (distinct getters below)"""
    args: Any
    """FunctionLikeMacro.args"""
    arg_vvars: Any
    """Call.arg_vvars / Macro.arg_vvars (always None) -- tuple of VirtualVariable Expression instances"""
    @property
    def op(self) -> str:
        """UnaryOp.op / BinaryOp.op / Call.op (== "call") / DirtyExpression.op / VEXCCallExpression.op (== callee) / Let.op (== "let") / Macro.op + FunctionLikeMacro.op (== "call")"""
    @property
    def verbose_op(self) -> str:
        """``verbose_op`` -- defaults to ``op`` for the regular operator variants (UnaryOp / BinaryOp / Convert / Reinterpret) so callers that look up an op-handler via ``mapping[expr.verbose_op]`` find a match regardless of variant. The legacy per-class pyclasses exposed it on every op-shaped expression with the same content as ``op``."""
    def __init__(
        self,
        idx: int | None,
        target: Any,
        args: Any | None = ...,
        bits: int | None = ...,
        arg_vvars: Any | None = ...,
        **tags: Any,
    ) -> None: ...

class DirtyExpression(Expression):
    callee: str
    """DirtyExpression.callee / VEXCCallExpression.callee"""
    operands: Any
    """DirtyExpression.operands / VEXCCallExpression.operands / BinaryOp.operands / UnaryOp.operands (single-element list, legacy quirk) / Convert.operands / Reinterpret.operands (same single-element wrap for legacy compat). DirtyExpression returns a list; VEXCCall returns a tuple; BinaryOp returns a 2-tuple; the single-operand variants return a 1-element list mirroring the legacy per-class pyclass contract."""
    guard: Expression | None
    """Store.guard"""
    @property
    def op(self) -> str:
        """UnaryOp.op / BinaryOp.op / Call.op (== "call") / DirtyExpression.op / VEXCCallExpression.op (== callee) / Let.op (== "let") / Macro.op + FunctionLikeMacro.op (== "call")"""
    @property
    def verbose_op(self) -> str:
        """``verbose_op`` -- defaults to ``op`` for the regular operator variants (UnaryOp / BinaryOp / Convert / Reinterpret) so callers that look up an op-handler via ``mapping[expr.verbose_op]`` find a match regardless of variant. The legacy per-class pyclasses exposed it on every op-shaped expression with the same content as ``op``."""
    @property
    def mfx(self) -> str | None:
        """DirtyExpression.mfx"""
    @property
    def maddr(self) -> Expression | None:
        """DirtyExpression.maddr"""
    @property
    def msize(self) -> int | None:
        """DirtyExpression.msize"""
    def __init__(
        self,
        idx: int | None,
        callee: str,
        operands: Any,
        *,
        guard: Expression | None = ...,
        mfx: str | None = ...,
        maddr: Expression | None = ...,
        msize: int | None = ...,
        bits: int,
        **tags: Any,
    ) -> None: ...

class Extract(Expression):
    base: Any
    """Extract.base (Expression) / Insert.base (Expression) / BasePointerOffset.base (str) / StackBaseOffset.base (== ``"stack_base"``, the legacy contract)."""
    offset: Any
    """Extract.offset (Expression) / Insert.offset (Expression) / BasePointerOffset.offset (int) / StackBaseOffset.offset (int)."""
    @property
    def endness(self) -> str:
        """Store.endness / CAS.endness"""
    def __init__(
        self, idx: int | None, bits: int, base: Expression, offset: Expression, endness: str, **tags: Any
    ) -> None: ...

class FunctionLikeMacro(Expression):
    args: Any
    """FunctionLikeMacro.args"""
    @property
    def name(self) -> str:
        """Label.name"""
    @property
    def delimiter(self) -> str:
        """Macro.delimiter / FunctionLikeMacro.delimiter"""
    @property
    def op(self) -> str:
        """UnaryOp.op / BinaryOp.op / Call.op (== "call") / DirtyExpression.op / VEXCCallExpression.op (== callee) / Let.op (== "let") / Macro.op + FunctionLikeMacro.op (== "call")"""
    @property
    def verbose_op(self) -> str:
        """``verbose_op`` -- defaults to ``op`` for the regular operator variants (UnaryOp / BinaryOp / Convert / Reinterpret) so callers that look up an op-handler via ``mapping[expr.verbose_op]`` find a match regardless of variant. The legacy per-class pyclasses exposed it on every op-shaped expression with the same content as ``op``."""
    def __init__(
        self,
        idx: int | None,
        name: str,
        args: Any,
        bits: int | None = ...,
        delimiter: str = ...,
        **tags: Any,
    ) -> None: ...

class ITE(Expression):
    cond: Expression
    """ITE.cond"""
    iftrue: Expression
    """ITE.iftrue"""
    iffalse: Expression
    """ITE.iffalse"""
    def __init__(
        self, idx: int | None, cond: Expression, iffalse: Expression, iftrue: Expression, **tags: Any
    ) -> None: ...

class Insert(Expression):
    base: Any
    """Extract.base (Expression) / Insert.base (Expression) / BasePointerOffset.base (str) / StackBaseOffset.base (== ``"stack_base"``, the legacy contract)."""
    offset: Any
    """Extract.offset (Expression) / Insert.offset (Expression) / BasePointerOffset.offset (int) / StackBaseOffset.offset (int)."""
    value: Any
    """Const.value (literal) / Insert.value (Expression operand)."""
    @property
    def endness(self) -> str:
        """Store.endness / CAS.endness"""
    def __init__(
        self, idx: int | None, base: Expression, offset: Expression, value: Expression, endness: str, **tags: Any
    ) -> None: ...

class Load(Expression):
    addr: Expression
    """Store.addr / CAS.addr"""
    guard: Expression | None
    """Store.guard"""
    @property
    def endness(self) -> str:
        """Store.endness / CAS.endness"""
    @property
    def alt(self) -> Expression | None:
        """Load.alt"""
    def __init__(
        self,
        idx: int | None,
        addr: Expression,
        size: int,
        endness: str,
        *,
        guard: Expression | None = ...,
        alt: Expression | None = ...,
        **tags: Any,
    ) -> None: ...

class Macro(Expression):
    @property
    def name(self) -> str:
        """Label.name"""
    @property
    def delimiter(self) -> str:
        """Macro.delimiter / FunctionLikeMacro.delimiter"""
    def __init__(self, idx: int | None, name: str, delimiter: str = ..., **tags: Any) -> None: ...

class MultiStatementExpression(Expression):
    """For representing comma-separated statements and expression in C."""

    stmts: Any
    """MultiStatementExpression.stmts -- materializes a fresh ``list[Statement]`` on each read; setter accepts any iterable of ``Statement`` instances."""
    expr: Expression
    """SideEffectStatement.expr"""
    def __init__(self, idx: int | None, stmts: Any, expr: Expression, **tags: Any) -> None: ...

class RustEnum(Expression):
    fields: Any
    """Struct.fields (dict) / RustEnum.fields (list)"""
    @property
    def name(self) -> str:
        """Label.name"""
    def __init__(self, idx: int | None, name: str, fields: Any, bits: int, **tags: Any) -> None: ...

class StringLiteral(Expression):
    @property
    def data(self) -> Any:
        """Store.data"""
    def __init__(self, idx: int | None, data: str, bits: int, **tags: Any) -> None: ...

class Struct(Expression):
    fields: Any
    """Struct.fields (dict) / RustEnum.fields (list)"""
    @property
    def name(self) -> str:
        """Label.name"""
    @property
    def field_offsets(self) -> dict[str, int]:
        """Struct.field_offsets"""
    @property
    def field_names(self) -> dict[int, str]:
        """Struct.field_names"""
    def get_field(self, name: str) -> Any | None:
        """Struct.get_field(name) -- dotted-path lookup through nested Structs"""
    def __init__(self, idx: int | None, name: str, fields: Any, field_offsets: Any, bits: int, **tags: Any) -> None: ...

class VEXCCallExpression(Expression):
    callee: str
    """DirtyExpression.callee / VEXCCallExpression.callee"""
    operands: Any
    """DirtyExpression.operands / VEXCCallExpression.operands / BinaryOp.operands / UnaryOp.operands (single-element list, legacy quirk) / Convert.operands / Reinterpret.operands (same single-element wrap for legacy compat). DirtyExpression returns a list; VEXCCall returns a tuple; BinaryOp returns a 2-tuple; the single-operand variants return a 1-element list mirroring the legacy per-class pyclass contract."""
    @property
    def op(self) -> str:
        """UnaryOp.op / BinaryOp.op / Call.op (== "call") / DirtyExpression.op / VEXCCallExpression.op (== callee) / Let.op (== "let") / Macro.op + FunctionLikeMacro.op (== "call")"""
    @property
    def verbose_op(self) -> str:
        """``verbose_op`` -- defaults to ``op`` for the regular operator variants (UnaryOp / BinaryOp / Convert / Reinterpret) so callers that look up an op-handler via ``mapping[expr.verbose_op]`` find a match regardless of variant. The legacy per-class pyclasses exposed it on every op-shaped expression with the same content as ``op``."""
    def __init__(self, idx: int | None, callee: str, operands: Any, bits: int, **tags: Any) -> None: ...

# ---------------------------------------------------------------------------
# Statement variant marker classes
# ---------------------------------------------------------------------------
#
# As with the expression variants above: runtime marker classes that all wrap a
# single ``Statement`` pyclass; statically each subclasses ``Statement`` so
# ``isinstance`` narrows and constructors carry the right signature. All variant
# accessors are inherited from ``Statement``.

class Assignment(Statement):
    """Assignment statement: expr_a = expr_b"""

    dst: Expression
    """Assignment.dst / WeakAssignment.dst (operand subtree)"""
    src: Expression
    """Assignment.src / WeakAssignment.src"""
    def __init__(self, idx: int | None, dst: Expression, src: Expression, **tags: Any) -> None: ...

class WeakAssignment(Statement):
    """An assignment statement that does not create a new variable at its destination; It should be seen as
    operator=(&dst, &src) in C++-like syntax.
    """

    dst: Expression
    """Assignment.dst / WeakAssignment.dst (operand subtree)"""
    src: Expression
    """Assignment.src / WeakAssignment.src"""
    def __init__(self, idx: int | None, dst: Expression, src: Expression, **tags: Any) -> None: ...

class Label(Statement):
    """A dummy statement that indicates a label with a name."""
    @property
    def name(self) -> str:
        """Label.name"""
    def __init__(self, idx: int | None, name: str, **tags: Any) -> None: ...

class Store(Statement):
    """Store statement: ``*addr = data``"""
    @property
    def addr(self) -> Expression:
        """Store.addr / CAS.addr"""
    @property
    def data(self) -> Expression:
        """Store.data"""
    @property
    def size(self) -> int:
        """Store.size"""
    @property
    def endness(self) -> str:
        """Store.endness / CAS.endness"""
    @property
    def guard(self) -> Expression | None:
        """Store.guard"""
    def __init__(
        self,
        idx: int | None,
        addr: Expression,
        data: Expression,
        size: int,
        endness: str,
        guard: Expression | None = ...,
        **tags: Any,
    ) -> None: ...

class Jump(Statement):
    """Jump statement: goto target"""

    target: Any
    """Jump.target / ConditionalJump callers reach for true_target/false_target (distinct getters below)"""
    target_idx: int | None
    """Jump.target_idx"""
    def __init__(self, idx: int | None, target: Any, target_idx: int | None = ..., **tags: Any) -> None: ...

class ConditionalJump(Statement):
    """if (cond) {true_target} else {false_target}"""

    condition: Expression
    """ConditionalJump.condition"""
    true_target: Any
    """ConditionalJump.true_target"""
    false_target: Any
    """ConditionalJump.false_target"""
    true_target_idx: int | None
    """ConditionalJump.true_target_idx"""
    false_target_idx: int | None
    """ConditionalJump.false_target_idx"""
    def __init__(
        self,
        idx: int | None,
        condition: Expression,
        true_target: Any,
        false_target: Any,
        *,
        true_target_idx: int | None = ...,
        false_target_idx: int | None = ...,
        **tags: Any,
    ) -> None: ...

class SideEffectStatement(Statement):
    """A statement wrapping an expression that has side effects (e.g., a function call).

    When wrapping a Call expression, ret_expr and fp_ret_expr hold the return value destinations.
    """

    expr: Expression
    """SideEffectStatement.expr"""
    @property
    def size(self) -> int:
        """Store.size"""
    @property
    def ret_expr(self) -> Expression | None:
        """SideEffectStatement.ret_expr"""
    @property
    def fp_ret_expr(self) -> Expression | None:
        """SideEffectStatement.fp_ret_expr"""
    def __init__(
        self,
        idx: int | None,
        expr: Expression,
        ret_expr: Expression | None = ...,
        fp_ret_expr: Expression | None = ...,
        **tags: Any,
    ) -> None: ...

class Return(Statement):
    """Return statement: (return expr_a), (return)"""

    ret_exprs: Any
    """Return.ret_exprs"""
    def __init__(self, idx: int | None, ret_exprs: Any, **tags: Any) -> None: ...

class CAS(Statement):
    """Atomic compare-and-swap.

    ``*_lo`` and ``*_hi`` are used to represent the low and high parts of a 128-bit CAS operation; ``*_hi`` is None if
    the CAS operation works on values that are less than or equal to 64 bits.

    addr: The address to be compared and swapped.
    data: The value to be written if the comparison is successful.
    expd: The expected value to be compared against.
    old: The value that is currently stored at addr before compare-and-swap; it will be returned after compare-and-swap.
    """
    @property
    def addr(self) -> Expression:
        """Store.addr / CAS.addr"""
    @property
    def endness(self) -> str:
        """Store.endness / CAS.endness"""
    @property
    def size(self) -> int:
        """Store.size"""
    @property
    def data_lo(self) -> Expression:
        """CAS.data_lo / data_hi / expd_lo / expd_hi / old_lo / old_hi"""
    @property
    def data_hi(self) -> Expression | None: ...
    @property
    def expd_lo(self) -> Expression: ...
    @property
    def expd_hi(self) -> Expression | None: ...
    @property
    def old_lo(self) -> Expression: ...
    @property
    def old_hi(self) -> Expression | None: ...
    def __init__(
        self,
        idx: int | None,
        addr: Expression,
        data_lo: Expression,
        data_hi: Expression | None,
        expd_lo: Expression,
        expd_hi: Expression | None,
        old_lo: Expression,
        old_hi: Expression | None,
        endness: str,
        **tags: Any,
    ) -> None: ...

class DirtyStatement(Statement):
    """Wrapper around the original statement, which is usually not convertible (temporarily)."""
    @property
    def dirty(self) -> Expression:
        """DirtyStatement.dirty"""
    def __init__(self, idx: int | None, dirty: Expression, **tags: Any) -> None: ...

class NoOp(Statement):
    """A statement that does nothing. It defines and uses no atoms. It is primarily used as an in-place placeholder for a
    removed statement so that the indices of the surrounding statements (and code locations referencing them) remain
    stable until the block is compacted.
    """
    def __init__(self, idx: int | None, **tags: Any) -> None: ...
