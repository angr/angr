"""
Protobuf serialization for the Go AST defined in :mod:`go`.

Same flat indexed node table as :mod:`c_serialize`, and the same ``Codegen`` envelope: ``Codegen.flavor`` says which
class family a node table belongs to, and every node kind shared with C names both a C class and its Go counterpart.
Where a Go node's payload matches its C counterpart's, the C serializer writes it.
"""
# pylint:disable=no-member,protected-access,import-error,no-name-in-module

from __future__ import annotations

import inspect
import json
import zlib
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from angr.analyses.decompiler.variable_map import VariableMap
from angr.enums import Flavors
from angr.errors import AngrMissingTypeError
from angr.go.sim_type import GoSimTypeInterface
from angr.protos import codegen_pb2  # pyright: ignore[reportAttributeAccessIssue]
from angr.rustylib.ailment import Block as AilBlock
from angr.rustylib.ailment import Expression as AilExpression
from angr.rustylib.ailment import Statement as AilStatement
from angr.sim_type import (
    SimStruct,
    SimType,
    SimTypeArray,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypePointer,
    SimTypeRef,
    SimUnion,
)
from angr.utils.types import unpack_typeref

from . import c_serialize
from .base import FunctionRef
from .c_serialize import (
    _UINT64_RANGE,
    ParseContext,
    SerializeContext,
    _parse_const_formats,
    _parse_instruction_mapping,
    _parse_notes,
    _parse_position_mappings,
    _read_constant,
    _ser_cailblock,
    _ser_cbreak,
    _ser_ccontinue,
    _ser_cdirtystmt,
    _ser_cdowhile,
    _ser_cfakevar,
    _ser_cfor,
    _ser_cgoto,
    _ser_cidxvar,
    _ser_cifbreak,
    _ser_cifelse,
    _ser_cincomplete_switch,
    _ser_cite,
    _ser_clabel,
    _ser_cmulti,
    _ser_cstatements,
    _ser_cstructfield,
    _ser_ctypecast,
    _ser_cunop,
    _ser_cunsupported,
    _ser_cvar,
    _ser_cvex,
    _ser_cwhile,
    _serializable_addr,
    _serialize_const_formats,
    _serialize_instruction_mapping,
    _serialize_notes,
    _serialize_position_mappings,
    _simvar_to_bytes,
    _write_constant,
)
from .go import (
    INDENT_DELTA,
    GoAILBlock,
    GoAssignment,
    GoBinaryOp,
    GoBoxedValue,
    GoBreak,
    GoConstant,
    GoContinue,
    GoDirtyExpression,
    GoDirtyStatement,
    GoDoWhileLoop,
    GoExpression,
    GoExpressionStatement,
    GoFakeVariable,
    GoForLoop,
    GoFunction,
    GoFunctionCall,
    GoGoto,
    GoIfBreak,
    GoIfElse,
    GoIncompleteSwitchCase,
    GoIndexedVariable,
    GoITE,
    GoLabel,
    GoMethodCall,
    GoMultiAssignment,
    GoMultiStatementExpression,
    GoRangeLoop,
    GoRegister,
    GoReturn,
    GoSelect,
    GoSelectCase,
    GoSliceLiteral,
    GoStatements,
    GoStringLiteral,
    GoStructField,
    GoStructLiteral,
    GoStructuredCodeGenerator,
    GoSwitchCase,
    GoTypeAssertion,
    GoTypeCast,
    GoTypeSwitch,
    GoUnaryOp,
    GoUnsupportedStatement,
    GoVariable,
    GoVariableField,
    GoVEXCCallExpression,
    GoWhileLoop,
    _is_descriptor_named_struct,
    cextern_sort_key,
)

# ---------------------------------------------------------------------------------------------------------------------
# Dispatch tables
# ---------------------------------------------------------------------------------------------------------------------

# kind -> class and kind -> parser, for the Go family. The class -> kind and class -> serializer directions live in
# the shared tables in c_serialize (class keys are unique across families).
_CLASS_BY_KIND: dict[int, type] = {}
_PARSERS: dict[int, Callable[[codegen_pb2.CConstructNode, Any], Any]] = {}


def _register(cls: type, kind: int, serializer: Callable, parser: Callable) -> None:
    c_serialize._SERIALIZE_KIND_BY_CLASS[cls] = kind
    c_serialize._SERIALIZERS[cls] = serializer
    _CLASS_BY_KIND[kind] = cls
    _PARSERS[kind] = parser


# ---------------------------------------------------------------------------------------------------------------------
# Serialize / parse contexts
# ---------------------------------------------------------------------------------------------------------------------


class GoSerializeContext(SerializeContext):
    """
    Stores a node under its idx, except when another node already took that idx: a node copied with copy.copy (as
    ChannelRangeRecovery does) keeps its original's idx, and the two must stay two nodes. Whichever is serialized
    second gets an id past every idx the codegen has allocated.
    """

    __slots__ = ("_ids", "_kb", "_library_names", "_next_free")

    def __init__(self, next_free: int, kb=None) -> None:
        super().__init__()
        self._ids: dict[int, int] = {}  # id(node) -> node_id
        self._next_free = next_free
        self._kb = kb
        self._library_names: dict[str, bool] = {}  # go_name -> kb.go_signatures knows the type

    def _is_library_struct(self, ty) -> bool:
        """A struct the binary or a library defines and the knowledge base can rebuild from its name alone."""
        if self._kb is None or not _is_descriptor_named_struct(ty):
            return False
        known = self._library_names.get(ty.go_name)
        if known is None:
            sigs = getattr(self._kb, "go_signatures", None)
            try:
                known = sigs is not None and sigs.named_type(ty.go_name) is not None
            except Exception:  # pylint:disable=broad-exception-caught
                known = False
            self._library_names[ty.go_name] = known
        return known

    def type_json_memo(self, t: SimType) -> dict | None:
        # library structs are written by name (as references) and resolved from kb.go_signatures when parsed, so a
        # type's JSON holds only what inference produced instead of the whole library type graph behind it
        memo: dict[str, SimTypeRef] = {}
        _seed_library_refs(t, memo, self._is_library_struct, set())
        return memo

    def node_id(self, node) -> int:
        nid = self._ids.get(id(node))
        if nid is None:
            nid = node.idx
            if nid in self._seen:
                nid = self._next_free
                self._next_free += 1
            self._ids[id(node)] = nid
        return nid

    def write_base_fields(self, node, pb) -> None:
        cls_name, _, ident_no = node.ident.rpartition("_")
        if cls_name != type(node).__name__ or not ident_no.isdigit():
            raise TypeError(f"Cannot serialize non-canonical GoConstruct.ident {node.ident!r} on {type(node).__name__}")
        pb.ident_no = int(ident_no)
        pb.tags_ref = self.intern_tags(node.tags)
        if isinstance(node, GoExpression):
            pb.collapsed = bool(node.collapsed)
            if node._type is not None:
                pb.expr_type_ref = self.intern_type(node._type)


def _seed_library_refs(ty, memo: dict[str, SimTypeRef], is_library, seen: set[int]) -> None:
    """Record every library struct reachable from ``ty`` in ``memo`` as a reference, without walking into it."""
    ty = unpack_typeref(ty)
    if ty is None or id(ty) in seen:
        return
    seen.add(id(ty))
    if isinstance(ty, SimStruct):
        if is_library(ty):
            memo[ty.go_name] = SimTypeRef(ty.go_name, type(ty))
            return
        if isinstance(ty, GoSimTypeInterface):
            for _, sig in ty.methods:
                _seed_library_refs(sig, memo, is_library, seen)
        for fty in ty.fields.values():
            _seed_library_refs(fty, memo, is_library, seen)
    elif isinstance(ty, SimUnion):
        for mty in ty.members.values():
            _seed_library_refs(mty, memo, is_library, seen)
    elif isinstance(ty, SimTypePointer):
        _seed_library_refs(ty.pts_to, memo, is_library, seen)
    elif isinstance(ty, (SimTypeArray, SimTypeFixedSizeArray)):
        _seed_library_refs(ty.elem_type, memo, is_library, seen)
    elif isinstance(ty, SimTypeFunction):
        for aty in ty.args or ():
            _seed_library_refs(aty, memo, is_library, seen)
        _seed_library_refs(ty.returnty, memo, is_library, seen)


class _GoLibraryTypes:
    """Resolves the name references a Go type pool holds against kb.go_signatures, as SimType.from_json expects of a
    type collection."""

    __slots__ = ("_cache", "_sigs")

    def __init__(self, kb) -> None:
        self._sigs = getattr(kb, "go_signatures", None) if kb is not None else None
        self._cache: dict[str, SimType] = {}

    def get(self, name: str, memo=None) -> SimType:  # pylint:disable=unused-argument
        ty = self._cache.get(name)
        if ty is None:
            if self._sigs is None or self._sigs.named_type(name) is None:
                raise AngrMissingTypeError(name)
            try:
                ty = self._sigs.type(name)
            except Exception as ex:  # pylint:disable=broad-exception-caught
                raise AngrMissingTypeError(name) from ex
            self._cache[name] = ty
        return ty


class GoParseContext(ParseContext):
    """Parses a Go node table."""

    __slots__ = ("_library_types", "_resolved_types")

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._library_types = _GoLibraryTypes(self.kb)
        self._resolved_types: dict[int, SimType] = {}

    def resolve_type(self, ref: int) -> SimType | None:
        """Resolve a type-pool ref once; every node referring to it shares the instance, as the live codegen's nodes
        share their variables' type objects. Library structs come back by name from kb.go_signatures."""
        if ref == 0:
            return None
        ty = self._resolved_types.get(ref)
        if ty is None:
            loaded = self._type_json_cache.get(ref)
            if loaded is None:
                loaded = json.loads(self._type_pool[ref - 1])
                self._type_json_cache[ref] = loaded
            ty = SimType.from_json(loaded, type_collection=self._library_types)
            if self.project is not None:
                ty = ty.with_arch(self.project.arch)
            self._resolved_types[ref] = ty
        return ty

    def resolve_function(self, addr: int) -> FunctionRef:
        # loaded on first use (GoConstant.reference_values), so that parsing loads no functions
        return FunctionRef(addr)

    def parser_for(self, kind: int):
        return _PARSERS[kind]

    def apply_base_state(self, obj, pb) -> None:
        obj.idx = pb.node_id
        obj.ident = f"{_CLASS_BY_KIND[pb.kind].__name__}_{pb.ident_no}"
        obj.tags = self.resolve_tags(pb.tags_ref)
        if isinstance(obj, GoExpression):
            obj.collapsed = bool(pb.collapsed) if pb.HasField("collapsed") else False
            obj._type = self.resolve_type(pb.expr_type_ref)

    def set_codegen(self, codegen) -> None:
        for node in self._parsed.values():
            node.codegen = codegen
            if isinstance(node, GoBinaryOp):
                node._cstyle_null_cmp = codegen.cstyle_null_cmp


# ---------------------------------------------------------------------------------------------------------------------
# Codegen envelope
# ---------------------------------------------------------------------------------------------------------------------

_CODEGEN_CTOR_DEFAULTS = {
    name: param.default
    for name, param in inspect.signature(GoStructuredCodeGenerator.__init__).parameters.items()
    if param.default is not inspect.Parameter.empty
}
# The Go generator has no C++ STL field accesses to name: it accepts stl_accessor_calls but ignores it and keeps
# no attribute for it.
_DISPLAY_OPTION_ATTRS = tuple(a for a in c_serialize._DISPLAY_OPTION_ATTRS if a != "stl_accessor_calls")
_DISPLAY_OPTION_DEFAULTS = {
    attr: _CODEGEN_CTOR_DEFAULTS[attr] for attr in _DISPLAY_OPTION_ATTRS if attr in _CODEGEN_CTOR_DEFAULTS
}


def serialize_codegen(codegen) -> codegen_pb2.Codegen:
    """Build a Codegen cmessage from a live GoStructuredCodeGenerator instance."""
    msg = codegen_pb2.Codegen()
    ctx = GoSerializeContext(codegen._next_node_idx, kb=getattr(codegen, "kb", None))

    if codegen.cfunc is not None:
        msg.root_id = ctx.serialize(codegen.cfunc)

    if codegen.text is not None:
        msg.text_z = zlib.compress(codegen.text.encode("utf-8"))
    # DecompilationCache.parse picks the generator by flavor, so it is always written
    msg.flavor = codegen.flavor if codegen.flavor is not None else Flavors.GO_FLAVOR

    _serialize_position_mappings(codegen.map_pos_to_node, codegen.map_pos_to_addr, ctx, msg.pos_maps)
    _serialize_instruction_mapping(codegen.map_addr_to_pos, msg.map_addr_to_pos)
    for (addr, idx), label in (codegen.map_addr_to_label or {}).items():
        entry = msg.map_addr_to_label.add()
        entry.addr = addr
        if idx is not None:
            entry.idx = idx
        entry.label_id = ctx.serialize(label)
    if codegen.cexterns:
        for v in sorted(codegen.cexterns, key=cextern_sort_key):
            msg.cexterns_ids.append(ctx.serialize(v))

    for var, dim_expr in (codegen._array_length_cexprs or {}).items():
        entry = msg.vla_dims.add()
        entry.simvar_ref = ctx.intern_simvar(var)
        entry.node_id = ctx.serialize(dim_expr)

    if codegen.expr_comments:
        for k, v in codegen.expr_comments.items():
            msg.expr_comments[k] = v
    if codegen.stmt_comments:
        for k, v in codegen.stmt_comments.items():
            msg.stmt_comments[k] = v
    _serialize_notes(codegen.notes, msg.notes_json)
    _serialize_const_formats(codegen.const_formats, msg.const_formats)

    for attr in _DISPLAY_OPTION_ATTRS:
        cg_attr = "_indent" if attr == "indent" else attr
        value = getattr(codegen, cg_attr, None)
        if value is not None:
            setattr(msg, attr, value)

    msg.nodes.extend(ctx.nodes)
    msg.type_pool.extend(ctx.type_pool)
    msg.tag_pool.extend(ctx.tag_pool)
    msg.simvar_pool.extend(ctx.simvar_pool)
    msg.node_config.config_entries.extend(ctx.node_config)
    return msg


def parse_codegen(msg, *, project=None, kb=None, func=None):
    """Create a GoStructuredCodeGenerator from a Codegen cmessage, bypassing __init__ (which runs the whole
    decompilation pipeline). The result is suitable for display, navigation, and cache-validity checks; re-rendering
    needs the runtime back-references (project / func / kb) reattached."""
    # built attribute by attribute, some of which a live generator never holds as None
    cg: Any = GoStructuredCodeGenerator.__new__(GoStructuredCodeGenerator)
    ctx = GoParseContext(
        msg.nodes,
        project=project,
        kb=kb,
        type_pool=msg.type_pool,
        tag_pool=msg.tag_pool,
        simvar_pool=msg.simvar_pool,
        node_config=msg.node_config,
    )

    cg.cfunc = ctx.resolve(msg.root_id) if msg.root_id != 0 else None

    cg.text = zlib.decompress(msg.text_z).decode("utf-8") if msg.HasField("text_z") else None
    cg.flavor = msg.flavor if msg.HasField("flavor") else Flavors.GO_FLAVOR
    cg.notes = _parse_notes(msg.notes_json)
    cg.expr_comments = dict(msg.expr_comments)
    cg.stmt_comments = dict(msg.stmt_comments)
    cg.const_formats = _parse_const_formats(msg.const_formats)
    cg.ident_counters = {}
    cg._next_node_idx = max((n.node_id for n in msg.nodes), default=0) + 1

    cg.map_pos_to_node, cg.map_pos_to_addr = _parse_position_mappings(msg.pos_maps, ctx)
    cg.map_addr_to_pos = _parse_instruction_mapping(msg.map_addr_to_pos)
    # built on first use (see GoStructuredCodeGenerator.map_ast_to_pos), so that parsing loads no callees
    cg._map_ast_to_pos = None
    cg._map_ast_to_pos_pending = True
    cg._resolved_callees = {}

    cg.map_addr_to_label = {}
    for entry in msg.map_addr_to_label:
        cg.map_addr_to_label[(entry.addr, entry.idx)] = ctx.resolve(entry.label_id)

    cg.cexterns = {ctx.resolve(i) for i in msg.cexterns_ids} if msg.cexterns_ids else None

    cg._array_length_cexprs = {}
    for entry in msg.vla_dims:
        var = ctx.resolve_simvar(entry.simvar_ref)
        if var is not None:
            cg._array_length_cexprs[var] = ctx.resolve(entry.node_id)

    for attr in _DISPLAY_OPTION_ATTRS:
        cg_attr = "_indent" if attr == "indent" else attr
        if msg.HasField(attr):
            setattr(cg, cg_attr, getattr(msg, attr))
        elif attr in _DISPLAY_OPTION_DEFAULTS:
            setattr(cg, cg_attr, _DISPLAY_OPTION_DEFAULTS[attr])

    cg.project = project
    cg._func = func
    cg._func_args = None
    cg._cfg = None
    cg._sequence = None
    cg.kb = kb
    cg.externs = set()
    cg._variables_in_use = cg.cfunc.variables_in_use if cg.cfunc is not None else None
    cg._inlined_strings = set()
    cg._function_pointers = set()
    cg.ailexpr2cnode = None
    cg.cnode2ailexpr = None
    cg._handlers = None  # callers that want to re-render should construct a fresh GoStructuredCodeGenerator
    cg.ail_graph = None
    cg._variable_map = VariableMap()
    cg.indent_delta = INDENT_DELTA
    if cg.cfunc is not None:
        manager = None
        if kb is not None and func is not None and func.addr in kb.dec_variables:
            manager = kb.dec_variables[func.addr]
        cg.cfunc.variable_manager = manager

    ctx.set_codegen(cg)
    return cg


def rebuild_ast_to_pos(pos_to_node):
    """Mirror of GoStructuredCodeGenerator.render_text: rebuild map_ast_to_pos from map_pos_to_node."""
    ast_to_pos = defaultdict(set)
    if pos_to_node is None:
        return ast_to_pos
    for elem, node in pos_to_node.items():
        obj = node.obj
        if isinstance(obj, GoConstant):
            ast_to_pos[obj.value].add(elem)
        elif isinstance(obj, GoVariable):
            ast_to_pos[obj.unified_variable if obj.unified_variable is not None else obj.variable].add(elem)
        elif isinstance(obj, GoFunctionCall):
            ast_to_pos[obj.callee_func if obj.callee_func is not None else obj.callee_target].add(elem)
        elif isinstance(obj, GoStructField):
            ast_to_pos[(obj.struct_type, obj.offset)].add(elem)
        else:
            ast_to_pos[obj].add(elem)
    return ast_to_pos


# ---------------------------------------------------------------------------------------------------------------------
# Parsers for the payloads Go shares with C (the C serializers write them)
# ---------------------------------------------------------------------------------------------------------------------


def _parse_break(_pb, _ctx):
    return GoBreak.__new__(GoBreak)


def _parse_continue(_pb, _ctx):
    return GoContinue.__new__(GoContinue)


def _parse_label(pb, _ctx):
    obj = GoLabel.__new__(GoLabel)
    obj.name = pb.clabel.name
    return obj


def _parse_statements(pb, ctx):
    obj = GoStatements.__new__(GoStatements)
    obj.statements = [ctx.resolve(i) for i in pb.cstatements.statements_ids]
    obj.addr = pb.cstatements.addr if pb.cstatements.HasField("addr") else None
    return obj


def _parse_ifbreak(pb, ctx):
    obj = GoIfBreak.__new__(GoIfBreak)
    obj.condition = ctx.resolve(pb.cifbreak.condition_id)
    obj.cstyle_ifs = pb.cifbreak.cstyle_ifs
    return obj


def _parse_dirtystmt(pb, ctx):
    obj = GoDirtyStatement.__new__(GoDirtyStatement)
    obj.dirty = ctx.resolve(pb.cdirty_stmt.dirty_id)
    return obj


def _parse_loop(cls, body, ctx):
    obj = cls.__new__(cls)
    obj.condition = ctx.resolve(body.condition_id) if body.HasField("condition_id") else None
    obj.body = ctx.resolve(body.body_id) if body.HasField("body_id") else None
    return obj


def _parse_while(pb, ctx):
    return _parse_loop(GoWhileLoop, pb.cwhile, ctx)


def _parse_dowhile(pb, ctx):
    return _parse_loop(GoDoWhileLoop, pb.cdowhile, ctx)


def _parse_for(pb, ctx):
    obj = GoForLoop.__new__(GoForLoop)
    body = pb.cfor
    obj.initializer = ctx.resolve(body.initializer_id) if body.HasField("initializer_id") else None
    obj.condition = ctx.resolve(body.condition_id) if body.HasField("condition_id") else None
    obj.iterator = ctx.resolve(body.iterator_id) if body.HasField("iterator_id") else None
    obj.body = ctx.resolve(body.body_id) if body.HasField("body_id") else None
    return obj


def _parse_ifelse(pb, ctx):
    obj = GoIfElse.__new__(GoIfElse)
    body = pb.cifelse
    obj.condition_and_nodes = [
        (ctx.resolve(e.condition_id), ctx.resolve(e.statement_id) if e.HasField("statement_id") else None)
        for e in body.condition_and_nodes
    ]
    obj.else_node = ctx.resolve(body.else_node_id) if body.HasField("else_node_id") else None
    obj.simplify_else_scope = body.simplify_else_scope
    obj.cstyle_ifs = body.cstyle_ifs
    return obj


def _parse_incomplete_switch(pb, ctx):
    obj = GoIncompleteSwitchCase.__new__(GoIncompleteSwitchCase)
    body = pb.cincomplete_switch
    obj.head = ctx.resolve(body.head_id)
    obj.cases = [(e.case_addr, ctx.resolve(e.statements_id)) for e in body.cases]
    return obj


def _parse_goto(pb, ctx):
    obj: Any = GoGoto.__new__(GoGoto)
    which = pb.cgoto.WhichOneof("target")
    if which == "target_int":
        obj.target = pb.cgoto.target_int
    elif which == "target_expr_id":
        obj.target = ctx.resolve(pb.cgoto.target_expr_id)
    else:
        obj.target = None
    obj.target_idx = pb.cgoto.target_idx
    return obj


def _parse_unop(pb, ctx):
    obj = GoUnaryOp.__new__(GoUnaryOp)
    obj.op = pb.cunop.op
    obj.operand = ctx.resolve(pb.cunop.operand_id)
    return obj


def _parse_typecast(pb, ctx):
    obj = GoTypeCast.__new__(GoTypeCast)
    obj.src_type = ctx.resolve_type(pb.ctypecast.src_type_ref)
    obj.dst_type = ctx.resolve_type(pb.ctypecast.dst_type_ref)
    obj.expr = ctx.resolve(pb.ctypecast.expr_id)
    return obj


def _parse_ite(pb, ctx):
    obj = GoITE.__new__(GoITE)
    obj.cond = ctx.resolve(pb.cite.cond_id)
    obj.iftrue = ctx.resolve(pb.cite.iftrue_id)
    obj.iffalse = ctx.resolve(pb.cite.iffalse_id)
    return obj


def _parse_multi(pb, ctx):
    obj = GoMultiStatementExpression.__new__(GoMultiStatementExpression)
    obj.stmts = ctx.resolve(pb.cmulti_stmt_expr.stmts_id)
    obj.expr = ctx.resolve(pb.cmulti_stmt_expr.expr_id)
    return obj


def _parse_vex(pb, ctx):
    obj = GoVEXCCallExpression.__new__(GoVEXCCallExpression)
    obj.callee = pb.cvex_ccall.callee
    obj.operands = [ctx.resolve(i) for i in pb.cvex_ccall.operands_ids]
    return obj


def _parse_structfield(pb, ctx):
    obj = GoStructField.__new__(GoStructField)
    obj.struct_type = ctx.resolve_type(pb.cstruct_field.struct_type_ref)
    obj.offset = pb.cstruct_field.offset
    obj.field = pb.cstruct_field.field
    return obj


def _parse_fakevar(pb, _ctx):
    obj = GoFakeVariable.__new__(GoFakeVariable)
    obj.name = pb.cfake_var.name
    return obj


def _parse_var(pb, ctx):
    obj = GoVariable.__new__(GoVariable)
    body = pb.cvar
    obj.variable = ctx.resolve_simvar(body.variable_ref)
    obj.unified_variable = ctx.resolve_simvar(body.unified_variable_ref)
    obj.variable_type = ctx.resolve_type(body.variable_type_ref)
    obj.vvar_id = body.vvar_id if body.HasField("vvar_id") else None
    return obj


def _parse_idxvar(pb, ctx):
    obj = GoIndexedVariable.__new__(GoIndexedVariable)
    obj.variable = ctx.resolve(pb.cindexed_var.variable_id)
    obj.index = ctx.resolve(pb.cindexed_var.index_id)
    return obj


def _parse_ailblock(pb, _ctx):
    obj = GoAILBlock.__new__(GoAILBlock)
    obj.block = AilBlock.from_bytes(pb.cailblock.block)
    return obj


def _parse_unsupported(pb, _ctx):
    obj = GoUnsupportedStatement.__new__(GoUnsupportedStatement)
    obj.stmt = AilStatement.from_bytes(pb.cunsupported.stmt)
    return obj


# ---------------------------------------------------------------------------------------------------------------------
# Shared kinds whose Go payload differs
# ---------------------------------------------------------------------------------------------------------------------


def _ser_function(node, pb, ctx):
    body = pb.go_function
    func = body.function
    addr = _serializable_addr(node)
    if addr is not None:
        func.addr = addr
    func.name = node.name
    func.functy_ref = ctx.intern_type(node.functy)
    for arg in node.arg_list:
        func.arg_list_ids.append(ctx.serialize(arg))
    func.statements_id = ctx.serialize(node.statements)
    for simvar, var in node.variables_in_use.items():
        entry = func.variables_in_use.add()
        entry.simvariable_ref = ctx.intern_simvar(simvar)
        entry.cvariable_id = ctx.serialize(var)
    if node.demangled_name is not None:
        func.demangled_name = node.demangled_name
    func.show_demangled_name = node.show_demangled_name
    func.omit_header = node.omit_header
    for name, ty in node.extra_decls:
        entry = body.extra_decls.add()
        entry.name = name
        entry.type_ref = ctx.intern_type(ty)
    # short_declared is a set: emit it in a fixed order so the same codegen always serializes to the same bytes
    members = ((isinstance(m, str), m if isinstance(m, str) else _simvar_to_bytes(m), m) for m in node.short_declared)
    for is_name, key, member in sorted(members, key=lambda t: t[:2]):
        entry = body.short_declared.add()
        if is_name:
            entry.name = key
        else:
            entry.simvar_ref = ctx.intern_simvar(member)


def _parse_function(pb, ctx):
    obj: Any = GoFunction.__new__(GoFunction)
    body = pb.go_function
    func = body.function
    obj.addr = func.addr if func.HasField("addr") else None
    obj.name = func.name
    obj.functy = ctx.resolve_type(func.functy_ref)
    obj.arg_list = [ctx.resolve(i) for i in func.arg_list_ids]
    obj.statements = ctx.resolve(func.statements_id)
    obj.variables_in_use = {
        ctx.resolve_simvar(e.simvariable_ref): ctx.resolve(e.cvariable_id) for e in func.variables_in_use
    }
    obj.demangled_name = func.demangled_name if func.HasField("demangled_name") else None
    obj.show_demangled_name = func.show_demangled_name
    obj.omit_header = func.omit_header
    obj.extra_decls = [(e.name, ctx.resolve_type(e.type_ref)) for e in body.extra_decls]
    obj.short_declared = {
        e.name if e.WhichOneof("entry") == "name" else ctx.resolve_simvar(e.simvar_ref) for e in body.short_declared
    }
    # variable_manager is attached by parse_codegen; unified_local_vars is recomputed by refresh() once codegen and
    # variable_manager are wired up
    obj.variable_manager = None
    obj.unified_local_vars = {}
    return obj


def _ser_assignment(node, pb, ctx):
    body = pb.go_assignment
    body.assignment.lhs_id = ctx.serialize(node.lhs)
    body.assignment.rhs_id = ctx.serialize(node.rhs)
    body.declares = node.declares


def _parse_assignment(pb, ctx):
    obj = GoAssignment.__new__(GoAssignment)
    body = pb.go_assignment
    obj.lhs = ctx.resolve(body.assignment.lhs_id)
    obj.rhs = ctx.resolve(body.assignment.rhs_id)
    obj.declares = body.declares
    return obj


def _ser_exprstmt(node, pb, ctx):
    body = pb.go_expression_stmt
    body.expr_id = ctx.serialize(node.expr)
    if node.returning is not None:
        body.returning = node.returning


def _parse_exprstmt(pb, ctx):
    obj = GoExpressionStatement.__new__(GoExpressionStatement)
    body = pb.go_expression_stmt
    obj.expr = ctx.resolve(body.expr_id)
    obj.returning = body.returning if body.HasField("returning") else None
    return obj


def _ser_return(node, pb, ctx):
    body = pb.go_return
    body.SetInParent()
    body.retval_ids.extend(ctx.serialize(v) for v in node.retvals)


def _parse_return(pb, ctx):
    obj = GoReturn.__new__(GoReturn)
    obj.retvals = [ctx.resolve(i) for i in pb.go_return.retval_ids]
    return obj


def _ser_funcall(node, pb, ctx):
    body = pb.go_funcall
    call = body.call
    target = node.callee_target
    if isinstance(target, int):
        call.callee_target_int = target
    elif isinstance(target, str):
        call.callee_target_str = target
    elif target is not None:
        call.callee_target_expr_id = ctx.serialize(target)
    if node.callee_func_addr is not None:
        call.callee_func_addr = node.callee_func_addr
    for a in node.args:
        call.args_ids.append(ctx.serialize(a))
    body.site_returnty_ref = ctx.intern_type(node.site_returnty)
    body.SetInParent()
    if not (node.show_demangled_name and node.show_disambiguated_name):
        ctx.add_cfuncall_config(pb.node_id, node.show_demangled_name, node.show_disambiguated_name)


def _parse_funcall(pb, ctx):
    obj = GoFunctionCall.__new__(GoFunctionCall)
    body = pb.go_funcall
    call = body.call
    which = call.WhichOneof("callee_target")
    if which == "callee_target_int":
        obj.callee_target = call.callee_target_int
    elif which == "callee_target_str":
        obj.callee_target = call.callee_target_str
    elif which == "callee_target_expr_id":
        obj.callee_target = ctx.resolve(call.callee_target_expr_id)
    else:
        obj.callee_target = None
    # resolved on first use of callee_func
    obj._callee_func = None
    obj._callee_func_addr = call.callee_func_addr if call.HasField("callee_func_addr") else None
    obj.args = [ctx.resolve(i) for i in call.args_ids]
    obj.site_returnty = ctx.resolve_type(body.site_returnty_ref)
    obj.show_demangled_name, obj.show_disambiguated_name = ctx.cfuncall_config(pb.node_id)
    return obj


def _ser_binop(node, pb, ctx):
    body = pb.go_binop
    body.binop.op = node.op
    body.binop.lhs_id = ctx.serialize(node.lhs)
    body.binop.rhs_id = ctx.serialize(node.rhs)
    body.binop.common_type_ref = ctx.intern_type(node.common_type)
    if node.signed is not None:
        body.signed = node.signed


def _parse_binop(pb, ctx):
    obj = GoBinaryOp.__new__(GoBinaryOp)
    body = pb.go_binop
    obj.op = body.binop.op
    obj.lhs = ctx.resolve(body.binop.lhs_id)
    obj.rhs = ctx.resolve(body.binop.rhs_id)
    obj.common_type = ctx.resolve_type(body.binop.common_type_ref)
    obj.signed = body.signed if body.HasField("signed") else None
    obj._cstyle_null_cmp = False  # rebuilt from the codegen by set_codegen
    return obj


def _ser_const(node, pb, ctx):
    body = pb.go_const
    _write_constant(node, body.constant, ctx, reference_values=node.raw_reference_values)
    body.constant.SetInParent()
    if node.string_data is not None:
        body.string_data = node.string_data


def _parse_const(pb, ctx):
    obj = GoConstant.__new__(GoConstant)
    body = pb.go_const
    _read_constant(obj, body.constant, ctx)
    obj.string_data = body.string_data if body.HasField("string_data") else None
    return obj


def _ser_switch(node, pb, ctx):
    body = pb.go_switch
    body.switch_id = ctx.serialize(node.switch)
    for case_ids, stmts in node.cases:
        entry = body.cases.add()
        entry.is_tuple = isinstance(case_ids, tuple)
        labels = case_ids if entry.is_tuple else (case_ids,)
        if labels and all(isinstance(label, str) for label in labels):
            entry.case_strs.extend(labels)
        else:
            # as in _ser_cswitch: store raw 64-bit values; record which are negative only when one of them is
            signed = [label < 0 for label in labels]
            entry.case_ids.extend(label + _UINT64_RANGE if neg else label for label, neg in zip(labels, signed))
            if any(signed):
                entry.case_ids_signed.extend(signed)
        entry.statements_id = ctx.serialize(stmts)
    if node.default is not None:
        body.default_id = ctx.serialize(node.default)


def _parse_switch(pb, ctx):
    obj = GoSwitchCase.__new__(GoSwitchCase)
    body = pb.go_switch
    obj.switch = ctx.resolve(body.switch_id)
    obj.cases = []
    for entry in body.cases:
        if entry.case_strs:
            labels = list(entry.case_strs)
        else:
            signed = entry.case_ids_signed
            labels = [v - _UINT64_RANGE if i < len(signed) and signed[i] else v for i, v in enumerate(entry.case_ids)]
        obj.cases.append((tuple(labels) if entry.is_tuple else labels[0], ctx.resolve(entry.statements_id)))
    obj.default = ctx.resolve(body.default_id) if body.HasField("default_id") else None
    return obj


def _ser_register(node, pb, _ctx):
    if isinstance(node.reg, str):
        pb.go_register.name = node.reg
    else:
        pb.go_register.reg = node.reg.to_bytes()


def _parse_register(pb, _ctx):
    obj = GoRegister.__new__(GoRegister)
    if pb.go_register.HasField("name"):
        obj.reg = pb.go_register.name
    else:
        obj.reg = AilExpression.from_bytes(pb.go_register.reg)
    return obj


def _ser_varfield(node, pb, ctx):
    # CVariableFieldMsg without stl_accessor, which Go never sets
    pb.cvar_field.variable_id = ctx.serialize(node.variable)
    pb.cvar_field.field_id = ctx.serialize(node.field)
    pb.cvar_field.var_is_ptr = node.var_is_ptr


def _parse_varfield(pb, ctx):
    obj = GoVariableField.__new__(GoVariableField)
    obj.variable = ctx.resolve(pb.cvar_field.variable_id)
    obj.field = ctx.resolve(pb.cvar_field.field_id)
    obj.var_is_ptr = pb.cvar_field.var_is_ptr
    return obj


def _ser_dirtyexpr(node, pb, _ctx):
    # CDirtyExpressionMsg without operands, which GoDirtyExpression does not have
    pb.cdirty_expr.dirty = node.dirty.to_bytes()


def _parse_dirtyexpr(pb, _ctx):
    obj = GoDirtyExpression.__new__(GoDirtyExpression)
    obj.dirty = AilExpression.from_bytes(pb.cdirty_expr.dirty)
    return obj


# ---------------------------------------------------------------------------------------------------------------------
# Go-only kinds
# ---------------------------------------------------------------------------------------------------------------------


def _ser_range_loop(node, pb, ctx):
    body = pb.go_range_loop
    if node.index is not None:
        body.index_id = ctx.serialize(node.index)
    if node.value is not None:
        body.value_id = ctx.serialize(node.value)
    body.collection_id = ctx.serialize(node.collection)
    body.body_id = ctx.serialize(node.body)
    body.declares = node.declares


def _parse_range_loop(pb, ctx):
    obj = GoRangeLoop.__new__(GoRangeLoop)
    body = pb.go_range_loop
    obj.index = ctx.resolve(body.index_id) if body.HasField("index_id") else None
    obj.value = ctx.resolve(body.value_id) if body.HasField("value_id") else None
    obj.collection = ctx.resolve(body.collection_id)
    obj.body = ctx.resolve(body.body_id)
    obj.declares = body.declares
    return obj


def _ser_method_call(node, pb, ctx):
    body = pb.go_method_call
    body.receiver_id = ctx.serialize(node.receiver)
    body.method = node.method
    body.args_ids.extend(ctx.serialize(a) for a in node.args)
    body.signature_ref = ctx.intern_type(node.signature)


def _parse_method_call(pb, ctx):
    obj = GoMethodCall.__new__(GoMethodCall)
    body = pb.go_method_call
    obj.receiver = ctx.resolve(body.receiver_id)
    obj.method = body.method
    obj.args = [ctx.resolve(i) for i in body.args_ids]
    obj.signature = ctx.resolve_type(body.signature_ref)
    return obj


def _ser_multi_assignment(node, pb, ctx):
    body = pb.go_multi_assignment
    body.lhs_ids.extend(ctx.serialize(t) for t in node.lhs)
    body.rhs_id = ctx.serialize(node.rhs)
    body.declares = node.declares


def _parse_multi_assignment(pb, ctx):
    obj = GoMultiAssignment.__new__(GoMultiAssignment)
    body = pb.go_multi_assignment
    obj.lhs = [ctx.resolve(i) for i in body.lhs_ids]
    obj.rhs = ctx.resolve(body.rhs_id)
    obj.declares = body.declares
    return obj


def _ser_select(node, pb, ctx):
    body = pb.go_select
    body.SetInParent()
    for case, stmts in node.cases:
        entry = body.cases.add()
        entry.kind = case.kind
        if case.channel is not None:
            entry.channel_id = ctx.serialize(case.channel)
        if case.value is not None:
            entry.value_id = ctx.serialize(case.value)
        if case.ok is not None:
            entry.ok_id = ctx.serialize(case.ok)
        entry.body_id = ctx.serialize(stmts)


def _parse_select(pb, ctx):
    obj = GoSelect.__new__(GoSelect)
    obj.cases = [
        (
            GoSelectCase(
                e.kind,
                channel=ctx.resolve(e.channel_id) if e.HasField("channel_id") else None,
                value=ctx.resolve(e.value_id) if e.HasField("value_id") else None,
                ok=ctx.resolve(e.ok_id) if e.HasField("ok_id") else None,
            ),
            ctx.resolve(e.body_id),
        )
        for e in pb.go_select.cases
    ]
    return obj


def _ser_type_switch(node, pb, ctx):
    body = pb.go_type_switch
    body.value_id = ctx.serialize(node.value)
    if node.bound_name is not None:
        body.bound_name = node.bound_name
    for type_name, stmts in node.cases:
        entry = body.cases.add()
        entry.type_name = type_name
        entry.body_id = ctx.serialize(stmts)
    if node.default is not None:
        body.default_id = ctx.serialize(node.default)


def _parse_type_switch(pb, ctx):
    obj = GoTypeSwitch.__new__(GoTypeSwitch)
    body = pb.go_type_switch
    obj.value = ctx.resolve(body.value_id)
    obj.bound_name = body.bound_name if body.HasField("bound_name") else None
    obj.cases = [(e.type_name, ctx.resolve(e.body_id)) for e in body.cases]
    obj.default = ctx.resolve(body.default_id) if body.HasField("default_id") else None
    return obj


def _ser_string_literal(node, pb, _ctx):
    body = pb.go_string_literal
    body.SetInParent()
    body.data = node.data


def _parse_string_literal(pb, _ctx):
    obj = GoStringLiteral.__new__(GoStringLiteral)
    obj.data = pb.go_string_literal.data
    return obj


def _ser_struct_literal(node, pb, ctx):
    body = pb.go_struct_literal
    body.SetInParent()
    body.name = node.name
    for offset, value in node.fields.items():
        entry = body.fields.add()
        entry.offset = offset
        entry.value_id = ctx.serialize(value)
    for offset, name in node.field_names.items():
        entry = body.field_names.add()
        entry.offset = offset
        entry.name = name


def _parse_struct_literal(pb, ctx):
    obj = GoStructLiteral.__new__(GoStructLiteral)
    body = pb.go_struct_literal
    obj.name = body.name
    obj.fields = {e.offset: ctx.resolve(e.value_id) for e in body.fields}
    obj.field_names = {e.offset: e.name for e in body.field_names}
    return obj


def _ser_boxed_value(node, pb, ctx):
    body = pb.go_boxed_value
    body.expr_id = ctx.serialize(node.expr)
    body.iface_name = node.iface_name
    if node.concrete is not None:
        body.concrete = node.concrete


def _parse_boxed_value(pb, ctx):
    obj = GoBoxedValue.__new__(GoBoxedValue)
    body = pb.go_boxed_value
    obj.expr = ctx.resolve(body.expr_id)
    obj.iface_name = body.iface_name
    obj.concrete = body.concrete if body.HasField("concrete") else None
    return obj


def _ser_type_assertion(node, pb, ctx):
    body = pb.go_type_assertion
    body.expr_id = ctx.serialize(node.expr)
    body.type_name = node.type_name
    body.conversion = node.conversion


def _parse_type_assertion(pb, ctx):
    obj = GoTypeAssertion.__new__(GoTypeAssertion)
    body = pb.go_type_assertion
    obj.expr = ctx.resolve(body.expr_id)
    obj.type_name = body.type_name
    obj.conversion = body.conversion
    return obj


def _ser_slice_literal(node, pb, ctx):
    body = pb.go_slice_literal
    body.SetInParent()
    body.elem_type = node.elem_type
    body.elems_ids.extend(ctx.serialize(e) for e in node.elems)


def _parse_slice_literal(pb, ctx):
    obj = GoSliceLiteral.__new__(GoSliceLiteral)
    body = pb.go_slice_literal
    obj.elem_type = body.elem_type
    obj.elems = [ctx.resolve(i) for i in body.elems_ids]
    return obj


def register_all() -> None:
    """Register serializer/parser pairs for every concrete GoConstruct subclass. Called from go.py at import time,
    once every class is defined."""
    # kinds shared with C whose payload matches: the C serializer writes it
    _register(GoBreak, codegen_pb2.CCK_BREAK, _ser_cbreak, _parse_break)
    _register(GoContinue, codegen_pb2.CCK_CONTINUE, _ser_ccontinue, _parse_continue)
    _register(GoLabel, codegen_pb2.CCK_LABEL, _ser_clabel, _parse_label)
    _register(GoStatements, codegen_pb2.CCK_STATEMENTS, _ser_cstatements, _parse_statements)
    _register(GoIfBreak, codegen_pb2.CCK_IF_BREAK, _ser_cifbreak, _parse_ifbreak)
    _register(GoDirtyStatement, codegen_pb2.CCK_DIRTY_STATEMENT, _ser_cdirtystmt, _parse_dirtystmt)
    _register(GoWhileLoop, codegen_pb2.CCK_WHILE_LOOP, _ser_cwhile, _parse_while)
    _register(GoDoWhileLoop, codegen_pb2.CCK_DO_WHILE_LOOP, _ser_cdowhile, _parse_dowhile)
    _register(GoForLoop, codegen_pb2.CCK_FOR_LOOP, _ser_cfor, _parse_for)
    _register(GoIfElse, codegen_pb2.CCK_IF_ELSE, _ser_cifelse, _parse_ifelse)
    _register(
        GoIncompleteSwitchCase,
        codegen_pb2.CCK_INCOMPLETE_SWITCH_CASE,
        _ser_cincomplete_switch,
        _parse_incomplete_switch,
    )
    _register(GoGoto, codegen_pb2.CCK_GOTO, _ser_cgoto, _parse_goto)
    _register(GoUnaryOp, codegen_pb2.CCK_UNARY_OP, _ser_cunop, _parse_unop)
    _register(GoTypeCast, codegen_pb2.CCK_TYPE_CAST, _ser_ctypecast, _parse_typecast)
    _register(GoITE, codegen_pb2.CCK_ITE, _ser_cite, _parse_ite)
    _register(GoMultiStatementExpression, codegen_pb2.CCK_MULTI_STATEMENT_EXPRESSION, _ser_cmulti, _parse_multi)
    _register(GoVEXCCallExpression, codegen_pb2.CCK_VEX_CCALL_EXPRESSION, _ser_cvex, _parse_vex)
    _register(GoStructField, codegen_pb2.CCK_STRUCT_FIELD, _ser_cstructfield, _parse_structfield)
    _register(GoFakeVariable, codegen_pb2.CCK_FAKE_VARIABLE, _ser_cfakevar, _parse_fakevar)
    _register(GoVariable, codegen_pb2.CCK_VARIABLE, _ser_cvar, _parse_var)
    _register(GoIndexedVariable, codegen_pb2.CCK_INDEXED_VARIABLE, _ser_cidxvar, _parse_idxvar)
    _register(GoAILBlock, codegen_pb2.CCK_AIL_BLOCK, _ser_cailblock, _parse_ailblock)
    _register(GoUnsupportedStatement, codegen_pb2.CCK_UNSUPPORTED_STATEMENT, _ser_cunsupported, _parse_unsupported)
    # kinds shared with C whose Go payload differs
    _register(GoFunction, codegen_pb2.CCK_FUNCTION, _ser_function, _parse_function)
    _register(GoAssignment, codegen_pb2.CCK_ASSIGNMENT, _ser_assignment, _parse_assignment)
    _register(GoExpressionStatement, codegen_pb2.CCK_EXPRESSION_STATEMENT, _ser_exprstmt, _parse_exprstmt)
    _register(GoReturn, codegen_pb2.CCK_RETURN, _ser_return, _parse_return)
    _register(GoFunctionCall, codegen_pb2.CCK_FUNCTION_CALL, _ser_funcall, _parse_funcall)
    _register(GoBinaryOp, codegen_pb2.CCK_BINARY_OP, _ser_binop, _parse_binop)
    _register(GoConstant, codegen_pb2.CCK_CONSTANT, _ser_const, _parse_const)
    _register(GoRegister, codegen_pb2.CCK_REGISTER, _ser_register, _parse_register)
    _register(GoVariableField, codegen_pb2.CCK_VARIABLE_FIELD, _ser_varfield, _parse_varfield)
    _register(GoDirtyExpression, codegen_pb2.CCK_DIRTY_EXPRESSION, _ser_dirtyexpr, _parse_dirtyexpr)
    _register(GoSwitchCase, codegen_pb2.CCK_SWITCH_CASE, _ser_switch, _parse_switch)
    # Go-only kinds
    _register(GoRangeLoop, codegen_pb2.CCK_GO_RANGE_LOOP, _ser_range_loop, _parse_range_loop)
    _register(GoMethodCall, codegen_pb2.CCK_GO_METHOD_CALL, _ser_method_call, _parse_method_call)
    _register(GoMultiAssignment, codegen_pb2.CCK_GO_MULTI_ASSIGNMENT, _ser_multi_assignment, _parse_multi_assignment)
    _register(GoSelect, codegen_pb2.CCK_GO_SELECT, _ser_select, _parse_select)
    _register(GoTypeSwitch, codegen_pb2.CCK_GO_TYPE_SWITCH, _ser_type_switch, _parse_type_switch)
    _register(GoStringLiteral, codegen_pb2.CCK_GO_STRING_LITERAL, _ser_string_literal, _parse_string_literal)
    _register(GoStructLiteral, codegen_pb2.CCK_GO_STRUCT_LITERAL, _ser_struct_literal, _parse_struct_literal)
    _register(GoBoxedValue, codegen_pb2.CCK_GO_BOXED_VALUE, _ser_boxed_value, _parse_boxed_value)
    _register(GoTypeAssertion, codegen_pb2.CCK_GO_TYPE_ASSERTION, _ser_type_assertion, _parse_type_assertion)
    _register(GoSliceLiteral, codegen_pb2.CCK_GO_SLICE_LITERAL, _ser_slice_literal, _parse_slice_literal)
