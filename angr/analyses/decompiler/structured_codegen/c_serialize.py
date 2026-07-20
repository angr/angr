"""
Protobuf serialization helpers for the C AST defined in :mod:`c`.

The AST is serialized as a flat indexed table of :class:`CConstructNode` cmessages: every :class:`CConstruct` instance
is assigned a non-zero ``uint32`` node_id at serialize time, and child CConstructs are referenced by id rather than
embedded inline. This keeps the schema-level representation flat (which avoids unbounded recursion in protobuf
encoding) and lets :class:`PositionMapping`, ``cexterns``, and ``map_addr_to_label`` reference into the AST without
duplicating subtrees.

The dispatch is table-driven (per subclass) rather than method-based so that the rendering-side classes in :mod:`c`
stay focused on rendering logic and a future audit of the serialization can look at this one file.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import angr.sim_variable as sim_variable
from angr.protos import codegen_pb2
from angr.sim_type import SimType
from angr.sim_variable import SimVariable

from .base import PositionMapping
from .c import CConstant, CFunctionCall, CStructField, CVariable

if TYPE_CHECKING:
    from .c import CConstruct

# ---------------------------------------------------------------------------------------------------------------------
# Tag sanitization
# ---------------------------------------------------------------------------------------------------------------------


def _sanitize_tags(tags: dict | None) -> codegen_pb2.CConstructTags:
    """Drop tag entries we can't JSON-encode; keep the rest as ``{key: json.dumps(value)}``."""
    out = codegen_pb2.CConstructTags()
    if not tags:
        return out
    for k, v in tags.items():
        if not isinstance(k, str):
            continue
        try:
            out.json_values[k] = json.dumps(v)
        except (TypeError, ValueError):
            continue  # silently drop non-JSON-serializable values; they will be missing after round-trip
    return out


def _parse_tags(cmsg: codegen_pb2.CConstructTags) -> dict:
    return {k: json.loads(v) for k, v in cmsg.json_values.items()}


# ---------------------------------------------------------------------------------------------------------------------
# SimType / SimVariable plumbing
# ---------------------------------------------------------------------------------------------------------------------


def _simtype_to_json(t: SimType | None) -> str:
    if t is None:
        return ""
    return json.dumps(t.to_json())


def _simtype_from_json(s: str) -> SimType | None:
    if not s:
        return None
    return SimType.from_json(json.loads(s))


def _simvar_to_bytes(v: SimVariable | None) -> bytes:
    """Encode a SimVariable as ``b"<ClassName>\\0<protobuf>"`` so the dispatch type tag round-trips with the payload.
    SimVariable subclasses each define their own _pb2 message; we need the type tag to know which Serializable.parse
    classmethod to dispatch through."""
    if v is None:
        return b""
    return type(v).__name__.encode("ascii") + b"\0" + v.serialize()


def _simvar_from_bytes(b: bytes) -> SimVariable | None:
    if not b:
        return None
    sep = b.index(b"\0")
    cls_name = b[:sep].decode("ascii")
    payload = b[sep + 1 :]
    cls = getattr(sim_variable, cls_name)
    return cls.parse(payload)


# ---------------------------------------------------------------------------------------------------------------------
# Serialize / parse contexts
# ---------------------------------------------------------------------------------------------------------------------


class SerializeContext:
    """
    Tracks which nodes have been serialized while walking the C AST.
    """

    __slots__ = ("_seen", "nodes")

    def __init__(self) -> None:
        self._seen: set[int] = set()  # stores CConstruct.idx for serialized nodes
        self.nodes: list[codegen_pb2.CConstructNode] = []

    def serialize(self, node: CConstruct | None) -> int:
        """Serialize ``node`` (recursively) and return its node_id (== node.idx). 0 indicates absent."""
        if node is None:
            return 0
        nid = node.idx
        if nid in self._seen:
            return nid
        self._seen.add(nid)

        from .c import CExpression  # avoid circular import at module load

        pb = codegen_pb2.CConstructNode()
        pb.node_id = nid
        pb.kind = _SERIALIZE_KIND_BY_CLASS[type(node)]
        pb.ident = node.ident
        pb.tags.CopyFrom(_sanitize_tags(getattr(node, "tags", None)))
        if isinstance(node, CExpression):
            pb.collapsed = bool(getattr(node, "collapsed", False))
            ty = getattr(node, "_type", None)
            if ty is not None:
                pb.expr_type_json = _simtype_to_json(ty)
        _SERIALIZERS[type(node)](node, pb, self)
        self.nodes.append(pb)
        return nid


class ParseContext:
    """
    Tracks and resolves node.idx to the corresponding C AST.
    """

    __slots__ = ("_msg_by_id", "_parsed", "kb", "project")

    def __init__(self, nodes_msg, project=None, kb=None) -> None:
        self._msg_by_id: dict[int, codegen_pb2.CConstructNode] = {n.node_id: n for n in nodes_msg}
        self._parsed: dict[int, Any] = {}
        # Project / KB are used to resolve Function references and similar by-address pointers at parse time.
        self.project = project
        self.kb = kb

    def resolve(self, node_id: int):
        if node_id == 0:
            return None
        if node_id in self._parsed:
            return self._parsed[node_id]
        pb = self._msg_by_id[node_id]
        obj = _PARSERS[pb.kind](pb, self)
        # CConstruct base state
        obj.idx = pb.node_id
        obj.ident = pb.ident
        obj.tags = _parse_tags(pb.tags)
        obj.codegen = None  # back-reference re-attached by set_codegen()
        from .c import CExpression

        if isinstance(obj, CExpression):
            obj.collapsed = bool(pb.collapsed) if pb.HasField("collapsed") else False
            obj._type = _simtype_from_json(pb.expr_type_json) if pb.HasField("expr_type_json") else None
        self._parsed[node_id] = obj
        return obj

    def set_codegen(self, codegen) -> None:
        for node in self._parsed.values():
            node.codegen = codegen


#
# Dispatch tables (populated by register_subclass at the bottom of c.py / by this module)
#

_SERIALIZE_KIND_BY_CLASS: dict[type, int] = {}
_CLASS_BY_KIND: dict[int, type] = {}
_SERIALIZERS: dict[type, Callable[[Any, codegen_pb2.CConstructNode, SerializeContext], None]] = {}
_PARSERS: dict[int, Callable[[codegen_pb2.CConstructNode, ParseContext], Any]] = {}


def _register(cls: type, kind: int, serializer: Callable, parser: Callable) -> None:
    _SERIALIZE_KIND_BY_CLASS[cls] = kind
    _CLASS_BY_KIND[kind] = cls
    _SERIALIZERS[cls] = serializer
    _PARSERS[kind] = parser


#
# Subtree parsing/serialization
#


def serialize_subtree(root: CConstruct) -> bytes:
    """Serialize an AST subtree as a Codegen envelope carrying only the indexed table + root_id. For testing and any
    caller that wants to round-trip a CConstruct without a full codegen object."""
    ctx = SerializeContext()
    root_id = ctx.serialize(root)
    msg = codegen_pb2.Codegen()
    msg.root_id = root_id
    msg.nodes.extend(ctx.nodes)
    return msg.SerializeToString()


def parse_subtree(data: bytes, project=None, kb=None) -> CConstruct | None:
    msg = codegen_pb2.Codegen()
    msg.ParseFromString(data)
    ctx = ParseContext(msg.nodes, project=project, kb=kb)
    return ctx.resolve(msg.root_id)


#
# Position mapping serialization
#


def _serialize_position_mapping(pm, ctx: SerializeContext, out_msg) -> None:
    if pm is None:
        return
    for _, elem in pm.items():
        obj = elem.obj
        if obj is None or type(obj) not in _SERIALIZE_KIND_BY_CLASS:
            continue
        entry = out_msg.entries.add()
        entry.start = elem.start
        entry.length = elem.length
        entry.node_id = ctx.serialize(obj)


def _parse_position_mapping(pm_msg, ctx: ParseContext):
    pm = PositionMapping()
    for entry in pm_msg.entries:
        obj = ctx.resolve(entry.node_id) if entry.node_id != 0 else None
        pm.add_mapping(entry.start, entry.length, obj)
    return pm


def _serialize_instruction_mapping(im, out_msg) -> None:
    if im is None:
        return
    for _, elem in im.items():
        entry = out_msg.entries.add()
        entry.ins_addr = elem.ins_addr
        entry.posmap_pos = elem.posmap_pos


def _parse_instruction_mapping(im_msg):
    from .base import InstructionMapping

    im = InstructionMapping()
    for entry in im_msg.entries:
        im.add_mapping(entry.ins_addr, entry.posmap_pos)
    return im


#
# Codegen serialization
#


def _serialize_notes(notes: dict | None, out_msg) -> None:
    """notes: dict[str, DecompilationNote]. Each DecompilationNote is serialized to JSON."""
    if not notes:
        return
    for k, note in notes.items():
        out_msg[k] = note.to_json()


def _parse_notes(notes_msg):
    from angr.analyses.decompiler.notes import DecompilationNote

    return {k: DecompilationNote.from_json(blob) for k, blob in notes_msg.items()}


def _serialize_const_formats(const_formats: dict | None, out_repeated) -> None:
    """const_formats: dict[IdentType, dict[str, bool]]; IdentType = tuple[int, int, str]."""
    if not const_formats:
        return
    for ident, fmt in const_formats.items():
        entry = out_repeated.add()
        entry.ident_ins_addr = ident[0]
        entry.ident_kind = ident[1]
        entry.ident_value = ident[2]
        for k, v in fmt.items():
            entry.fmt[k] = bool(v)


def _parse_const_formats(entries):
    result = {}
    for entry in entries:
        key = (entry.ident_ins_addr, entry.ident_kind, entry.ident_value)
        result[key] = dict(entry.fmt)
    return result


# Display-option attribute names round-tripped on Codegen. Mirrors the codegen_pb2.Codegen field names where the
# Python attribute and the proto field share the same identifier.
_DISPLAY_OPTION_ATTRS = (
    "indent",
    "show_casts",
    "comment_gotos",
    "braces_on_own_lines",
    "use_compound_assignments",
    "show_local_types",
    "cstyle_null_cmp",
    "show_externs",
    "show_demangled_name",
    "show_disambiguated_name",
    "simplify_else_scope",
    "cstyle_ifs",
    "omit_func_header",
    "display_block_addrs",
    "display_vvar_ids",
    "display_notes",
    "prettify_thiscall",
    "cstyle_void_param",
    "binop_depth_cutoff",
    "min_data_addr",
    "max_str_len",
)


def serialize_codegen(codegen) -> codegen_pb2.Codegen:
    """Build a Codegen cmessage from a live CStructuredCodeGenerator instance."""
    msg = codegen_pb2.Codegen()
    ctx = SerializeContext()

    if codegen.cfunc is not None:
        msg.root_id = ctx.serialize(codegen.cfunc)

    if codegen.text is not None:
        msg.text = codegen.text
    if getattr(codegen, "flavor", None) is not None:
        msg.flavor = codegen.flavor

    _serialize_position_mapping(codegen.map_pos_to_node, ctx, msg.map_pos_to_node)
    _serialize_position_mapping(codegen.map_pos_to_addr, ctx, msg.map_pos_to_addr)
    _serialize_instruction_mapping(codegen.map_addr_to_pos, msg.map_addr_to_pos)
    # map_ast_to_pos is intentionally not serialized. The map is derivable from map_pos_to_node so we rebuild it after
    # parse.
    for (addr, idx), label in (codegen.map_addr_to_label or {}).items():
        entry = msg.map_addr_to_label.add()
        entry.addr = addr
        if idx is not None:
            entry.idx = idx
        entry.label_id = ctx.serialize(label)
    if codegen.cexterns:
        for v in codegen.cexterns:
            msg.cexterns_ids.append(ctx.serialize(v))

    if codegen.expr_comments:
        for k, v in codegen.expr_comments.items():
            msg.expr_comments[k] = v
    if codegen.stmt_comments:
        for k, v in codegen.stmt_comments.items():
            msg.stmt_comments[k] = v
    _serialize_notes(codegen.notes, msg.notes_json)
    _serialize_const_formats(codegen.const_formats, msg.const_formats)

    for attr in _DISPLAY_OPTION_ATTRS:
        if not hasattr(codegen, attr):
            continue
        value = getattr(codegen, attr)
        if value is None:
            continue
        setattr(msg, attr, value)

    # The flat AST node table is filled in by ctx.serialize during the recursive calls above.
    msg.nodes.extend(ctx.nodes)
    return msg


def _rebuild_ast_to_pos(pos_to_node):
    """Mirror of the logic in :meth:`CStructuredCodeGenerator.render_text` that builds ``map_ast_to_pos`` from
    ``pos_to_node``. Used after parse to restore the cross-reference map."""
    ast_to_pos = defaultdict(set)
    if pos_to_node is None:
        return ast_to_pos
    for elem, node in pos_to_node.items():
        obj = node.obj
        if isinstance(obj, CConstant):
            ast_to_pos[obj.value].add(elem)
        elif isinstance(obj, CVariable):
            ast_to_pos[obj.unified_variable if obj.unified_variable is not None else obj.variable].add(elem)
        elif isinstance(obj, CFunctionCall):
            key = obj.callee_func if obj.callee_func is not None else obj.callee_target
            ast_to_pos[key].add(elem)
        elif isinstance(obj, CStructField):
            ast_to_pos[(obj.struct_type, obj.offset)].add(elem)
        else:
            ast_to_pos[obj].add(elem)
    return ast_to_pos


def parse_codegen(msg, *, project=None, kb=None, variable_kb=None, func=None):
    """Materialize a CStructuredCodeGenerator from a Codegen cmessage. Bypasses __init__ since the constructor runs
    the full decompilation pipeline; instead we populate the attributes directly. The parsed instance is suitable for
    display, navigation, and cache-validity checks but is not "live" — methods that re-render or re-run analyses
    require ``project`` / ``func`` / ``variable_kb`` to be reattached."""
    from .c import CStructuredCodeGenerator

    cg = CStructuredCodeGenerator.__new__(CStructuredCodeGenerator)
    ctx = ParseContext(msg.nodes, project=project, kb=kb)

    # Materialize the AST.
    cg.cfunc = ctx.resolve(msg.root_id) if msg.root_id != 0 else None

    # Base / display state.
    cg.text = msg.text if msg.HasField("text") else None
    cg.flavor = msg.flavor if msg.HasField("flavor") else None
    cg.notes = _parse_notes(msg.notes_json)
    cg.expr_comments = dict(msg.expr_comments)
    cg.stmt_comments = dict(msg.stmt_comments)
    cg.const_formats = _parse_const_formats(msg.const_formats)
    cg.ident_counters = {}
    # resume idx allocation past every deserialized node so nodes created later stay unique
    cg._next_node_idx = max((n.node_id for n in msg.nodes), default=0) + 1

    cg.map_pos_to_node = _parse_position_mapping(msg.map_pos_to_node, ctx)
    cg.map_pos_to_addr = _parse_position_mapping(msg.map_pos_to_addr, ctx)
    cg.map_addr_to_pos = _parse_instruction_mapping(msg.map_addr_to_pos)
    # map_ast_to_pos is rebuilt below from map_pos_to_node (see serialize_codegen for why we don't store it directly).
    cg.map_ast_to_pos = _rebuild_ast_to_pos(cg.map_pos_to_node)

    cg.map_addr_to_label = {}
    for entry in msg.map_addr_to_label:
        idx = entry.idx if entry.HasField("idx") else None
        cg.map_addr_to_label[(entry.addr, idx)] = ctx.resolve(entry.label_id)

    cg.cexterns = {ctx.resolve(i) for i in msg.cexterns_ids} if msg.cexterns_ids else None

    # Display options: only set those present in the cmessage.
    for attr in _DISPLAY_OPTION_ATTRS:
        if msg.HasField(attr):
            setattr(cg, "_indent" if attr == "indent" else attr, getattr(msg, attr))

    # Runtime / back-reference state — caller-provided.
    cg._func = func
    cg._func_args = None
    cg._cfg = None
    cg._sequence = None
    cg._variable_kb = variable_kb
    cg.externs = set()
    cg._variables_in_use = None
    cg._inlined_strings = set()
    cg._function_pointers = set()
    cg.ailexpr2cnode = None
    cg.cnode2ailexpr = None
    cg._handlers = None  # callers that want to re-render should construct a fresh CStructuredCodeGenerator
    # The CFunction holds a back-reference to its variable_manager. variable_kb is the source.
    if cg.cfunc is not None:
        cg.cfunc.variable_manager = variable_kb.variables if variable_kb is not None else None

    # Re-attach codegen back-references on every AST node.
    ctx.set_codegen(cg)
    return cg


def register_all() -> None:
    """Registers serializer/parser pairs for every concrete CConstruct subclass. Called from c.py at import time."""
    # Imports are deferred to avoid circular import at module load.
    from . import c as cmod

    # -----------------------------------------------------------------------------------------------------------------
    # Trivial subclasses (no payload beyond base fields).
    # -----------------------------------------------------------------------------------------------------------------

    def _ser_cbreak(node, pb, ctx):
        pb.cbreak.SetInParent()

    def _parse_cbreak(pb, ctx):
        return cmod.CBreak.__new__(cmod.CBreak)

    _register(cmod.CBreak, codegen_pb2.CCK_BREAK, _ser_cbreak, _parse_cbreak)

    def _ser_ccontinue(node, pb, ctx):
        pb.ccontinue.SetInParent()

    def _parse_ccontinue(pb, ctx):
        return cmod.CContinue.__new__(cmod.CContinue)

    _register(cmod.CContinue, codegen_pb2.CCK_CONTINUE, _ser_ccontinue, _parse_ccontinue)

    # -----------------------------------------------------------------------------------------------------------------
    # Plain-primitive subclasses.
    # -----------------------------------------------------------------------------------------------------------------

    def _ser_clabel(node, pb, ctx):
        pb.clabel.name = node.name

    def _parse_clabel(pb, ctx):
        obj = cmod.CLabel.__new__(cmod.CLabel)
        obj.name = pb.clabel.name
        return obj

    _register(cmod.CLabel, codegen_pb2.CCK_LABEL, _ser_clabel, _parse_clabel)

    def _ser_cregister(node, pb, ctx):
        pb.creg.reg = node.reg

    def _parse_cregister(pb, ctx):
        obj = cmod.CRegister.__new__(cmod.CRegister)
        obj.reg = pb.creg.reg
        return obj

    _register(cmod.CRegister, codegen_pb2.CCK_REGISTER, _ser_cregister, _parse_cregister)

    # -----------------------------------------------------------------------------------------------------------------
    # Simple statements (children-only).
    # -----------------------------------------------------------------------------------------------------------------

    def _ser_cstatements(node, pb, ctx):
        for stmt in node.statements:
            pb.cstatements.statements_ids.append(ctx.serialize(stmt))
        if node.addr is not None:
            pb.cstatements.addr = node.addr

    def _parse_cstatements(pb, ctx):
        obj = cmod.CStatements.__new__(cmod.CStatements)
        obj.statements = [ctx.resolve(i) for i in pb.cstatements.statements_ids]
        obj.addr = pb.cstatements.addr if pb.cstatements.HasField("addr") else None
        return obj

    _register(cmod.CStatements, codegen_pb2.CCK_STATEMENTS, _ser_cstatements, _parse_cstatements)

    def _ser_cassignment(node, pb, ctx):
        pb.cassignment.lhs_id = ctx.serialize(node.lhs)
        pb.cassignment.rhs_id = ctx.serialize(node.rhs)

    def _parse_cassignment(pb, ctx):
        obj = cmod.CAssignment.__new__(cmod.CAssignment)
        obj.lhs = ctx.resolve(pb.cassignment.lhs_id)
        obj.rhs = ctx.resolve(pb.cassignment.rhs_id)
        return obj

    _register(cmod.CAssignment, codegen_pb2.CCK_ASSIGNMENT, _ser_cassignment, _parse_cassignment)

    def _ser_cexprstmt(node, pb, ctx):
        pb.cexpression_stmt.expr_id = ctx.serialize(node.expr)
        pb.cexpression_stmt.returning = node.returning

    def _parse_cexprstmt(pb, ctx):
        obj = cmod.CExpressionStatement.__new__(cmod.CExpressionStatement)
        obj.expr = ctx.resolve(pb.cexpression_stmt.expr_id)
        obj.returning = pb.cexpression_stmt.returning
        return obj

    _register(cmod.CExpressionStatement, codegen_pb2.CCK_EXPRESSION_STATEMENT, _ser_cexprstmt, _parse_cexprstmt)

    def _ser_creturn(node, pb, ctx):
        if node.retval is not None:
            pb.creturn.retval_id = ctx.serialize(node.retval)

    def _parse_creturn(pb, ctx):
        obj = cmod.CReturn.__new__(cmod.CReturn)
        obj.retval = ctx.resolve(pb.creturn.retval_id) if pb.creturn.HasField("retval_id") else None
        return obj

    _register(cmod.CReturn, codegen_pb2.CCK_RETURN, _ser_creturn, _parse_creturn)

    def _ser_cifbreak(node, pb, ctx):
        pb.cifbreak.condition_id = ctx.serialize(node.condition)
        pb.cifbreak.cstyle_ifs = node.cstyle_ifs

    def _parse_cifbreak(pb, ctx):
        obj = cmod.CIfBreak.__new__(cmod.CIfBreak)
        obj.condition = ctx.resolve(pb.cifbreak.condition_id)
        obj.cstyle_ifs = pb.cifbreak.cstyle_ifs
        return obj

    _register(cmod.CIfBreak, codegen_pb2.CCK_IF_BREAK, _ser_cifbreak, _parse_cifbreak)

    def _ser_cdirtystmt(node, pb, ctx):
        pb.cdirty_stmt.dirty_id = ctx.serialize(node.dirty)

    def _parse_cdirtystmt(pb, ctx):
        obj = cmod.CDirtyStatement.__new__(cmod.CDirtyStatement)
        obj.dirty = ctx.resolve(pb.cdirty_stmt.dirty_id)
        return obj

    _register(cmod.CDirtyStatement, codegen_pb2.CCK_DIRTY_STATEMENT, _ser_cdirtystmt, _parse_cdirtystmt)

    # -----------------------------------------------------------------------------------------------------------------
    # Loop family.
    # -----------------------------------------------------------------------------------------------------------------

    def _ser_cwhile(node, pb, ctx):
        if node.condition is not None:
            pb.cwhile.condition_id = ctx.serialize(node.condition)
        if node.body is not None:
            pb.cwhile.body_id = ctx.serialize(node.body)

    def _parse_cwhile(pb, ctx):
        obj = cmod.CWhileLoop.__new__(cmod.CWhileLoop)
        obj.condition = ctx.resolve(pb.cwhile.condition_id) if pb.cwhile.HasField("condition_id") else None
        obj.body = ctx.resolve(pb.cwhile.body_id) if pb.cwhile.HasField("body_id") else None
        return obj

    _register(cmod.CWhileLoop, codegen_pb2.CCK_WHILE_LOOP, _ser_cwhile, _parse_cwhile)

    def _ser_cdowhile(node, pb, ctx):
        if node.condition is not None:
            pb.cdowhile.condition_id = ctx.serialize(node.condition)
        if node.body is not None:
            pb.cdowhile.body_id = ctx.serialize(node.body)

    def _parse_cdowhile(pb, ctx):
        obj = cmod.CDoWhileLoop.__new__(cmod.CDoWhileLoop)
        obj.condition = ctx.resolve(pb.cdowhile.condition_id) if pb.cdowhile.HasField("condition_id") else None
        obj.body = ctx.resolve(pb.cdowhile.body_id) if pb.cdowhile.HasField("body_id") else None
        return obj

    _register(cmod.CDoWhileLoop, codegen_pb2.CCK_DO_WHILE_LOOP, _ser_cdowhile, _parse_cdowhile)

    def _ser_cfor(node, pb, ctx):
        if node.initializer is not None:
            pb.cfor.initializer_id = ctx.serialize(node.initializer)
        if node.condition is not None:
            pb.cfor.condition_id = ctx.serialize(node.condition)
        if node.iterator is not None:
            pb.cfor.iterator_id = ctx.serialize(node.iterator)
        if node.body is not None:
            pb.cfor.body_id = ctx.serialize(node.body)

    def _parse_cfor(pb, ctx):
        obj = cmod.CForLoop.__new__(cmod.CForLoop)
        body = pb.cfor
        obj.initializer = ctx.resolve(body.initializer_id) if body.HasField("initializer_id") else None
        obj.condition = ctx.resolve(body.condition_id) if body.HasField("condition_id") else None
        obj.iterator = ctx.resolve(body.iterator_id) if body.HasField("iterator_id") else None
        obj.body = ctx.resolve(body.body_id) if body.HasField("body_id") else None
        return obj

    _register(cmod.CForLoop, codegen_pb2.CCK_FOR_LOOP, _ser_cfor, _parse_cfor)

    # -----------------------------------------------------------------------------------------------------------------
    # If / switch / goto / label.
    # -----------------------------------------------------------------------------------------------------------------

    def _ser_cifelse(node, pb, ctx):
        for cond, stmt in node.condition_and_nodes:
            entry = pb.cifelse.condition_and_nodes.add()
            entry.condition_id = ctx.serialize(cond)
            if stmt is not None:
                entry.statement_id = ctx.serialize(stmt)
        if node.else_node is not None:
            pb.cifelse.else_node_id = ctx.serialize(node.else_node)
        pb.cifelse.simplify_else_scope = node.simplify_else_scope
        pb.cifelse.cstyle_ifs = node.cstyle_ifs

    def _parse_cifelse(pb, ctx):
        obj = cmod.CIfElse.__new__(cmod.CIfElse)
        body = pb.cifelse
        obj.condition_and_nodes = [
            (ctx.resolve(e.condition_id), ctx.resolve(e.statement_id) if e.HasField("statement_id") else None)
            for e in body.condition_and_nodes
        ]
        obj.else_node = ctx.resolve(body.else_node_id) if body.HasField("else_node_id") else None
        obj.simplify_else_scope = body.simplify_else_scope
        obj.cstyle_ifs = body.cstyle_ifs
        return obj

    _register(cmod.CIfElse, codegen_pb2.CCK_IF_ELSE, _ser_cifelse, _parse_cifelse)

    def _ser_cswitch(node, pb, ctx):
        pb.cswitch.switch_id = ctx.serialize(node.switch)
        for case_ids, stmts in node.cases:
            entry = pb.cswitch.cases.add()
            if isinstance(case_ids, tuple):
                entry.case_ids.extend(case_ids)
            else:
                entry.case_ids.append(case_ids)
            entry.statements_id = ctx.serialize(stmts)
        if node.default is not None:
            pb.cswitch.default_id = ctx.serialize(node.default)

    def _parse_cswitch(pb, ctx):
        obj = cmod.CSwitchCase.__new__(cmod.CSwitchCase)
        body = pb.cswitch
        obj.switch = ctx.resolve(body.switch_id)
        obj.cases = [
            (tuple(e.case_ids) if len(e.case_ids) > 1 else e.case_ids[0], ctx.resolve(e.statements_id))
            for e in body.cases
        ]
        obj.default = ctx.resolve(body.default_id) if body.HasField("default_id") else None
        return obj

    _register(cmod.CSwitchCase, codegen_pb2.CCK_SWITCH_CASE, _ser_cswitch, _parse_cswitch)

    def _ser_cincomplete_switch(node, pb, ctx):
        pb.cincomplete_switch.head_id = ctx.serialize(node.head)
        for case_addr, stmts in node.cases:
            entry = pb.cincomplete_switch.cases.add()
            entry.case_addr = case_addr
            entry.statements_id = ctx.serialize(stmts)

    def _parse_cincomplete_switch(pb, ctx):
        obj = cmod.CIncompleteSwitchCase.__new__(cmod.CIncompleteSwitchCase)
        body = pb.cincomplete_switch
        obj.head = ctx.resolve(body.head_id)
        obj.cases = [(e.case_addr, ctx.resolve(e.statements_id)) for e in body.cases]
        return obj

    _register(
        cmod.CIncompleteSwitchCase,
        codegen_pb2.CCK_INCOMPLETE_SWITCH_CASE,
        _ser_cincomplete_switch,
        _parse_cincomplete_switch,
    )

    def _ser_cgoto(node, pb, ctx):
        if isinstance(node.target, int):
            pb.cgoto.target_int = node.target
        else:
            pb.cgoto.target_expr_id = ctx.serialize(node.target)
        if node.target_idx is not None:
            pb.cgoto.target_idx = node.target_idx

    def _parse_cgoto(pb, ctx):
        obj = cmod.CGoto.__new__(cmod.CGoto)
        which = pb.cgoto.WhichOneof("target")
        if which == "target_int":
            obj.target = pb.cgoto.target_int
        elif which == "target_expr_id":
            obj.target = ctx.resolve(pb.cgoto.target_expr_id)
        else:
            obj.target = None  # should not happen but be defensive
        obj.target_idx = pb.cgoto.target_idx if pb.cgoto.HasField("target_idx") else None
        return obj

    _register(cmod.CGoto, codegen_pb2.CCK_GOTO, _ser_cgoto, _parse_cgoto)

    # -----------------------------------------------------------------------------------------------------------------
    # Expressions.
    # -----------------------------------------------------------------------------------------------------------------

    def _ser_cunop(node, pb, ctx):
        pb.cunop.op = node.op
        pb.cunop.operand_id = ctx.serialize(node.operand)

    def _parse_cunop(pb, ctx):
        obj = cmod.CUnaryOp.__new__(cmod.CUnaryOp)
        obj.op = pb.cunop.op
        obj.operand = ctx.resolve(pb.cunop.operand_id)
        return obj

    _register(cmod.CUnaryOp, codegen_pb2.CCK_UNARY_OP, _ser_cunop, _parse_cunop)

    def _ser_cbinop(node, pb, ctx):
        pb.cbinop.op = node.op
        pb.cbinop.lhs_id = ctx.serialize(node.lhs)
        pb.cbinop.rhs_id = ctx.serialize(node.rhs)
        pb.cbinop.common_type_json = _simtype_to_json(node.common_type)

    def _parse_cbinop(pb, ctx):
        obj = cmod.CBinaryOp.__new__(cmod.CBinaryOp)
        obj.op = pb.cbinop.op
        obj.lhs = ctx.resolve(pb.cbinop.lhs_id)
        obj.rhs = ctx.resolve(pb.cbinop.rhs_id)
        obj.common_type = _simtype_from_json(pb.cbinop.common_type_json)
        obj._cstyle_null_cmp = False  # rebuilt from codegen flags after set_codegen; safe default
        return obj

    _register(cmod.CBinaryOp, codegen_pb2.CCK_BINARY_OP, _ser_cbinop, _parse_cbinop)

    def _ser_ctypecast(node, pb, ctx):
        pb.ctypecast.src_type_json = _simtype_to_json(node.src_type)
        pb.ctypecast.dst_type_json = _simtype_to_json(node.dst_type)
        pb.ctypecast.expr_id = ctx.serialize(node.expr)

    def _parse_ctypecast(pb, ctx):
        obj = cmod.CTypeCast.__new__(cmod.CTypeCast)
        obj.src_type = _simtype_from_json(pb.ctypecast.src_type_json)
        obj.dst_type = _simtype_from_json(pb.ctypecast.dst_type_json)
        obj.expr = ctx.resolve(pb.ctypecast.expr_id)
        return obj

    _register(cmod.CTypeCast, codegen_pb2.CCK_TYPE_CAST, _ser_ctypecast, _parse_ctypecast)

    def _ser_cite(node, pb, ctx):
        pb.cite.cond_id = ctx.serialize(node.cond)
        pb.cite.iftrue_id = ctx.serialize(node.iftrue)
        pb.cite.iffalse_id = ctx.serialize(node.iffalse)

    def _parse_cite(pb, ctx):
        obj = cmod.CITE.__new__(cmod.CITE)
        obj.cond = ctx.resolve(pb.cite.cond_id)
        obj.iftrue = ctx.resolve(pb.cite.iftrue_id)
        obj.iffalse = ctx.resolve(pb.cite.iffalse_id)
        return obj

    _register(cmod.CITE, codegen_pb2.CCK_ITE, _ser_cite, _parse_cite)

    def _ser_cmulti(node, pb, ctx):
        pb.cmulti_stmt_expr.stmts_id = ctx.serialize(node.stmts)
        pb.cmulti_stmt_expr.expr_id = ctx.serialize(node.expr)

    def _parse_cmulti(pb, ctx):
        obj = cmod.CMultiStatementExpression.__new__(cmod.CMultiStatementExpression)
        obj.stmts = ctx.resolve(pb.cmulti_stmt_expr.stmts_id)
        obj.expr = ctx.resolve(pb.cmulti_stmt_expr.expr_id)
        return obj

    _register(cmod.CMultiStatementExpression, codegen_pb2.CCK_MULTI_STATEMENT_EXPRESSION, _ser_cmulti, _parse_cmulti)

    def _ser_cvex(node, pb, ctx):
        pb.cvex_ccall.callee = node.callee
        for op in node.operands:
            pb.cvex_ccall.operands_ids.append(ctx.serialize(op))

    def _parse_cvex(pb, ctx):
        obj = cmod.CVEXCCallExpression.__new__(cmod.CVEXCCallExpression)
        obj.callee = pb.cvex_ccall.callee
        obj.operands = [ctx.resolve(i) for i in pb.cvex_ccall.operands_ids]
        return obj

    _register(cmod.CVEXCCallExpression, codegen_pb2.CCK_VEX_CCALL_EXPRESSION, _ser_cvex, _parse_cvex)

    # -----------------------------------------------------------------------------------------------------------------
    # Variables and structs.
    # -----------------------------------------------------------------------------------------------------------------

    def _ser_cstructfield(node, pb, ctx):
        pb.cstruct_field.struct_type_json = _simtype_to_json(node.struct_type)
        pb.cstruct_field.offset = node.offset
        pb.cstruct_field.field = node.field

    def _parse_cstructfield(pb, ctx):
        obj = cmod.CStructField.__new__(cmod.CStructField)
        obj.struct_type = _simtype_from_json(pb.cstruct_field.struct_type_json)
        obj.offset = pb.cstruct_field.offset
        obj.field = pb.cstruct_field.field
        return obj

    _register(cmod.CStructField, codegen_pb2.CCK_STRUCT_FIELD, _ser_cstructfield, _parse_cstructfield)

    def _ser_cfakevar(node, pb, ctx):
        pb.cfake_var.name = node.name
        ty = getattr(node, "_type", None)
        if ty is not None:
            pb.cfake_var.type_json = _simtype_to_json(ty)

    def _parse_cfakevar(pb, ctx):
        obj = cmod.CFakeVariable.__new__(cmod.CFakeVariable)
        obj.name = pb.cfake_var.name
        # _type is restored by ParseContext.resolve via expr_type_json on the wrapper; CFakeVariable also has _type
        # in __slots__, set there too if present in body.
        if pb.cfake_var.HasField("type_json"):
            obj._type = _simtype_from_json(pb.cfake_var.type_json)
        return obj

    _register(cmod.CFakeVariable, codegen_pb2.CCK_FAKE_VARIABLE, _ser_cfakevar, _parse_cfakevar)

    def _ser_cvar(node, pb, ctx):
        pb.cvar.variable = _simvar_to_bytes(node.variable)
        if node.unified_variable is not None:
            pb.cvar.unified_variable = _simvar_to_bytes(node.unified_variable)
        if node.variable_type is not None:
            pb.cvar.variable_type_json = _simtype_to_json(node.variable_type)
        if node.vvar_id is not None:
            pb.cvar.vvar_id = node.vvar_id

    def _parse_cvar(pb, ctx):
        obj = cmod.CVariable.__new__(cmod.CVariable)
        body = pb.cvar
        obj.variable = _simvar_from_bytes(body.variable)
        obj.unified_variable = _simvar_from_bytes(body.unified_variable) if body.HasField("unified_variable") else None
        obj.variable_type = _simtype_from_json(body.variable_type_json) if body.HasField("variable_type_json") else None
        obj.vvar_id = body.vvar_id if body.HasField("vvar_id") else None
        return obj

    _register(cmod.CVariable, codegen_pb2.CCK_VARIABLE, _ser_cvar, _parse_cvar)

    def _ser_cidxvar(node, pb, ctx):
        pb.cindexed_var.variable_id = ctx.serialize(node.variable)
        pb.cindexed_var.index_id = ctx.serialize(node.index)
        ty = getattr(node, "_type", None)
        if ty is not None:
            pb.cindexed_var.type_json = _simtype_to_json(ty)

    def _parse_cidxvar(pb, ctx):
        obj = cmod.CIndexedVariable.__new__(cmod.CIndexedVariable)
        body = pb.cindexed_var
        obj.variable = ctx.resolve(body.variable_id)
        obj.index = ctx.resolve(body.index_id)
        if body.HasField("type_json"):
            obj._type = _simtype_from_json(body.type_json)
        return obj

    _register(cmod.CIndexedVariable, codegen_pb2.CCK_INDEXED_VARIABLE, _ser_cidxvar, _parse_cidxvar)

    def _ser_cvarfield(node, pb, ctx):
        pb.cvar_field.variable_id = ctx.serialize(node.variable)
        pb.cvar_field.field_id = ctx.serialize(node.field)
        pb.cvar_field.var_is_ptr = node.var_is_ptr

    def _parse_cvarfield(pb, ctx):
        obj = cmod.CVariableField.__new__(cmod.CVariableField)
        body = pb.cvar_field
        obj.variable = ctx.resolve(body.variable_id)
        obj.field = ctx.resolve(body.field_id)
        obj.var_is_ptr = body.var_is_ptr
        return obj

    _register(cmod.CVariableField, codegen_pb2.CCK_VARIABLE_FIELD, _ser_cvarfield, _parse_cvarfield)

    # -----------------------------------------------------------------------------------------------------------------
    # CConstant (heterogeneous value + reference_values).
    # -----------------------------------------------------------------------------------------------------------------

    def _ser_cconst(node, pb, ctx):
        body = pb.cconst
        if isinstance(node.value, bool):
            body.int_value = int(node.value)
        elif isinstance(node.value, int):
            body.int_value = node.value
        elif isinstance(node.value, float):
            body.float_value = node.value
        elif isinstance(node.value, str):
            body.str_value = node.value
        body.type_json = _simtype_to_json(node._type)
        if node.reference_values:
            from angr.knowledge_plugins.cfg.memory_data import MemoryData

            for ty, val in node.reference_values.items():
                entry = body.reference_values.add()
                entry.type_json = _simtype_to_json(ty)
                if isinstance(val, bool):
                    entry.int_value = int(val)
                elif isinstance(val, int):
                    entry.int_value = val
                elif isinstance(val, bytes):
                    entry.raw_bytes = val
                elif isinstance(val, str):
                    entry.str_value = val
                elif isinstance(val, MemoryData):
                    entry.memory_data = val.serialize()
                # other types intentionally dropped

    def _parse_cconst(pb, ctx):
        from angr.knowledge_plugins.cfg.memory_data import MemoryData

        obj = cmod.CConstant.__new__(cmod.CConstant)
        body = pb.cconst
        which = body.WhichOneof("value")
        if which == "int_value":
            obj.value = body.int_value
        elif which == "float_value":
            obj.value = body.float_value
        elif which == "str_value":
            obj.value = body.str_value
        else:
            obj.value = None
        obj._type = _simtype_from_json(body.type_json)
        if body.reference_values:
            refs = {}
            for entry in body.reference_values:
                key = _simtype_from_json(entry.type_json)
                w = entry.WhichOneof("value")
                if w == "int_value":
                    refs[key] = entry.int_value
                elif w == "raw_bytes":
                    refs[key] = entry.raw_bytes
                elif w == "str_value":
                    refs[key] = entry.str_value
                elif w == "memory_data":
                    refs[key] = MemoryData.parse(entry.memory_data)
            obj.reference_values = refs
        else:
            obj.reference_values = None
        return obj

    _register(cmod.CConstant, codegen_pb2.CCK_CONSTANT, _ser_cconst, _parse_cconst)

    # -----------------------------------------------------------------------------------------------------------------
    # CFunctionCall (oneof callee_target + callee_func reference).
    # -----------------------------------------------------------------------------------------------------------------

    def _ser_cfuncall(node, pb, ctx):
        body = pb.cfuncall
        target = node.callee_target
        if isinstance(target, int):
            body.callee_target_int = target
        elif isinstance(target, str):
            body.callee_target_str = target
        else:
            body.callee_target_expr_id = ctx.serialize(target)
        if node.callee_func is not None:
            body.callee_func_addr = node.callee_func.addr
        for a in node.args:
            body.args_ids.append(ctx.serialize(a))
        body.show_demangled_name = node.show_demangled_name
        body.show_disambiguated_name = node.show_disambiguated_name

    def _parse_cfuncall(pb, ctx):
        obj = cmod.CFunctionCall.__new__(cmod.CFunctionCall)
        body = pb.cfuncall
        which = body.WhichOneof("callee_target")
        if which == "callee_target_int":
            obj.callee_target = body.callee_target_int
        elif which == "callee_target_str":
            obj.callee_target = body.callee_target_str
        elif which == "callee_target_expr_id":
            obj.callee_target = ctx.resolve(body.callee_target_expr_id)
        else:
            obj.callee_target = None
        if body.HasField("callee_func_addr") and ctx.kb is not None:
            obj.callee_func = ctx.kb.functions.function(body.callee_func_addr)
        else:
            obj.callee_func = None
        obj.args = [ctx.resolve(i) for i in body.args_ids]
        obj.show_demangled_name = body.show_demangled_name
        obj.show_disambiguated_name = body.show_disambiguated_name
        return obj

    _register(cmod.CFunctionCall, codegen_pb2.CCK_FUNCTION_CALL, _ser_cfuncall, _parse_cfuncall)

    # -----------------------------------------------------------------------------------------------------------------
    # CFunction (the AST root).
    # -----------------------------------------------------------------------------------------------------------------

    def _ser_cfunction(node, pb, ctx):
        body = pb.cfunction
        if node.addr is not None:
            body.addr = node.addr
        body.name = node.name
        body.functy_json = _simtype_to_json(node.functy)
        for arg in node.arg_list:
            body.arg_list_ids.append(ctx.serialize(arg))
        body.statements_id = ctx.serialize(node.statements)
        for simvar, cvar in node.variables_in_use.items():
            entry = body.variables_in_use.add()
            entry.simvariable = _simvar_to_bytes(simvar)
            entry.cvariable_id = ctx.serialize(cvar)
        if node.demangled_name is not None:
            body.demangled_name = node.demangled_name
        body.show_demangled_name = node.show_demangled_name
        body.omit_header = node.omit_header

    def _parse_cfunction(pb, ctx):
        obj = cmod.CFunction.__new__(cmod.CFunction)
        body = pb.cfunction
        obj.addr = body.addr if body.HasField("addr") else None
        obj.name = body.name
        obj.functy = _simtype_from_json(body.functy_json)
        obj.arg_list = [ctx.resolve(i) for i in body.arg_list_ids]
        obj.statements = ctx.resolve(body.statements_id)
        obj.variables_in_use = {
            _simvar_from_bytes(e.simvariable): ctx.resolve(e.cvariable_id) for e in body.variables_in_use
        }
        obj.demangled_name = body.demangled_name if body.HasField("demangled_name") else None
        obj.show_demangled_name = body.show_demangled_name
        obj.omit_header = body.omit_header
        # variable_manager is attached by the codegen wrapper at parse time; unified_local_vars is recomputed via
        # refresh() once codegen + variable_manager are wired up.
        obj.variable_manager = None
        obj.unified_local_vars = {}
        return obj

    _register(cmod.CFunction, codegen_pb2.CCK_FUNCTION, _ser_cfunction, _parse_cfunction)

    # -----------------------------------------------------------------------------------------------------------------
    # Ailment-coupled subclasses (native AIL to_bytes payloads).
    # -----------------------------------------------------------------------------------------------------------------
    from angr.rustylib.ailment import Block as AilBlock
    from angr.rustylib.ailment import Expression as AilExpression
    from angr.rustylib.ailment import Statement as AilStatement

    def _ser_cailblock(node, pb, ctx):
        pb.cailblock.block = node.block.to_bytes()

    def _parse_cailblock(pb, ctx):
        obj = cmod.CAILBlock.__new__(cmod.CAILBlock)
        obj.block = AilBlock.from_bytes(pb.cailblock.block)
        return obj

    _register(cmod.CAILBlock, codegen_pb2.CCK_AIL_BLOCK, _ser_cailblock, _parse_cailblock)

    def _ser_cunsupported(node, pb, ctx):
        pb.cunsupported.stmt = node.stmt.to_bytes()

    def _parse_cunsupported(pb, ctx):
        obj = cmod.CUnsupportedStatement.__new__(cmod.CUnsupportedStatement)
        obj.stmt = AilStatement.from_bytes(pb.cunsupported.stmt)
        return obj

    _register(cmod.CUnsupportedStatement, codegen_pb2.CCK_UNSUPPORTED_STATEMENT, _ser_cunsupported, _parse_cunsupported)

    def _ser_cdirtyexpr(node, pb, ctx):
        pb.cdirty_expr.dirty = node.dirty.to_bytes()

    def _parse_cdirtyexpr(pb, ctx):
        obj = cmod.CDirtyExpression.__new__(cmod.CDirtyExpression)
        obj.dirty = AilExpression.from_bytes(pb.cdirty_expr.dirty)
        return obj

    _register(cmod.CDirtyExpression, codegen_pb2.CCK_DIRTY_EXPRESSION, _ser_cdirtyexpr, _parse_cdirtyexpr)
