"""
Protobuf serialization for the Rust AST defined in :mod:`rust`.

Same flat indexed node table as :mod:`c_serialize`, and the same ``Codegen`` envelope: ``Codegen.flavor`` says which
class family a node table belongs to, and every node kind names both a C class and its Rust counterpart. Rust nodes
carry no ``idx``/``ident`` of their own, so node ids are assigned here (by object identity) instead of read off the
node.
"""
# pylint:disable=no-member,protected-access

from __future__ import annotations

import inspect
import zlib
from collections import OrderedDict, defaultdict
from collections.abc import Callable
from functools import cache
from typing import Any

from angr.ailment.expression import Convert as AilConvert
from angr.ailment.expression import Let as AilLet
from angr.analyses.decompiler.variable_map import VariableMap
from angr.protos import codegen_pb2
from angr.rust.sim_type import EnumVariant
from angr.rustylib.ailment import Block as AilBlock
from angr.rustylib.ailment import Expression as AilExpression
from angr.rustylib.ailment import Statement as AilStatement

from . import c_serialize
from .c_serialize import (
    ParseContext,
    SerializeContext,
    _parse_const_formats,
    _parse_notes,
    _serialize_const_formats,
    _serialize_instruction_mapping,
    _serialize_notes,
    _serialize_position_mappings,
)
from .rust import (
    INDENT_DELTA,
    RustAILBlock,
    RustArray,
    RustAssignment,
    RustBinaryOp,
    RustBreak,
    RustConstant,
    RustContinue,
    RustDirtyExpression,
    RustDirtyStatement,
    RustDoWhileLoop,
    RustEnum,
    RustExpression,
    RustFakeVariable,
    RustForLoop,
    RustFunction,
    RustFunctionCall,
    RustFunctionLikeMacro,
    RustGoto,
    RustIfBreak,
    RustIfElse,
    RustIfLet,
    RustIncompleteSwitchCase,
    RustIndexedVariable,
    RustInfiniteLoop,
    RustITE,
    RustLabel,
    RustLet,
    RustMultiStatementExpression,
    RustPatternMatch,
    RustRegister,
    RustReturn,
    RustStatements,
    RustStringLiteral,
    RustStruct,
    RustStructField,
    RustStructuredCodeGenerator,
    RustSwitchCase,
    RustTypeCast,
    RustUnaryOp,
    RustUnsupportedStatement,
    RustVariable,
    RustVariableField,
    RustVectorConvert,
    RustVEXCCallExpression,
    RustWhileLoop,
)

# ---------------------------------------------------------------------------------------------------------------------
# Dispatch tables
# ---------------------------------------------------------------------------------------------------------------------

# kind -> class and kind -> parser, for the Rust family. The class -> kind and class -> serializer directions live in
# the shared tables in c_serialize (class keys are unique across both families).
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


class RustSerializeContext(SerializeContext):
    """Assigns node ids by object identity: Rust nodes have no idx of their own."""

    __slots__ = ("_ids",)

    def __init__(self) -> None:
        super().__init__()
        self._ids: dict[int, int] = {}  # id(node) -> node_id

    def node_id(self, node) -> int:
        nid = self._ids.get(id(node))
        if nid is None:
            nid = len(self._ids) + 1  # 0 is the "absent" sentinel
            self._ids[id(node)] = nid
        return nid

    def write_base_fields(self, node, pb) -> None:
        # getattr: RustLet and RustStringLiteral declare the tags slot but never assign it.
        tags = getattr(node, "tags", None) if _accepts_tags(type(node)) else None
        pb.tags_ref = self.intern_tags(tags)
        if isinstance(node, RustExpression):
            pb.collapsed = bool(node.collapsed)
            if node._type is not None:
                pb.expr_type_ref = self.intern_type(node._type)

    def intern_variant(self, variant: EnumVariant, msg) -> None:
        msg.name = variant.name
        for field_ty, field_name in variant.fields:
            entry = msg.fields.add()
            entry.type_ref = self.intern_type(field_ty)
            if field_name is not None:
                entry.name = field_name
        if variant.discriminant is not None:
            msg.discriminant = variant.discriminant
        if variant.discriminant_size is not None:
            msg.discriminant_size = variant.discriminant_size

    def write_pattern(self, pattern, msg) -> None:
        variant, bound = pattern
        self.intern_variant(variant, msg.variant)
        for expr in bound:
            msg.bound_ids.append(self.serialize(expr))


class RustParseContext(ParseContext):
    """Parses a Rust node table. Rust nodes have no idx/ident to restore."""

    __slots__ = ()

    def parser_for(self, kind: int):
        return _PARSERS[kind]

    def apply_base_state(self, obj, pb) -> None:
        if _accepts_tags(type(obj)):
            obj.tags = self.resolve_tags(pb.tags_ref)
        if isinstance(obj, RustExpression):
            obj.collapsed = bool(pb.collapsed) if pb.HasField("collapsed") else False
            obj._type = self.resolve_type(pb.expr_type_ref)

    def set_codegen(self, codegen) -> None:
        for node in self._parsed.values():
            node.codegen = codegen
            if isinstance(node, RustBinaryOp):
                node._cstyle_null_cmp = codegen.cstyle_null_cmp

    def resolve_variant(self, msg) -> EnumVariant:
        fields = [(self.resolve_type(e.type_ref), e.name if e.HasField("name") else None) for e in msg.fields]
        return EnumVariant(
            msg.name,
            fields,
            msg.discriminant if msg.HasField("discriminant") else None,
            msg.discriminant_size if msg.HasField("discriminant_size") else None,
        )

    def resolve_pattern(self, msg):
        return (self.resolve_variant(msg.variant), tuple(self.resolve(i) for i in msg.bound_ids))


@cache
def _accepts_tags(cls: type) -> bool:
    """Whether instances of ``cls`` can hold tags: the slot is declared somewhere in the MRO, or instances have a
    __dict__. Asking the class rather than the instance matters on both sides: a few Rust classes declare the slot
    without ever assigning it, and a node under construction has not been assigned one yet."""
    if any("tags" in (getattr(k, "__slots__", ()) or ()) for k in cls.__mro__):
        return True
    return any("__dict__" in vars(k) for k in cls.__mro__)


# ---------------------------------------------------------------------------------------------------------------------
# Codegen envelope
# ---------------------------------------------------------------------------------------------------------------------

_CODEGEN_CTOR_DEFAULTS = {
    name: param.default
    for name, param in inspect.signature(RustStructuredCodeGenerator.__init__).parameters.items()
    if param.default is not inspect.Parameter.empty
}
# The Rust generator accepts stl_accessor_calls so that the shared decompilation options apply to both flavors, but
# it has no C++ STL field accesses to name and never stores the option. Restoring a default for it would invent an
# attribute a live generator does not have.
_UNSTORED_DISPLAY_OPTIONS = frozenset({"stl_accessor_calls"})
_DISPLAY_OPTION_ATTRS = tuple(a for a in c_serialize._DISPLAY_OPTION_ATTRS if a not in _UNSTORED_DISPLAY_OPTIONS)
_DISPLAY_OPTION_DEFAULTS = {
    attr: _CODEGEN_CTOR_DEFAULTS[attr] for attr in _DISPLAY_OPTION_ATTRS if attr in _CODEGEN_CTOR_DEFAULTS
}


def serialize_codegen(codegen) -> codegen_pb2.Codegen:
    """Build a Codegen cmessage from a live RustStructuredCodeGenerator instance."""
    msg = codegen_pb2.Codegen()
    ctx = RustSerializeContext()

    if codegen.rust_func is not None:
        msg.root_id = ctx.serialize(codegen.rust_func)

    if codegen.text is not None:
        msg.text_z = zlib.compress(codegen.text.encode("utf-8"))
    msg.flavor = codegen.flavor if codegen.flavor is not None else "rust"

    _serialize_position_mappings(codegen.map_pos_to_node, codegen.map_pos_to_addr, ctx, msg.pos_maps)
    _serialize_instruction_mapping(codegen.map_addr_to_pos, msg.map_addr_to_pos)
    for (addr, idx), label in (codegen.map_addr_to_label or {}).items():
        entry = msg.map_addr_to_label.add()
        if addr is not None:
            entry.addr = addr
        if idx is not None:
            entry.idx = idx
        entry.label_id = ctx.serialize(label)
    if codegen.cexterns:
        # cexterns is a set: sort the assigned ids so the same codegen always serializes to the same bytes
        msg.cexterns_ids.extend(sorted(ctx.serialize(v) for v in codegen.cexterns))

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
        if not hasattr(codegen, cg_attr):
            continue
        value = getattr(codegen, cg_attr)
        if value is None:
            continue
        setattr(msg, attr, value)

    msg.nodes.extend(ctx.nodes)
    msg.type_pool.extend(ctx.type_pool)
    msg.tag_pool.extend(ctx.tag_pool)
    msg.simvar_pool.extend(ctx.simvar_pool)
    msg.node_config.config_entries.extend(ctx.node_config)
    return msg


def parse_codegen(msg, *, project=None, kb=None, func=None):
    """Create a RustStructuredCodeGenerator from a Codegen cmessage, bypassing __init__ (which runs the whole
    decompilation pipeline). The result is suitable for display, navigation, and cache-validity checks; re-rendering
    needs the runtime back-references (project / func / kb, and a variable map) reattached."""
    cg = RustStructuredCodeGenerator.__new__(RustStructuredCodeGenerator)
    ctx = RustParseContext(
        msg.nodes,
        project=project,
        kb=kb,
        type_pool=msg.type_pool,
        tag_pool=msg.tag_pool,
        simvar_pool=msg.simvar_pool,
        node_config=msg.node_config,
    )

    cg.rust_func = ctx.resolve(msg.root_id) if msg.root_id != 0 else None

    cg.text = zlib.decompress(msg.text_z).decode("utf-8") if msg.HasField("text_z") else None
    cg.flavor = msg.flavor if msg.HasField("flavor") else "rust"
    cg.notes = _parse_notes(msg.notes_json)
    cg.expr_comments = dict(msg.expr_comments)
    cg.stmt_comments = dict(msg.stmt_comments)
    cg.const_formats = _parse_const_formats(msg.const_formats)
    cg.ident_counters = {}
    cg._next_node_idx = 1

    cg.map_pos_to_node, cg.map_pos_to_addr = c_serialize._parse_position_mappings(msg.pos_maps, ctx)
    cg.map_addr_to_pos = c_serialize._parse_instruction_mapping(msg.map_addr_to_pos)
    cg.map_ast_to_pos = _rebuild_ast_to_pos(cg.map_pos_to_node)

    cg.map_addr_to_label = {}
    for entry in msg.map_addr_to_label:
        addr = entry.addr if entry.HasField("addr") else None
        idx = entry.idx if entry.HasField("idx") else None
        cg.map_addr_to_label[(addr, idx)] = ctx.resolve(entry.label_id)

    cg.cexterns = {ctx.resolve(i) for i in msg.cexterns_ids} if msg.cexterns_ids else None

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
    cg._variables_in_use = cg.rust_func.variables_in_use if cg.rust_func is not None else None
    cg._inlined_strings = set()
    cg._function_pointers = set()
    cg.ailexpr2cnode = None
    cg.cnode2ailexpr = None
    cg._handlers = None
    cg.ail_graph = None
    # RustLet and RustFunctionLikeMacro read variant/return types out of the variable map at render time; a parsed
    # codegen has no live map, and re-rendering requires a freshly constructed generator anyway.
    cg._variable_map = VariableMap()
    cg.indent_delta = INDENT_DELTA
    if cg.rust_func is not None:
        has_dvars = kb is not None and func is not None and func.addr in kb.dec_variables
        cg.rust_func.variable_manager = kb.dec_variables[func.addr] if has_dvars else None

    ctx.set_codegen(cg)
    return cg


def _rebuild_ast_to_pos(pos_to_node):
    """Mirror of RustStructuredCodeGenerator.render_text: rebuild map_ast_to_pos from map_pos_to_node."""
    ast_to_pos = defaultdict(set)
    if pos_to_node is None:
        return ast_to_pos
    for elem, node in pos_to_node.items():
        obj = node.obj
        if isinstance(obj, RustConstant):
            ast_to_pos[obj.value].add(elem)
        elif isinstance(obj, RustVariable):
            ast_to_pos[obj.unified_variable if obj.unified_variable is not None else obj.variable].add(elem)
        elif isinstance(obj, RustFunctionCall):
            key = obj.callee_func if obj.callee_func is not None else obj.callee_target
            ast_to_pos[key].add(elem)
        elif isinstance(obj, RustStructField):
            ast_to_pos[(obj.struct_type, obj.offset)].add(elem)
        else:
            ast_to_pos[obj].add(elem)
    return ast_to_pos


# ---------------------------------------------------------------------------------------------------------------------
# Per-class serializers / parsers
# ---------------------------------------------------------------------------------------------------------------------


def _ser_break(_node, pb, _ctx):
    pb.cbreak.SetInParent()


def _parse_break(_pb, _ctx):
    return RustBreak.__new__(RustBreak)


def _ser_continue(_node, pb, _ctx):
    pb.ccontinue.SetInParent()


def _parse_continue(_pb, _ctx):
    return RustContinue.__new__(RustContinue)


def _ser_label(node, pb, _ctx):
    pb.rust_label.name = node.name
    if node.ins_addr is not None:
        pb.rust_label.ins_addr = node.ins_addr
    if node.block_idx is not None:
        pb.rust_label.block_idx = node.block_idx


def _parse_label(pb, _ctx):
    obj = RustLabel.__new__(RustLabel)
    body = pb.rust_label
    obj.name = body.name
    obj.ins_addr = body.ins_addr if body.HasField("ins_addr") else None
    obj.block_idx = body.block_idx if body.HasField("block_idx") else None
    return obj


def _ser_register(node, pb, _ctx):
    pb.creg.reg = node.reg


def _parse_register(pb, _ctx):
    obj = RustRegister.__new__(RustRegister)
    obj.reg = pb.creg.reg
    return obj


def _ser_statements(node, pb, ctx):
    for stmt in node.statements:
        pb.cstatements.statements_ids.append(ctx.serialize(stmt))


def _parse_statements(pb, ctx):
    obj = RustStatements.__new__(RustStatements)
    obj.statements = [ctx.resolve(i) for i in pb.cstatements.statements_ids]
    return obj


def _ser_assignment(node, pb, ctx):
    pb.cassignment.lhs_id = ctx.serialize(node.lhs)
    pb.cassignment.rhs_id = ctx.serialize(node.rhs)


def _parse_assignment(pb, ctx):
    obj = RustAssignment.__new__(RustAssignment)
    obj.lhs = ctx.resolve(pb.cassignment.lhs_id)
    obj.rhs = ctx.resolve(pb.cassignment.rhs_id)
    return obj


def _ser_return(node, pb, ctx):
    if node.retval is not None:
        pb.creturn.retval_id = ctx.serialize(node.retval)


def _parse_return(pb, ctx):
    obj = RustReturn.__new__(RustReturn)
    obj.retval = ctx.resolve(pb.creturn.retval_id) if pb.creturn.HasField("retval_id") else None
    return obj


def _ser_ifbreak(node, pb, ctx):
    pb.cifbreak.condition_id = ctx.serialize(node.condition)
    pb.cifbreak.cstyle_ifs = node.cstyle_ifs


def _parse_ifbreak(pb, ctx):
    obj = RustIfBreak.__new__(RustIfBreak)
    obj.condition = ctx.resolve(pb.cifbreak.condition_id)
    obj.cstyle_ifs = pb.cifbreak.cstyle_ifs
    return obj


def _ser_dirtystmt(node, pb, ctx):
    pb.cdirty_stmt.dirty_id = ctx.serialize(node.dirty)


def _parse_dirtystmt(pb, ctx):
    obj = RustDirtyStatement.__new__(RustDirtyStatement)
    obj.dirty = ctx.resolve(pb.cdirty_stmt.dirty_id)
    return obj


def _ser_while(node, pb, ctx):
    if node.condition is not None:
        pb.cwhile.condition_id = ctx.serialize(node.condition)
    if node.body is not None:
        pb.cwhile.body_id = ctx.serialize(node.body)


def _parse_while(pb, ctx):
    obj = RustWhileLoop.__new__(RustWhileLoop)
    obj.condition = ctx.resolve(pb.cwhile.condition_id) if pb.cwhile.HasField("condition_id") else None
    obj.body = ctx.resolve(pb.cwhile.body_id) if pb.cwhile.HasField("body_id") else None
    return obj


def _ser_dowhile(node, pb, ctx):
    if node.condition is not None:
        pb.cdowhile.condition_id = ctx.serialize(node.condition)
    if node.body is not None:
        pb.cdowhile.body_id = ctx.serialize(node.body)


def _parse_dowhile(pb, ctx):
    obj = RustDoWhileLoop.__new__(RustDoWhileLoop)
    obj.condition = ctx.resolve(pb.cdowhile.condition_id) if pb.cdowhile.HasField("condition_id") else None
    obj.body = ctx.resolve(pb.cdowhile.body_id) if pb.cdowhile.HasField("body_id") else None
    return obj


def _ser_infinite_loop(node, pb, ctx):
    if node.body is not None:
        pb.rust_infinite_loop.body_id = ctx.serialize(node.body)


def _parse_infinite_loop(pb, ctx):
    obj = RustInfiniteLoop.__new__(RustInfiniteLoop)
    obj.body = ctx.resolve(pb.rust_infinite_loop.body_id)
    return obj


def _ser_for(node, pb, ctx):
    if node.initializer is not None:
        pb.cfor.initializer_id = ctx.serialize(node.initializer)
    if node.condition is not None:
        pb.cfor.condition_id = ctx.serialize(node.condition)
    if node.iterator is not None:
        pb.cfor.iterator_id = ctx.serialize(node.iterator)
    if node.body is not None:
        pb.cfor.body_id = ctx.serialize(node.body)


def _parse_for(pb, ctx):
    obj = RustForLoop.__new__(RustForLoop)
    body = pb.cfor
    obj.initializer = ctx.resolve(body.initializer_id) if body.HasField("initializer_id") else None
    obj.condition = ctx.resolve(body.condition_id) if body.HasField("condition_id") else None
    obj.iterator = ctx.resolve(body.iterator_id) if body.HasField("iterator_id") else None
    obj.body = ctx.resolve(body.body_id) if body.HasField("body_id") else None
    return obj


def _ser_ifelse(node, pb, ctx):
    for cond, stmt in node.condition_and_nodes:
        entry = pb.cifelse.condition_and_nodes.add()
        entry.condition_id = ctx.serialize(cond)
        if stmt is not None:
            entry.statement_id = ctx.serialize(stmt)
    if node.else_node is not None:
        pb.cifelse.else_node_id = ctx.serialize(node.else_node)
    pb.cifelse.simplify_else_scope = node.simplify_else_scope
    pb.cifelse.cstyle_ifs = node.cstyle_ifs


def _parse_ifelse(pb, ctx):
    obj = RustIfElse.__new__(RustIfElse)
    body = pb.cifelse
    obj.condition_and_nodes = [
        (ctx.resolve(e.condition_id), ctx.resolve(e.statement_id) if e.HasField("statement_id") else None)
        for e in body.condition_and_nodes
    ]
    obj.else_node = ctx.resolve(body.else_node_id) if body.HasField("else_node_id") else None
    obj.simplify_else_scope = body.simplify_else_scope
    obj.cstyle_ifs = body.cstyle_ifs
    return obj


def _ser_switch(node, pb, ctx):
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


def _parse_switch(pb, ctx):
    obj = RustSwitchCase.__new__(RustSwitchCase)
    body = pb.cswitch
    obj.switch = ctx.resolve(body.switch_id)
    obj.cases = [
        (tuple(e.case_ids) if len(e.case_ids) > 1 else e.case_ids[0], ctx.resolve(e.statements_id)) for e in body.cases
    ]
    obj.default = ctx.resolve(body.default_id) if body.HasField("default_id") else None
    return obj


def _ser_incomplete_switch(node, pb, ctx):
    pb.cincomplete_switch.head_id = ctx.serialize(node.head)
    for case_addr, stmts in node.cases:
        entry = pb.cincomplete_switch.cases.add()
        entry.case_addr = case_addr
        entry.statements_id = ctx.serialize(stmts)


def _parse_incomplete_switch(pb, ctx):
    obj = RustIncompleteSwitchCase.__new__(RustIncompleteSwitchCase)
    body = pb.cincomplete_switch
    obj.head = ctx.resolve(body.head_id)
    obj.cases = [(e.case_addr, ctx.resolve(e.statements_id)) for e in body.cases]
    return obj


def _ser_goto(node, pb, ctx):
    if isinstance(node.target, int):
        pb.cgoto.target_int = node.target
    else:
        pb.cgoto.target_expr_id = ctx.serialize(node.target)
    if node.target_idx is not None:
        pb.cgoto.target_idx = node.target_idx


def _parse_goto(pb, ctx):
    obj = RustGoto.__new__(RustGoto)
    which = pb.cgoto.WhichOneof("target")
    if which == "target_int":
        obj.target = pb.cgoto.target_int
    elif which == "target_expr_id":
        obj.target = ctx.resolve(pb.cgoto.target_expr_id)
    else:
        obj.target = None
    obj.target_idx = pb.cgoto.target_idx if pb.cgoto.HasField("target_idx") else None
    return obj


def _ser_if_let(node, pb, ctx):
    body = pb.rust_if_let
    ctx.write_pattern(node.pattern, body.pattern)
    body.scrutinee_id = ctx.serialize(node.scrutinee)
    body.true_node_id = ctx.serialize(node.true_node)
    if node.false_node is not None:
        body.false_node_id = ctx.serialize(node.false_node)


def _parse_if_let(pb, ctx):
    obj = RustIfLet.__new__(RustIfLet)
    body = pb.rust_if_let
    obj.pattern = ctx.resolve_pattern(body.pattern)
    obj.scrutinee = ctx.resolve(body.scrutinee_id)
    obj.true_node = ctx.resolve(body.true_node_id)
    obj.false_node = ctx.resolve(body.false_node_id)
    return obj


def _ser_pattern_match(node, pb, ctx):
    body = pb.rust_pattern_match
    body.scrutinee_id = ctx.serialize(node.scrutinee)
    for pattern, arm in node.arms:
        entry = body.arms.add()
        ctx.write_pattern(pattern, entry.pattern)
        entry.body_id = ctx.serialize(arm)
    if node.default is not None:
        body.default_id = ctx.serialize(node.default)


def _parse_pattern_match(pb, ctx):
    obj = RustPatternMatch.__new__(RustPatternMatch)
    body = pb.rust_pattern_match
    obj.scrutinee = ctx.resolve(body.scrutinee_id)
    obj.arms = [(ctx.resolve_pattern(e.pattern), ctx.resolve(e.body_id)) for e in body.arms]
    obj.default = ctx.resolve(body.default_id)
    return obj


def _ser_unop(node, pb, ctx):
    pb.cunop.op = node.op
    pb.cunop.operand_id = ctx.serialize(node.operand)


def _parse_unop(pb, ctx):
    obj = RustUnaryOp.__new__(RustUnaryOp)
    obj.op = pb.cunop.op
    obj.operand = ctx.resolve(pb.cunop.operand_id)
    return obj


def _ser_binop(node, pb, ctx):
    pb.cbinop.op = node.op
    pb.cbinop.lhs_id = ctx.serialize(node.lhs)
    pb.cbinop.rhs_id = ctx.serialize(node.rhs)
    pb.cbinop.common_type_ref = ctx.intern_type(node.common_type)


def _parse_binop(pb, ctx):
    obj = RustBinaryOp.__new__(RustBinaryOp)
    obj.op = pb.cbinop.op
    obj.lhs = ctx.resolve(pb.cbinop.lhs_id)
    obj.rhs = ctx.resolve(pb.cbinop.rhs_id)
    obj.common_type = ctx.resolve_type(pb.cbinop.common_type_ref)
    # _cstyle_null_cmp is re-derived from the codegen in set_codegen()
    obj._cstyle_null_cmp = True
    return obj


def _ser_typecast(node, pb, ctx):
    pb.ctypecast.src_type_ref = ctx.intern_type(node.src_type)
    pb.ctypecast.dst_type_ref = ctx.intern_type(node.dst_type)
    pb.ctypecast.expr_id = ctx.serialize(node.expr)


def _parse_typecast(pb, ctx):
    obj = RustTypeCast.__new__(RustTypeCast)
    obj.src_type = ctx.resolve_type(pb.ctypecast.src_type_ref)
    obj.dst_type = ctx.resolve_type(pb.ctypecast.dst_type_ref)
    obj.expr = ctx.resolve(pb.ctypecast.expr_id)
    return obj


def _ser_ite(node, pb, ctx):
    pb.cite.cond_id = ctx.serialize(node.cond)
    pb.cite.iftrue_id = ctx.serialize(node.iftrue)
    pb.cite.iffalse_id = ctx.serialize(node.iffalse)


def _parse_ite(pb, ctx):
    obj = RustITE.__new__(RustITE)
    obj.cond = ctx.resolve(pb.cite.cond_id)
    obj.iftrue = ctx.resolve(pb.cite.iftrue_id)
    obj.iffalse = ctx.resolve(pb.cite.iffalse_id)
    return obj


def _ser_multi(node, pb, ctx):
    pb.cmulti_stmt_expr.stmts_id = ctx.serialize(node.stmts)
    pb.cmulti_stmt_expr.expr_id = ctx.serialize(node.expr)


def _parse_multi(pb, ctx):
    obj = RustMultiStatementExpression.__new__(RustMultiStatementExpression)
    obj.stmts = ctx.resolve(pb.cmulti_stmt_expr.stmts_id)
    obj.expr = ctx.resolve(pb.cmulti_stmt_expr.expr_id)
    return obj


def _ser_vex(node, pb, ctx):
    pb.cvex_ccall.callee = node.callee
    for op in node.operands:
        pb.cvex_ccall.operands_ids.append(ctx.serialize(op))


def _parse_vex(pb, ctx):
    obj = RustVEXCCallExpression.__new__(RustVEXCCallExpression)
    obj.callee = pb.cvex_ccall.callee
    obj.operands = [ctx.resolve(i) for i in pb.cvex_ccall.operands_ids]
    return obj


def _ser_structfield(node, pb, ctx):
    pb.cstruct_field.struct_type_ref = ctx.intern_type(node.struct_type)
    pb.cstruct_field.offset = node.offset
    pb.cstruct_field.field = node.field


def _parse_structfield(pb, ctx):
    obj = RustStructField.__new__(RustStructField)
    obj.struct_type = ctx.resolve_type(pb.cstruct_field.struct_type_ref)
    obj.offset = pb.cstruct_field.offset
    obj.field = pb.cstruct_field.field
    return obj


def _ser_fakevar(node, pb, ctx):
    pb.cfake_var.name = node.name
    if node._type is not None:
        pb.cfake_var.type_ref = ctx.intern_type(node._type)


def _parse_fakevar(pb, ctx):
    obj = RustFakeVariable.__new__(RustFakeVariable)
    obj.name = pb.cfake_var.name
    if pb.cfake_var.type_ref:
        obj._type = ctx.resolve_type(pb.cfake_var.type_ref)
    return obj


def _ser_var(node, pb, ctx):
    pb.cvar.variable_ref = ctx.intern_simvar(node.variable)
    if node.unified_variable is not None:
        pb.cvar.unified_variable_ref = ctx.intern_simvar(node.unified_variable)
    if node.variable_type is not None:
        pb.cvar.variable_type_ref = ctx.intern_type(node.variable_type)


def _parse_var(pb, ctx):
    obj = RustVariable.__new__(RustVariable)
    body = pb.cvar
    obj.variable = ctx.resolve_simvar(body.variable_ref)
    obj.unified_variable = ctx.resolve_simvar(body.unified_variable_ref)
    obj.variable_type = ctx.resolve_type(body.variable_type_ref)
    return obj


def _ser_idxvar(node, pb, ctx):
    pb.cindexed_var.variable_id = ctx.serialize(node.variable)
    pb.cindexed_var.index_id = ctx.serialize(node.index)
    if node._type is not None:
        pb.cindexed_var.type_ref = ctx.intern_type(node._type)


def _parse_idxvar(pb, ctx):
    obj = RustIndexedVariable.__new__(RustIndexedVariable)
    body = pb.cindexed_var
    obj.variable = ctx.resolve(body.variable_id)
    obj.index = ctx.resolve(body.index_id)
    if body.type_ref:
        obj._type = ctx.resolve_type(body.type_ref)
    return obj


def _ser_varfield(node, pb, ctx):
    pb.cvar_field.variable_id = ctx.serialize(node.variable)
    pb.cvar_field.field_id = ctx.serialize(node.field)
    pb.cvar_field.var_is_ptr = node.var_is_ptr


def _parse_varfield(pb, ctx):
    obj = RustVariableField.__new__(RustVariableField)
    body = pb.cvar_field
    obj.variable = ctx.resolve(body.variable_id)
    obj.field = ctx.resolve(body.field_id)
    obj.var_is_ptr = body.var_is_ptr
    return obj


def _ser_const(node, pb, ctx):
    c_serialize._ser_cconst(node, pb, ctx)


def _parse_const(pb, ctx):
    parsed = c_serialize._parse_cconst(pb, ctx)
    obj = RustConstant.__new__(RustConstant)
    obj.value = parsed.value
    obj._type = parsed._type
    obj.reference_values = parsed.reference_values
    return obj


def _ser_funcall(node, pb, ctx):
    body = pb.rust_funcall
    target = node.callee_target
    if isinstance(target, int):
        body.callee_target_int = target
    elif isinstance(target, str):
        body.callee_target_str = target
    elif target is not None:
        body.callee_target_expr_id = ctx.serialize(target)
    if node.callee_func is not None:
        body.callee_func_addr = node.callee_func.addr
    for a in node.args or ():
        body.args_ids.append(ctx.serialize(a))
    body.returning = node.returning
    if node.ret_expr is not None:
        body.ret_expr_id = ctx.serialize(node.ret_expr)
    if node.receiver is not None:
        body.receiver_id = ctx.serialize(node.receiver)
    body.is_expr = node.is_expr
    if node.callsite_prototype is not None:
        body.callsite_prototype_ref = ctx.intern_type(node.callsite_prototype)
    if not (node.show_demangled_name and node.show_disambiguated_name):
        ctx.add_cfuncall_config(pb.node_id, node.show_demangled_name, node.show_disambiguated_name)


def _parse_funcall(pb, ctx):
    obj = RustFunctionCall.__new__(RustFunctionCall)
    body = pb.rust_funcall
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
    obj.returning = body.returning
    obj.ret_expr = ctx.resolve(body.ret_expr_id)
    obj.receiver = ctx.resolve(body.receiver_id)
    obj.is_expr = body.is_expr
    obj.callsite_prototype = ctx.resolve_type(body.callsite_prototype_ref)
    obj.show_demangled_name, obj.show_disambiguated_name = ctx.cfuncall_config(pb.node_id)
    return obj


def _ser_macro(node, pb, ctx):
    body = pb.rust_macro
    body.name = node.name
    for arg in node.args or ():
        body.args.append(arg.to_bytes())
    body.delimiter.extend(node.delimiter)
    body.is_expr = node.is_expr
    if node.returnty is not None:
        body.returnty_ref = ctx.intern_type(node.returnty)


def _parse_macro(pb, ctx):
    obj = RustFunctionLikeMacro.__new__(RustFunctionLikeMacro)
    body = pb.rust_macro
    obj.name = body.name
    obj.args = [AilExpression.from_bytes(b) for b in body.args]
    obj.delimiter = tuple(body.delimiter)
    obj.is_expr = body.is_expr
    obj.returnty = ctx.resolve_type(body.returnty_ref)
    return obj


def _ser_function(node, pb, ctx):
    body = pb.cfunction
    if node.addr is not None:
        body.addr = node.addr
    body.name = node.name
    body.functy_ref = ctx.intern_type(node.functy)
    for arg in node.arg_list:
        body.arg_list_ids.append(ctx.serialize(arg))
    body.statements_id = ctx.serialize(node.statements)
    for simvar, cvar in (node.variables_in_use or {}).items():
        entry = body.variables_in_use.add()
        entry.simvariable_ref = ctx.intern_simvar(simvar)
        entry.cvariable_id = ctx.serialize(cvar)
    if node.demangled_name is not None:
        body.demangled_name = node.demangled_name
    body.show_demangled_name = node.show_demangled_name


def _parse_function(pb, ctx):
    obj = RustFunction.__new__(RustFunction)
    body = pb.cfunction
    obj.addr = body.addr if body.HasField("addr") else None
    obj.name = body.name
    obj.functy = ctx.resolve_type(body.functy_ref)
    obj.arg_list = [ctx.resolve(i) for i in body.arg_list_ids]
    obj.statements = ctx.resolve(body.statements_id)
    obj.variables_in_use = {
        ctx.resolve_simvar(e.simvariable_ref): ctx.resolve(e.cvariable_id) for e in body.variables_in_use
    }
    obj.demangled_name = body.demangled_name if body.HasField("demangled_name") else None
    obj.show_demangled_name = body.show_demangled_name
    obj.variable_manager = None
    obj.unified_local_vars = {}
    return obj


def _ser_ailblock(node, pb, _ctx):
    pb.cailblock.block = node.block.to_bytes()


def _parse_ailblock(pb, _ctx):
    obj = RustAILBlock.__new__(RustAILBlock)
    obj.block = AilBlock.from_bytes(pb.cailblock.block)
    return obj


def _ser_unsupported(node, pb, _ctx):
    pb.cunsupported.stmt = node.stmt.to_bytes()


def _parse_unsupported(pb, _ctx):
    obj = RustUnsupportedStatement.__new__(RustUnsupportedStatement)
    obj.stmt = AilStatement.from_bytes(pb.cunsupported.stmt)
    return obj


def _ser_dirtyexpr(node, pb, _ctx):
    pb.cdirty_expr.dirty = node.dirty.to_bytes()


def _parse_dirtyexpr(pb, _ctx):
    obj = RustDirtyExpression.__new__(RustDirtyExpression)
    obj.dirty = AilExpression.from_bytes(pb.cdirty_expr.dirty)
    return obj


def _ser_vectorconvert(node, pb, ctx):
    pb.cvector_convert.expr = node.expr.to_bytes()
    pb.cvector_convert.operand_id = ctx.serialize(node.operand)


def _parse_vectorconvert(pb, ctx):
    obj = RustVectorConvert.__new__(RustVectorConvert)
    expr = AilExpression.from_bytes(pb.cvector_convert.expr)
    assert isinstance(expr, AilConvert)
    obj.expr = expr
    obj.operand = ctx.resolve(pb.cvector_convert.operand_id)
    return obj


def _ser_let(node, pb, _ctx):
    pb.rust_let.let_expr = node.let_expr.to_bytes()


def _parse_let(pb, _ctx):
    obj = RustLet.__new__(RustLet)
    expr = AilExpression.from_bytes(pb.rust_let.let_expr)
    assert isinstance(expr, AilLet)
    obj.let_expr = expr
    return obj


def _ser_struct(node, pb, ctx):
    body = pb.rust_struct
    if node.name is not None:
        body.name = node.name
    for offset, value in node.fields.items():
        entry = body.fields.add()
        entry.offset = offset
        entry.value_id = ctx.serialize(value)
    if node.field_names is not None:
        body.has_field_names = True
        for offset, name in node.field_names.items():
            entry = body.field_names.add()
            entry.offset = offset
            entry.name = name


def _parse_struct(pb, ctx):
    obj = RustStruct.__new__(RustStruct)
    body = pb.rust_struct
    obj.name = body.name if body.HasField("name") else None
    obj.fields = OrderedDict((e.offset, ctx.resolve(e.value_id)) for e in body.fields)
    obj.field_names = OrderedDict((e.offset, e.name) for e in body.field_names) if body.has_field_names else None
    return obj


def _ser_enum(node, pb, ctx):
    body = pb.rust_enum
    if node.name is not None:
        body.name = node.name
    for field in node.fields:
        body.fields_ids.append(ctx.serialize(field))


def _parse_enum(pb, ctx):
    obj = RustEnum.__new__(RustEnum)
    body = pb.rust_enum
    obj.name = body.name if body.HasField("name") else None
    obj.fields = [ctx.resolve(i) for i in body.fields_ids]
    return obj


def _ser_array(node, pb, ctx):
    for element in node.elements:
        pb.rust_array.elements_ids.append(ctx.serialize(element))


def _parse_array(pb, ctx):
    obj = RustArray.__new__(RustArray)
    obj.elements = [ctx.resolve(i) for i in pb.rust_array.elements_ids]
    return obj


def _ser_string_literal(node, pb, _ctx):
    body = pb.rust_string_literal
    if isinstance(node.data, str):
        body.data = node.data.encode("utf-8", errors="surrogateescape")
        body.data_is_str = True
    else:
        body.data = node.data


def _parse_string_literal(pb, _ctx):
    obj = RustStringLiteral.__new__(RustStringLiteral)
    body = pb.rust_string_literal
    obj.data = body.data.decode("utf-8", errors="surrogateescape") if body.data_is_str else body.data
    return obj


def register_all() -> None:
    """Register serializer/parser pairs for every concrete RustConstruct subclass. Called from rust.py at import
    time, once every class is defined."""
    _register(RustBreak, codegen_pb2.CCK_BREAK, _ser_break, _parse_break)
    _register(RustContinue, codegen_pb2.CCK_CONTINUE, _ser_continue, _parse_continue)
    _register(RustLabel, codegen_pb2.CCK_LABEL, _ser_label, _parse_label)
    _register(RustRegister, codegen_pb2.CCK_REGISTER, _ser_register, _parse_register)
    _register(RustStatements, codegen_pb2.CCK_STATEMENTS, _ser_statements, _parse_statements)
    _register(RustAssignment, codegen_pb2.CCK_ASSIGNMENT, _ser_assignment, _parse_assignment)
    _register(RustReturn, codegen_pb2.CCK_RETURN, _ser_return, _parse_return)
    _register(RustIfBreak, codegen_pb2.CCK_IF_BREAK, _ser_ifbreak, _parse_ifbreak)
    _register(RustDirtyStatement, codegen_pb2.CCK_DIRTY_STATEMENT, _ser_dirtystmt, _parse_dirtystmt)
    _register(RustWhileLoop, codegen_pb2.CCK_WHILE_LOOP, _ser_while, _parse_while)
    _register(RustDoWhileLoop, codegen_pb2.CCK_DO_WHILE_LOOP, _ser_dowhile, _parse_dowhile)
    _register(RustForLoop, codegen_pb2.CCK_FOR_LOOP, _ser_for, _parse_for)
    _register(RustIfElse, codegen_pb2.CCK_IF_ELSE, _ser_ifelse, _parse_ifelse)
    _register(RustSwitchCase, codegen_pb2.CCK_SWITCH_CASE, _ser_switch, _parse_switch)
    _register(
        RustIncompleteSwitchCase,
        codegen_pb2.CCK_INCOMPLETE_SWITCH_CASE,
        _ser_incomplete_switch,
        _parse_incomplete_switch,
    )
    _register(RustGoto, codegen_pb2.CCK_GOTO, _ser_goto, _parse_goto)
    _register(RustUnaryOp, codegen_pb2.CCK_UNARY_OP, _ser_unop, _parse_unop)
    _register(RustBinaryOp, codegen_pb2.CCK_BINARY_OP, _ser_binop, _parse_binop)
    _register(RustTypeCast, codegen_pb2.CCK_TYPE_CAST, _ser_typecast, _parse_typecast)
    _register(RustITE, codegen_pb2.CCK_ITE, _ser_ite, _parse_ite)
    _register(RustMultiStatementExpression, codegen_pb2.CCK_MULTI_STATEMENT_EXPRESSION, _ser_multi, _parse_multi)
    _register(RustVEXCCallExpression, codegen_pb2.CCK_VEX_CCALL_EXPRESSION, _ser_vex, _parse_vex)
    _register(RustStructField, codegen_pb2.CCK_STRUCT_FIELD, _ser_structfield, _parse_structfield)
    _register(RustFakeVariable, codegen_pb2.CCK_FAKE_VARIABLE, _ser_fakevar, _parse_fakevar)
    _register(RustVariable, codegen_pb2.CCK_VARIABLE, _ser_var, _parse_var)
    _register(RustIndexedVariable, codegen_pb2.CCK_INDEXED_VARIABLE, _ser_idxvar, _parse_idxvar)
    _register(RustVariableField, codegen_pb2.CCK_VARIABLE_FIELD, _ser_varfield, _parse_varfield)
    _register(RustConstant, codegen_pb2.CCK_CONSTANT, _ser_const, _parse_const)
    _register(RustFunctionCall, codegen_pb2.CCK_FUNCTION_CALL, _ser_funcall, _parse_funcall)
    _register(RustFunction, codegen_pb2.CCK_FUNCTION, _ser_function, _parse_function)
    _register(RustAILBlock, codegen_pb2.CCK_AIL_BLOCK, _ser_ailblock, _parse_ailblock)
    _register(RustUnsupportedStatement, codegen_pb2.CCK_UNSUPPORTED_STATEMENT, _ser_unsupported, _parse_unsupported)
    _register(RustDirtyExpression, codegen_pb2.CCK_DIRTY_EXPRESSION, _ser_dirtyexpr, _parse_dirtyexpr)
    _register(RustVectorConvert, codegen_pb2.CCK_VECTOR_CONVERT, _ser_vectorconvert, _parse_vectorconvert)
    _register(RustLet, codegen_pb2.CCK_RUST_LET, _ser_let, _parse_let)
    _register(RustIfLet, codegen_pb2.CCK_RUST_IF_LET, _ser_if_let, _parse_if_let)
    _register(RustPatternMatch, codegen_pb2.CCK_RUST_PATTERN_MATCH, _ser_pattern_match, _parse_pattern_match)
    _register(RustStruct, codegen_pb2.CCK_RUST_STRUCT, _ser_struct, _parse_struct)
    _register(RustEnum, codegen_pb2.CCK_RUST_ENUM, _ser_enum, _parse_enum)
    _register(RustArray, codegen_pb2.CCK_RUST_ARRAY, _ser_array, _parse_array)
    _register(RustStringLiteral, codegen_pb2.CCK_RUST_STRING_LITERAL, _ser_string_literal, _parse_string_literal)
    _register(RustFunctionLikeMacro, codegen_pb2.CCK_RUST_FUNCTION_LIKE_MACRO, _ser_macro, _parse_macro)
    _register(RustInfiniteLoop, codegen_pb2.CCK_RUST_INFINITE_LOOP, _ser_infinite_loop, _parse_infinite_loop)
