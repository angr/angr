# pylint:disable=missing-class-docstring,too-many-boolean-expressions,unused-argument,no-self-use,protected-access
"""
Go-flavored structured code generator. A fork of the C backend (c.py) that renders Go syntax.
"""

from __future__ import annotations

import contextlib
import copy
import json
import logging
import re
import struct
from collections import Counter, OrderedDict, defaultdict
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any, cast

from angr.ailment import Block, Expr, Stmt, Tmp
from angr.ailment.block_walker import _dispatch_key
from angr.ailment.constant import UNDETERMINED_SIZE
from angr.ailment.expression import BinaryOp, StackBaseOffset, StringLiteral, Struct
from angr.analyses.analysis import Analysis, register_analysis
from angr.analyses.decompiler.notes.deobfuscated_strings import DeobfuscatedStringsNote
from angr.analyses.decompiler.peephole_optimizations.cas_intrinsics import cas_intrinsic_name
from angr.analyses.decompiler.region_identifier import MultiNode
from angr.analyses.decompiler.structurer_nodes import (
    BreakNode,
    CascadingConditionNode,
    CodeNode,
    ConditionalBreakNode,
    ConditionNode,
    ContinueNode,
    IncompleteSwitchCaseHeadStatement,
    IncompleteSwitchCaseNode,
    LoopNode,
    SequenceNode,
    SwitchCaseNode,
)
from angr.analyses.decompiler.utils import structured_node_is_simple_return
from angr.analyses.decompiler.variable_map import VariableMap
from angr.errors import UnsupportedNodeTypeError
from angr.go.codegen_builtins import render_builtin_call
from angr.go.codegen_builtins_values import call_tag, render_builtin_call_value
from angr.go.sim_type import (
    GoSimStruct,
    GoSimType,
    GoSimTypeBool,
    GoSimTypeChan,
    GoSimTypeFunc,
    GoSimTypeInt,
    GoSimTypeInterface,
    GoSimTypeMap,
    GoSimTypePointer,
    GoSimTypeSlice,
    GoSimTypeString,
    GoSimTypeTuple,
)
from angr.go.utils.types import go_type_name_at
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from angr.knowledge_plugins.functions import Function
from angr.sim_type import (
    SimCppClass,
    SimStruct,
    SimType,
    SimTypeArray,
    SimTypeBitfield,
    SimTypeBool,
    SimTypeBottom,
    SimTypeChar,
    SimTypeDouble,
    SimTypeEnum,
    SimTypeFixedSizeArray,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeInt,
    SimTypeInt128,
    SimTypeInt256,
    SimTypeInt512,
    SimTypeLength,
    SimTypeLongLong,
    SimTypeNum,
    SimTypePointer,
    SimTypeReg,
    SimTypeShort,
    SimTypeWideChar,
    SimUnion,
    TypeRef,
)
from angr.sim_variable import (
    SimComboRegisterVariable,
    SimMemoryVariable,
    SimRegisterVariable,
    SimStackVariable,
    SimTemporaryVariable,
    SimVariable,
)
from angr.utils.bits import u2s
from angr.utils.constants import should_use_hex
from angr.utils.go_runtime import normalize_go_func_name
from angr.utils.loader import is_in_readonly_section, is_in_readonly_segment
from angr.utils.strings import decode_utf16_string
from angr.utils.types import dereference_simtype_by_lib, unpack_pointer_and_array, unpack_typeref

from .base import (
    BaseStructuredCodeGenerator,
    CConstantType,
    IdentType,
    InstructionMapping,
    PositionMapping,
    PositionMappingElement,
)

if TYPE_CHECKING:
    import archinfo

    import angr
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal


l = logging.getLogger(name=__name__)


type RenderResult = tuple[str, PositionMapping, PositionMapping, InstructionMapping, dict[Any, set[Any]]]


INDENT_DELTA = 4

_CAST_TYPES_BY_BITS: dict[int, type[SimTypeInt | SimTypeChar]] = {
    8: SimTypeChar,
    16: SimTypeShort,
    32: SimTypeInt,
    64: SimTypeLongLong,
    128: SimTypeInt128,
    256: SimTypeInt256,
    512: SimTypeInt512,
}


def qualifies_for_simple_cast(ty1, ty2):
    # converting ty1 to ty2 - can this happen precisely?
    # used to decide whether to add explicit typecasts instead of doing *(int*)&v1
    return (
        ty1.size == ty2.size
        and isinstance(ty1, (SimTypeInt, SimTypeChar, SimTypeNum, SimTypePointer))
        and isinstance(ty2, (SimTypeInt, SimTypeChar, SimTypeNum, SimTypePointer))
    )


def qualifies_for_width_cast(ty):
    # converting ty to a different width - can a scalar cast do it?
    # floats are excluded because a float cast converts the value, not the representation
    return isinstance(ty, (SimTypeInt, SimTypeChar, SimTypeNum, SimTypePointer, SimTypeBottom))


def qualifies_for_implicit_cast(ty1, ty2):
    # converting ty1 to ty2 - can this happen without a cast?
    # used to decide whether to omit typecasts from output during promotion
    # this function need to answer the question:
    # when does having a cast vs having an implicit promotion affect the result?
    # the answer: I DON'T KNOW
    if not isinstance(ty1, (SimTypeInt, SimTypeChar, SimTypeNum)) or not isinstance(
        ty2, (SimTypeInt, SimTypeChar, SimTypeNum)
    ):
        return False

    return ty1.size <= ty2.size if ty1.size is not None and ty2.size is not None else False


def extract_terms(expr: GoExpression) -> tuple[int, list[tuple[int, GoExpression]]]:
    # handle unnecessary type casts
    if isinstance(expr, GoTypeCast):
        expr = MakeTypecastsImplicit.collapse(expr.dst_type, expr.expr)
    if (
        isinstance(expr, GoTypeCast)
        and isinstance(expr.dst_type, SimTypeInt)
        and isinstance(expr.src_type, SimTypeInt)
        and expr.dst_type.size == expr.src_type.size
        and expr.dst_type.signed != expr.src_type.signed
    ):
        # (unsigned int)(a + 60)  ==>  a + 60, assuming a + 60 is an int
        expr = expr.expr

    if isinstance(expr, GoConstant) and isinstance(expr.value, int):
        return expr.value, []
    # elif isinstance(expr, GoUnaryOp) and expr.op == 'Minus'
    if isinstance(expr, GoBinaryOp) and expr.op == "Add":
        c1, t1 = extract_terms(expr.lhs)
        c2, t2 = extract_terms(expr.rhs)
        return c1 + c2, t1 + t2
    if isinstance(expr, GoBinaryOp) and expr.op == "Sub":
        c1, t1 = extract_terms(expr.lhs)
        c2, t2 = extract_terms(expr.rhs)
        return c1 - c2, t1 + [(-c, t) for c, t in t2]
    if isinstance(expr, GoBinaryOp) and expr.op == "Mul":
        if isinstance(expr.lhs, GoConstant) and isinstance(expr.lhs.value, int):
            c, t = extract_terms(expr.rhs)
            return c * expr.lhs.value, [(c1 * expr.lhs.value, t1) for c1, t1 in t]
        if isinstance(expr.rhs, GoConstant) and isinstance(expr.rhs.value, int):
            c, t = extract_terms(expr.lhs)
            return c * expr.rhs.value, [(c1 * expr.rhs.value, t1) for c1, t1 in t]
        return 0, [(1, expr)]
    if isinstance(expr, GoBinaryOp) and expr.op == "Shl":
        if isinstance(expr.rhs, GoConstant) and isinstance(expr.rhs.value, int):
            c, t = extract_terms(expr.lhs)
            return c << expr.rhs.value, [(c1 << expr.rhs.value, t1) for c1, t1 in t]
        return 0, [(1, expr)]
    return 0, [(1, expr)]


def is_machine_word_size_type(type_: SimType, arch: archinfo.Arch) -> bool:
    return isinstance(type_, SimTypeReg) and type_.size == arch.bits


def guess_value_type(value: int, project: angr.Project) -> SimType | None:
    if project.kb.functions.contains_addr(value):
        # might be a function pointer
        return SimTypePointer(SimTypeBottom(label="void")).with_arch(project.arch)
    if value > 4096:
        sec = project.loader.find_section_containing(value)
        if sec is not None and sec.is_readable:
            return SimTypePointer(SimTypeBottom(label="void")).with_arch(project.arch)
        seg = project.loader.find_segment_containing(value)
        if seg is not None and seg.is_readable:
            return SimTypePointer(SimTypeBottom(label="void")).with_arch(project.arch)
    return None


def type_equals(t0: SimType, t1: SimType) -> bool:
    t0 = unpack_typeref(t0)
    t1 = unpack_typeref(t1)
    # special logic for C++ classes
    if isinstance(t0, SimCppClass) and isinstance(t1, SimCppClass):  # noqa: SIM102
        # TODO: Use the information (class names, etc.) in types_stl
        if {t1.name, t0.name} == {
            "std::string",
            "class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>",
        }:
            return True
    return t0 == t1


def _safe_type_size(ty) -> int:
    sz = getattr(ty, "size", -1)
    return sz if isinstance(sz, int) else -1


def type_layout_key(ty, _seen: frozenset = frozenset()) -> str:
    """
    A structural sort key for a type, derived purely from its memory layout (sizes, field offsets, and the
    layouts of field/element/pointee types) and not from any user-renamable struct or field name. This lets
    the code generator order type definitions stably without their order changing when the user renames a struct
    or a field. Cycles through recursive struct/pointer references are broken with a marker.
    """
    ty = unpack_typeref(ty)
    if isinstance(ty, SimStruct):
        if id(ty) in _seen:
            return "@"  # a reference back to an enclosing struct (recursive type)
        if _seen and _go_descriptor_name(ty):
            # a named Go struct reached from another type is a leaf: its layout is fixed by the binary, and the
            # graph of named types reachable through its fields can be hundreds of types deep
            return f"S[{_safe_type_size(ty)};{len(ty.fields)}]"
        _seen = _seen | {id(ty)}
        offsets = ty.offsets
        fields = sorted(f"{offsets.get(fname, -1)}:{type_layout_key(fty, _seen)}" for fname, fty in ty.fields.items())
        return f"S[{_safe_type_size(ty)};{int(bool(getattr(ty, 'packed', False)))};{';'.join(fields)}]"
    if isinstance(ty, SimTypePointer):
        return f"P({type_layout_key(ty.pts_to, _seen)})"
    if isinstance(ty, (SimTypeArray, SimTypeFixedSizeArray)):
        return f"A{getattr(ty, 'length', None)}({type_layout_key(ty.elem_type, _seen)})"
    return f"T:{type(ty).__name__}:{_safe_type_size(ty)}:{getattr(ty, 'signed', None)}"


def cextern_sort_key(cextern) -> tuple:
    """
    A stable sort key for extern variables, based on the variable's address. Unlike the variable name, the
    address does not change when the user renames the variable, so the ordering of extern definitions stays put
    across renames.
    """
    addr = getattr(cextern.variable, "addr", None)
    if isinstance(addr, int):
        return (0, addr)
    return (1, str(addr) if addr is not None else "")


def _iter_struct_union_member_types(ty):
    """
    Yield the member types of a struct or a union, flattening nested unions.
    """
    members = ty.members if isinstance(ty, SimUnion) else ty.fields
    for member in members.values():
        member = unpack_typeref(member)
        if isinstance(member, SimUnion):
            yield from _iter_struct_union_member_types(member)
        else:
            yield member


def _is_go_value_read_as_int(base_type, data_type) -> bool:
    if not isinstance(base_type, (GoSimStruct, GoSimTypePointer)):
        return False
    if isinstance(data_type, GoSimStruct) or not isinstance(
        data_type, (SimTypeInt, SimTypeChar, SimTypeNum, SimTypeReg, GoSimTypeInt)
    ):
        return False
    try:
        return base_type.size == data_type.size
    except ValueError:
        return False


def _is_go_builtin_struct(ty) -> bool:
    """string, slices, interfaces and result tuples are struct-shaped but never declared."""
    return isinstance(ty, (GoSimTypeString, GoSimTypeSlice, GoSimTypeInterface, GoSimTypeTuple))


def _is_anonymous_struct_or_union(ty) -> bool:
    """
    Returns True if ``ty`` is an anonymous struct or union.
    """
    if isinstance(ty, SimStruct):
        return bool(ty.anonymous) or ty.name == "<anon>"
    return isinstance(ty, SimUnion) and ty.name == "<anon>"


def go_type_str(ty: SimType | None, memo: set[int] | None = None) -> str:
    """
    Spell a SimType the Go way. Only C-flavored SimTypes reach here until Go-specific SimTypes exist; they are mapped
    onto the closest Go builtin by size and signedness.
    """
    if memo is None:
        memo = set()
    ty = unpack_typeref(ty)
    if ty is None:
        return "<missing-type>"
    if isinstance(ty, GoSimType):
        return ty.go_repr()
    if isinstance(ty, SimTypeBottom):
        return "any"
    if isinstance(ty, SimTypePointer):
        pts_to = unpack_typeref(ty.pts_to)
        if pts_to is None or isinstance(pts_to, SimTypeBottom):
            return "unsafe.Pointer"
        if isinstance(pts_to, SimTypeFunction):
            return go_type_str(pts_to, memo)
        return "*" + go_type_str(pts_to, memo)
    if isinstance(ty, SimTypeFixedSizeArray):
        return f"[{ty.length}]" + go_type_str(ty.elem_type, memo)
    if isinstance(ty, SimTypeArray):
        prefix = f"[{ty.length}]" if ty.length is not None else "[]"
        return prefix + go_type_str(ty.elem_type, memo)
    if isinstance(ty, SimTypeFunction):
        args = ", ".join(go_type_str(a, memo) for a in ty.args)
        ret = unpack_typeref(ty.returnty)
        if ret is None or isinstance(ret, SimTypeBottom):
            return f"func({args})"
        return f"func({args}) {go_type_str(ret, memo)}"
    if isinstance(ty, (SimStruct, SimUnion)):
        if not _is_anonymous_struct_or_union(ty):
            return ty.name.removeprefix("class ")
        if id(ty) in memo:
            return "struct{ /* recursive */ }"
        memo.add(id(ty))
        members = ty.members if isinstance(ty, SimUnion) else ty.fields
        body = "; ".join(f"{k} {go_type_str(v, memo)}" for k, v in members.items())
        memo.discard(id(ty))
        prefix = "struct{ /* union */ " if isinstance(ty, SimUnion) else "struct{ "
        return prefix + body + " }"
    if isinstance(ty, SimTypeEnum):
        return ty.name
    if isinstance(ty, SimTypeFloat):
        if ty.size == 32:
            return "float32"
        if ty.size == 64:
            return "float64"
        return f"float{ty.size}"
    if isinstance(ty, SimTypeLength):
        return "uintptr"
    if isinstance(ty, SimTypeWideChar):
        return "uint16"
    if isinstance(ty, (SimTypeChar, SimTypeInt, SimTypeNum, SimTypeReg, SimTypeBitfield)):
        try:
            size = ty.size
        except ValueError:
            # arch-dependent width without an arch attached
            size = None
        if size is None:
            return "int" if getattr(ty, "signed", False) else "uint"
        signed = getattr(ty, "signed", None)
        if signed is None:
            signed = False
        if size == 8 and not signed:
            return "byte"
        return ("int" if signed else "uint") + str(size)
    return ty.c_repr(name=None) if hasattr(ty, "c_repr") else str(ty)


def _struct_fields_to_go_repr_chunks(ty, indent_str: str, indent_delta: int, memo: set[int]):
    new_indent_str = (" " * indent_delta) + indent_str
    memo.add(id(ty))
    members = ty.members if isinstance(ty, SimUnion) else ty.fields
    for k, v in members.items():
        yield from type_to_go_repr_chunks(
            v,
            name=k,
            name_type=GoStructFieldNameDef(k),
            full=False,
            indent_str=new_indent_str,
            indent_delta=indent_delta,
            memo=memo,
        )
        yield "\n", None
    memo.discard(id(ty))


def _anonymous_struct_union_to_go_repr_chunks(ty, name, name_type, indent_str: str, indent_delta: int, memo: set[int]):
    """
    Render an anonymous struct or union inline, as ``name struct { ... }``.
    """
    yield indent_str, None
    yield name, name_type
    yield (" struct { /* union */\n" if isinstance(ty, SimUnion) else " struct {\n"), None
    yield from _struct_fields_to_go_repr_chunks(ty, indent_str, indent_delta, memo)
    yield indent_str, None
    yield "}", None


def type_to_go_repr_chunks(
    ty: SimType,
    name=None,
    name_type=None,
    full=False,
    indent_str="",
    indent_delta: int = INDENT_DELTA,
    memo: set[int] | None = None,
):
    """
    Helper generator function to turn a SimType into generated tuples of (Go-string, AST node).

    Go declarations put the name first (``name T``); a full struct definition renders as ``type Name struct {...}``.
    """
    if memo is None:
        memo = set()

    if isinstance(ty, GoSimType) and not (full and isinstance(ty, SimStruct)):
        yield indent_str, None
        if name:
            yield name, name_type
            yield " ", None
        yield ty.go_repr(), ty
        return

    if not full and name is not None and _is_anonymous_struct_or_union(ty):
        if id(ty) in memo:
            yield indent_str, None
            yield name, name_type
            yield " struct{ /* recursive */ }", None
            return
        yield from _anonymous_struct_union_to_go_repr_chunks(
            ty, name, name_type, indent_str=indent_str, indent_delta=indent_delta, memo=memo
        )
    elif isinstance(ty, SimStruct) and full:
        type_name = ty.name.removeprefix("class ")
        yield indent_str, None
        yield "type ", None
        yield type_name, ty
        yield " struct {\n", None
        yield from _struct_fields_to_go_repr_chunks(ty, indent_str, indent_delta, memo)
        yield indent_str, None
        yield "}\n\n", None
    elif isinstance(ty, SimType):
        yield indent_str, None
        if name:
            yield name, name_type
            yield " ", None
        yield go_type_str(ty, memo), ty
    elif ty is None:
        assert name
        assert name_type
        yield name, name_type
        yield " <missing-type>", None
    else:
        assert False


def _recursively_collect_referenced_structs(ty, out: dict[int, SimStruct], _seen: set[int] | None = None) -> None:
    """
    Walk ``ty`` transitively and record every ``SimStruct`` reachable from it into ``out`` (keyed
    by object id). Used by the C backend to determine which structs are actually referenced by
    rendered declarations/expressions, so that unreferenced typedefs can be dropped.
    """
    if _seen is None:
        _seen = set()
    ty = unpack_typeref(ty)
    if ty is None or id(ty) in _seen:
        return
    _seen.add(id(ty))
    if isinstance(ty, SimStruct):
        out[id(ty)] = ty
        for ftype in ty.fields.values():
            _recursively_collect_referenced_structs(ftype, out, _seen=_seen)
    elif isinstance(ty, SimUnion):
        for mtype in ty.members.values():
            _recursively_collect_referenced_structs(mtype, out, _seen=_seen)
    elif isinstance(ty, SimTypePointer):
        _recursively_collect_referenced_structs(ty.pts_to, out, _seen=_seen)
    elif isinstance(ty, (SimTypeArray, SimTypeFixedSizeArray)):
        _recursively_collect_referenced_structs(ty.elem_type, out, _seen=_seen)
    elif isinstance(ty, SimTypeFunction):
        for arg in ty.args or ():
            _recursively_collect_referenced_structs(arg, out, _seen=_seen)
        _recursively_collect_referenced_structs(ty.returnty, out, _seen=_seen)


#
#   C Representation Classes
#


class GoConstruct:
    """
    Represents a program construct in C.
    Acts as the base class for all other representation constructions.
    """

    __slots__ = ("codegen", "ident", "idx", "tags")

    def __init__(self, codegen, tags=None):
        # a GoConstruct cannot exist without its owning codegen: ``idx`` (the per-codegen unique node identity) and
        # ``ident`` (a per-class-name display label; NOT unique) are both allocated from it
        assert codegen is not None
        self.tags = tags or {}
        self.codegen: GoStructuredCodeGenerator = codegen
        self.ident: str = codegen.next_ident(self.__class__.__name__)
        self.idx: int = codegen.next_node_idx()

    def c_repr(self, initial_pos=0, indent=0, pos_to_node=None, pos_to_addr=None, addr_to_pos=None):
        """
        Creates the C representation of the code and displays it by
        constructing a large string. This function is called by each program function that needs to be decompiled.
        The map_pos_to_node and map_pos_to_addr act as position maps for the location of each variable and statement to
        be tracked for later GUI operations. The map_pos_to_addr also contains expressions that are nested inside of
        statements.
        """

        pending_stmt_comments = dict(self.codegen.stmt_comments)
        pending_expr_comments = dict(self.codegen.expr_comments)

        def mapper(chunks):
            # start all positions at beginning of document
            pos = initial_pos

            last_insn_addr = None

            # track all variables so we can tell if this is a declaration or not
            used_vars = set()

            # get each string and object representation of the chunks
            for s, obj in chunks:
                # filter out anything that is not a statement or expression object
                if isinstance(obj, (GoStatement, GoExpression)):
                    # only add statements/expressions that can be address tracked into map_pos_to_addr
                    if hasattr(obj, "tags") and obj.tags is not None and "ins_addr" in obj.tags:
                        if isinstance(obj, GoVariable) and obj not in used_vars:
                            used_vars.add(obj)
                        else:
                            last_insn_addr = obj.tags["ins_addr"]

                            # all valid statements and expressions should be added to map_pos_to_addr and
                            # tracked for instruction mapping from disassembly
                            if pos_to_addr is not None:
                                pos_to_addr.add_mapping(pos, len(s), obj)
                            if addr_to_pos is not None:
                                addr_to_pos.add_mapping(obj.tags["ins_addr"], pos)

                    # add all variables, constants, and function calls to map_pos_to_node for highlighting
                    # add ops to pos_to_node but NOT ast_to_pos
                    if (
                        isinstance(
                            obj,
                            (
                                GoVariable,
                                GoConstant,
                                GoStructField,
                                GoIndexedVariable,
                                GoVariableField,
                                GoBinaryOp,
                                GoUnaryOp,
                                GoAssignment,
                                GoFunctionCall,
                                GoLabel,
                            ),
                        )
                        and pos_to_node is not None
                    ):
                        pos_to_node.add_mapping(pos, len(s), obj)

                # add (), {}, [], and [20] to mapping for highlighting as well as the full functions name
                elif isinstance(obj, (GoClosingObject, GoFunction, GoArrayTypeLength, GoStructFieldNameDef)):
                    if s is None:
                        continue

                    if pos_to_node is not None:
                        pos_to_node.add_mapping(pos, len(s), obj)

                elif isinstance(obj, SimType):
                    if pos_to_node is not None:
                        if isinstance(obj, TypeRef):
                            pos_to_node.add_mapping(pos, len(s), obj.type)
                        else:
                            pos_to_node.add_mapping(pos, len(s), obj)

                if s.endswith("\n"):
                    text = pending_stmt_comments.pop(last_insn_addr, None) if isinstance(last_insn_addr, int) else None
                    if text is not None:
                        todo = "  // " + text
                        pos += len(s) - 1
                        yield s[:-1]
                        pos += len(todo)
                        yield todo
                        s = "\n"

                pos += len(s)
                yield s

                if isinstance(obj, GoExpression):
                    text = pending_expr_comments.pop(last_insn_addr, None) if isinstance(last_insn_addr, int) else None
                    if text is not None:
                        todo = " /*" + text + "*/ "
                        pos += len(todo)
                        yield todo

            if pending_expr_comments or pending_stmt_comments:
                yield "// Orphaned comments\n"
                for text in pending_stmt_comments.values():
                    yield "// " + text + "\n"
                for text in pending_expr_comments.values():
                    yield "/* " + text + "*/\n"

        # A special note about this line:
        # Polymorphism allows that the c_repr_chunks() call will be called
        # by the GoFunction class, which will then call each statement within it and construct
        # the chunks that get printed in qccode_edit in angr-management.
        return "".join(mapper(self.c_repr_chunks(indent)))

    def c_repr_chunks(self, indent=0, asexpr=False):
        raise NotImplementedError

    @staticmethod
    def indent_str(indent=0):
        return " " * indent


class GoFunction(GoConstruct):  # pylint:disable=abstract-method
    """
    Represents a function in C.
    """

    __slots__ = (
        "addr",
        "arg_list",
        "demangled_name",
        "extra_decls",
        "functy",
        "name",
        "omit_header",
        "short_declared",
        "show_demangled_name",
        "statements",
        "unified_local_vars",
        "variable_manager",
        "variables_in_use",
    )

    def __init__(
        self,
        addr,
        name,
        functy: SimTypeFunction,
        arg_list: list[GoVariable],
        statements,
        variables_in_use,
        variable_manager,
        demangled_name=None,
        show_demangled_name=True,
        omit_header=False,
        **kwargs,
    ):
        super().__init__(**kwargs)

        self.addr = addr
        self.name = name
        self.functy = functy
        self.arg_list = arg_list
        self.statements = statements
        self.variables_in_use = variables_in_use
        self.variable_manager: VariableManagerInternal = variable_manager
        self.demangled_name = demangled_name
        self.unified_local_vars: dict[SimVariable, set[tuple[GoVariable, SimType]]] = {}
        self.show_demangled_name = show_demangled_name
        self.omit_header = omit_header
        # (name, type) declarations introduced by rewrites (e.g. destructured results)
        self.extra_decls: list[tuple[str, SimType]] = []
        # variables (unified variable or fake-variable name) declared by a := statement
        self.short_declared: set = set()

        self.refresh()

    def refresh(self):
        self.unified_local_vars = self.get_unified_local_vars()

    def get_unified_local_vars(self) -> dict[SimVariable, set[tuple[GoVariable, SimType]]]:
        unified_to_var_and_types: dict[SimVariable, set[tuple[GoVariable, SimType]]] = defaultdict(set)

        arg_set: set[SimVariable] = set()
        for arg in self.arg_list:
            # TODO: Handle GoIndexedVariable
            if isinstance(arg, GoVariable):
                if arg.unified_variable is not None:
                    arg_set.add(arg.unified_variable)
                else:
                    arg_set.add(arg.variable)

        # output each variable and its type
        for var, cvar in self.variables_in_use.items():
            if isinstance(var, SimMemoryVariable) and not isinstance(var, SimStackVariable):
                # Skip all global variables
                continue

            if var in arg_set or cvar.unified_variable in arg_set:
                continue

            unified_var = self.variable_manager.unified_variable(var)
            if unified_var is not None:
                key = unified_var
                var_type = self.variable_manager.get_variable_type(var)  # FIXME
            else:
                key = var
                var_type = self.variable_manager.get_variable_type(var)

            if var_type is None:
                var_type = SimTypeBottom().with_arch(self.codegen.project.arch)

            unified_to_var_and_types[key].add((cvar, var_type))

        return unified_to_var_and_types

    def _referenced_variables(self) -> set:
        referenced = set()

        def visit(node):
            if isinstance(node, GoVariable):
                referenced.add(node.variable)
                if node.unified_variable is not None:
                    referenced.add(node.unified_variable)
            for child in _go_expr_children(node):
                visit(child)

        visit(self.statements)
        return referenced

    def variable_list_repr_chunks(self, indent=0):
        indent_str = self.indent_str(indent)
        referenced = self._referenced_variables()

        for variable in self.sort_local_vars(self.unified_local_vars):
            cvar_and_vartypes = self.unified_local_vars[variable]
            if variable not in referenced and not any(
                cvar.variable in referenced or cvar.unified_variable in referenced for cvar, _ in cvar_and_vartypes
            ):
                # dropped by a rewrite (e.g. a range loop's increment temporary)
                continue
            if self._is_short_declared(variable, cvar_and_vartypes):
                continue

            yield indent_str, None

            # pick the first cvariable
            # picking any cvariable is enough since highlighting works on the unified variable
            try:
                cvariable = next(iter(cvar_and_vartypes))[0]
            except StopIteration:
                # this should never happen, but pylint complains
                continue

            if variable.name:
                name = variable.name
            elif isinstance(variable, SimTemporaryVariable):
                name = f"tmp_{variable.tmp_id}"
            else:
                name = str(variable)

            # sort by the following:
            #   * if it's a a non-basic type
            #   * the number of occurrences
            #   * the repr of the type itself
            # TODO: The type selection should actually happen during variable unification
            vartypes = [x[1] for x in cvar_and_vartypes]
            count = Counter(vartypes)
            vartypes = sorted(
                count.copy(),
                key=lambda x, ct=count: (isinstance(x, (SimTypeChar, SimTypeInt, SimTypeFloat)), ct[x], repr(x)),
            )

            vla_dim = self.codegen._array_length_cexprs.get(variable)

            for i, var_type in enumerate(vartypes):
                if i == 0:
                    yield "var ", None
                    if vla_dim is not None and isinstance(var_type, SimTypeArray) and var_type.length is None:
                        # variable-length array: render ``name [dim]elem_type`` with the runtime dimension
                        yield name, cvariable
                        yield " [", None
                        yield from vla_dim.c_repr_chunks()
                        yield "]", None
                        yield go_type_str(var_type.elem_type), var_type.elem_type
                    else:
                        yield from type_to_go_repr_chunks(var_type, name=name, name_type=cvariable)
                    yield "  // ", None
                    if vla_dim is not None:
                        # the buffer lives at a synthesized register slot; show its origin instead
                        yield "alloca", None
                    else:
                        yield variable.loc_repr(self.codegen.project.arch), None
                # multiple types
                else:
                    if i == 1:
                        yield ", Other Possible Types: ", None
                    else:
                        yield ", ", None
                    if isinstance(var_type, SimType):
                        yield go_type_str(var_type), var_type
                    else:
                        yield str(var_type), var_type
            yield "\n", None

        for name, ty in self.extra_decls:
            if name in self.short_declared:
                continue
            yield indent_str, None
            yield "var ", None
            yield name, None
            yield " ", None
            yield go_type_str(ty), ty
            yield "\n", None

        if (self.unified_local_vars or self.extra_decls) and not self._all_short_declared():
            yield "\n", None

    def _is_short_declared(self, variable, cvar_and_vartypes) -> bool:
        return variable in self.short_declared or any(
            cvar.variable in self.short_declared or cvar.unified_variable in self.short_declared
            for cvar, _ in cvar_and_vartypes
        )

    def _all_short_declared(self) -> bool:
        referenced = self._referenced_variables()
        for variable, cvar_and_vartypes in self.unified_local_vars.items():
            if variable not in referenced and not any(
                cvar.variable in referenced or cvar.unified_variable in referenced for cvar, _ in cvar_and_vartypes
            ):
                continue
            if not self._is_short_declared(variable, cvar_and_vartypes):
                return False
        return all(name in self.short_declared for name, _ in self.extra_decls)

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.omit_header:
            yield from self.headerless_c_repr_chunks(indent=indent)
        else:
            yield from self.full_c_repr_chunks(indent=indent, asexpr=asexpr)

    def headerless_c_repr_chunks(self, indent=0):
        yield from self.statements.c_repr_chunks(indent=indent)
        yield "\n", None

    def _collect_referenced_struct_types(self) -> dict[int, SimStruct]:
        """
        Collect every ``SimStruct`` that is referenced by the rendered output of this function. This inclues:
        - the function prototype (argument/return types)
        - the types of all in-use variables
        - extern declarations
        We use the result to filter out struct typedefs that is not referenced.
        """
        referenced: dict[int, SimStruct] = {}

        # Function signature
        if self.functy is not None:
            for arg_type in self.functy.args or ():
                _recursively_collect_referenced_structs(arg_type, referenced)
            _recursively_collect_referenced_structs(self.functy.returnty, referenced)

        # Declared variables (locals, args, globals) that are actually used in the body. This
        # covers variable declarations and, transitively, the struct types dereferenced by field
        # accesses on those variables.
        for var in self.variables_in_use:
            _recursively_collect_referenced_structs(self.variable_manager.get_variable_type(var), referenced)
        for cvar_and_types in self.unified_local_vars.values():
            for _cvar, vartype in cvar_and_types:
                _recursively_collect_referenced_structs(vartype, referenced)

        # Extern declarations
        if self.codegen.show_externs and self.codegen.cexterns:
            for v in self.codegen.cexterns:
                if v.variable in self.variables_in_use and v.type is not None:
                    _recursively_collect_referenced_structs(v.type, referenced)

        return referenced

    def full_c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent)

        referenced_structs = self._collect_referenced_struct_types()
        referenced_struct_names = {s.name for s in referenced_structs.values() if s.name}

        name_to_structtypes = {}
        if self.codegen.show_local_types:
            local_types = [unpack_typeref(ty) for ty in self.variable_manager.types.iter_own()]
            # First, discover all (possibly nested) struct types. This must run to completion before emitting,
            # so that emission can be reordered without disturbing discovery.
            for ty in local_types:
                if isinstance(ty, SimStruct):
                    name_to_structtypes[ty.name] = ty
                    for field in _iter_struct_union_member_types(ty):
                        if isinstance(field, SimTypePointer):
                            if isinstance(field.pts_to, (SimTypeArray, SimTypeFixedSizeArray)):
                                field = field.pts_to.elem_type
                            else:
                                field = field.pts_to
                        if isinstance(field, SimStruct) and field not in local_types:
                            if field.name and not field.fields and field.name in name_to_structtypes:
                                # we use SimStruct types with empty fields to refer to already defined struct types
                                # for example, see how struct _IO_marker is defined in sim_type.py
                                continue
                            if field.name:
                                name_to_structtypes[field.name] = field
                            local_types.append(field)

            # Emit in a stable order. variable_manager.types iterates in the (run-dependent) order variables were
            # typed, so emitting in iteration order makes the output non-deterministic. Sort by the type's
            # structural layout so the ordering is deterministic AND does not change when the user renames a
            # struct or a field. Structurally identical structs (e.g. isomorphic recursive types) are broken by
            # the translator's name-independent definition order, also rename-proof; the name is only a final
            # fallback for types with no such order (e.g. library structs not produced by type inference).
            def _local_type_sort_key(ty) -> tuple:
                order = getattr(ty, "_def_order", None)
                tiebreak = (
                    (0, order) if order is not None else (1, ty.name if isinstance(ty, SimStruct) and ty.name else "")
                )
                return (type_layout_key(ty), tiebreak)

            emitted_struct_names: set[str] = set()
            for ty in sorted(local_types, key=_local_type_sort_key):
                # drop unreferenced structs, anonymous ones, opaque (field-less) ones and Go builtins
                if (
                    not isinstance(ty, SimStruct)
                    or _is_anonymous_struct_or_union(ty)
                    or not ty.fields
                    or _is_go_builtin_struct(ty)
                    or ty.name not in referenced_struct_names
                ):
                    continue
                if ty.name in emitted_struct_names:
                    # multiple definitions share a name, which is probably because:
                    # - we incorrectly inferred types of fields of a struct with a library definition;
                    # - multiple types exist under the same name (from different libraries).
                    # we will fix them when encountering these cases.
                    l.warning(
                        "Multiple definitions of struct %s in function %s. Only the first one is emitted.",
                        ty.name,
                        self.name,
                    )
                    continue
                emitted_struct_names.add(ty.name)
                yield from type_to_go_repr_chunks(
                    ty, full=True, indent_str=indent_str, indent_delta=self.codegen.indent_delta
                )

        if self.codegen.show_externs and self.codegen.cexterns:
            # Emit struct definitions for types used by externs
            extern_types = []
            defined_struct_names = (
                set(name_to_structtypes.keys())  # type: ignore[possibly-undefined]
                if self.codegen.show_local_types
                else set()
            )
            # iterate externs in a stable, rename-independent order (by variable address) so the emission order of the
            # discovered struct types are deterministic
            for v in sorted(self.codegen.cexterns, key=cextern_sort_key):
                if v.variable not in self.variables_in_use or v.type is None:
                    continue
                ty = unpack_typeref(v.type)
                # Unwrap all pointer/array
                while isinstance(ty, (SimTypePointer, SimTypeArray, SimTypeFixedSizeArray)):
                    ty = unpack_typeref(ty.pts_to) if isinstance(ty, SimTypePointer) else unpack_typeref(ty.elem_type)
                if isinstance(ty, SimStruct) and ty not in extern_types:
                    extern_types.append(ty)

            # Discover all nested structs
            # we rely on the behavior that if you extend a list while it is iterating you will see those values
            for ty in extern_types:  # pylint:disable=modified-iterating-list
                for field in ty.fields.values():
                    field = unpack_typeref(field)
                    while isinstance(field, (SimTypePointer, SimTypeArray, SimTypeFixedSizeArray)):
                        if isinstance(field, SimTypePointer):
                            field = unpack_typeref(field.pts_to)
                        else:
                            field = unpack_typeref(field.elem_type)
                    if isinstance(field, SimStruct) and field not in extern_types:
                        if field.name and not field.fields and field.name in defined_struct_names:
                            continue
                        extern_types.append(field)  # pylint:disable=modified-iterating-list

            # Emit in reverse order: nested structs first
            for ty in reversed(extern_types):
                if ty.name in defined_struct_names or not ty.fields or _is_go_builtin_struct(ty):
                    continue
                defined_struct_names.add(ty.name)
                yield from type_to_go_repr_chunks(
                    ty, full=True, indent_str=indent_str, indent_delta=self.codegen.indent_delta
                )

            # Emit global declarations as one var block (ordered by variable address so renames do not reshuffle them)
            externs = [
                v for v in sorted(self.codegen.cexterns, key=cextern_sort_key) if v.variable in self.variables_in_use
            ]
            if externs:
                yield indent_str, None
                yield "var (\n", None
                extern_indent = indent_str + " " * self.codegen.indent_delta
                for v in externs:
                    varname = v.c_repr() if v.type is None else v.variable.name
                    if v.type is None:
                        yield extern_indent, None
                        yield varname, v
                        yield " <unknown-type>", None
                    else:
                        yield from type_to_go_repr_chunks(
                            v.type, name=varname, name_type=v, full=False, indent_str=extern_indent
                        )
                    yield "\n", None
                yield indent_str, None
                yield ")\n\n", None

        yield indent_str, None

        # header comments (if they exist)
        assert self.codegen.cfunc is not None and self.codegen.cfunc.addr is not None
        header_comments = self.codegen.kb.comments.get(self.codegen.cfunc.addr, [])
        if header_comments:
            header_cmt = self._line_wrap_comment("".join(header_comments))
            yield header_cmt, None

        if self.codegen._func.is_plt:
            yield "// attributes: PLT stub\n", None

        yield "func ", None
        params = list(zip(self.functy.args, self.arg_list))
        paren = GoClosingObject("(")
        brace = GoClosingObject("{")
        method_name = _go_method_name(self.name, self.codegen)
        if method_name is not None and params:
            # methods: func (recv T) Name(...)
            recv_type, recv_var = params.pop(0)
            variable = recv_var.unified_variable or recv_var.variable
            recv_paren = GoClosingObject("(")
            yield "(", recv_paren
            yield from type_to_go_repr_chunks(recv_type, name=variable.name, name_type=recv_var, full=False)
            yield ")", recv_paren
            yield " ", None
            yield method_name, self
        else:
            yield self.name, self
        # argument list
        yield "(", paren
        for i, (arg_type, cvariable) in enumerate(params):
            if i:
                yield ", ", None

            variable = cvariable.unified_variable or cvariable.variable
            yield from type_to_go_repr_chunks(arg_type, name=variable.name, name_type=cvariable, full=False)

        yield ")", paren
        # results
        returnty = unpack_typeref(self.functy.returnty)
        if returnty is not None and not isinstance(returnty, SimTypeBottom):
            yield " ", None
            yield go_type_str(returnty), self.functy.returnty
        # function body: Go mandates the opening brace on the same line
        yield " ", None
        yield "{", brace
        yield "\n", None
        yield from self.variable_list_repr_chunks(indent=indent + self.codegen.indent_delta)
        statements = self.statements
        if isinstance(statements, GoStatements):
            container, idx = _go_leaf(statements.statements, last=True)
            if container is not None and isinstance(container[idx], GoReturn) and not container[idx].retvals:
                # a bare return at the very end of a function is implied
                container.pop(idx)
        yield from statements.c_repr_chunks(indent=indent + self.codegen.indent_delta)
        yield indent_str, None
        yield "}", brace
        yield "\n", None

    @staticmethod
    def _line_wrap_comment(comment: str, width=80) -> str:
        lines = comment.splitlines()
        wrapped_cmt = ""

        for line in lines:
            if len(line) < width:
                wrapped_cmt += line + "\n"
                continue

            for i, c in enumerate(line):
                if i % width == 0 and i != 0:
                    wrapped_cmt += "\n"
                wrapped_cmt += c

            wrapped_cmt += "\n"

        return "".join([f"// {line}\n" for line in wrapped_cmt.splitlines()])

    @staticmethod
    def sort_local_vars(local_vars: Iterable[SimVariable]) -> list[SimVariable]:
        # Order:
        # - SimRegisterVariable, ordered based on their identifiers
        # - SimStackVariables, ordered based on their stack offsets
        # - SimMemoryVariable (but not stack variables)  - we should not have global variables anyway
        reg_vars, stack_vars, mem_vars = [], [], []
        for var in local_vars:
            match var:
                case SimRegisterVariable() | SimComboRegisterVariable():
                    reg_vars.append(var)
                case SimStackVariable():
                    stack_vars.append(var)
                case SimMemoryVariable():
                    mem_vars.append(var)
                case _:
                    pass

        reg_vars = sorted(reg_vars, key=lambda v: v.ident)
        stack_vars = sorted(stack_vars, key=lambda v: (v.offset, v.ident))
        mem_vars = sorted(mem_vars, key=lambda v: (v.addr if isinstance(v.addr, int) else -1, v.ident))
        return reg_vars + stack_vars + mem_vars


def _go_block_chunks(body, indent_str: str, indent: int, codegen):
    """Render ``{`` body ``}`` with Go's brace placement; an empty body renders as ``{ }``."""
    brace = GoClosingObject("{")
    yield " ", None
    yield "{", brace
    if body is None:
        yield " ", None
        yield "}", brace
        yield "\n", None
        return
    yield "\n", None
    yield from body.c_repr_chunks(indent=indent + codegen.indent_delta)
    yield indent_str, None
    yield "}", brace
    yield "\n", None


_GO_METHOD_RE = re.compile(
    r"^(?P<pkg>.+?)\.(?:\(\*(?P<ptr_type>[^()]+)\)|(?P<type>[A-Z][^.()\[]*(?:\[[^()]*\])?))\.(?P<method>[A-Za-z_]\w*)$"
)


def _go_method_name(func_name: str, codegen=None) -> str | None:
    """``pkg.(*T).M`` / ``pkg.T.M`` -> ``M``; None for plain functions, closures and ABI wrappers."""
    if codegen is not None:
        with contextlib.suppress(Exception):
            sig = codegen.kb.go_signatures.signature(func_name)
            if sig is not None:
                return func_name.rsplit(".", 1)[-1] if sig.recv is not None else None
    m = _GO_METHOD_RE.match(func_name)
    return None if m is None else m.group("method")


def _same_variable(a, b) -> bool:
    if a.unified_variable is not None or b.unified_variable is not None:
        return a.unified_variable is not None and a.unified_variable == b.unified_variable
    return a.variable is not None and a.variable == b.variable


def _go_is_seq_field(expr, name: str) -> bool:
    """``expr`` is the ``name`` header field of a slice or string value."""
    if not (isinstance(expr, GoVariableField) and expr.field.field == name):
        return False
    return isinstance(unpack_typeref(expr.variable.type), (GoSimTypeSlice, GoSimTypeString))


def _go_is_iface_word(expr) -> bool:
    """``expr`` is the itab/type word of an interface value."""
    return (
        isinstance(expr, GoVariableField)
        and expr.field.field == "tab"
        and isinstance(unpack_typeref(expr.variable.type), GoSimTypeInterface)
    )


def _go_is_nilable(ty) -> bool:
    ty = unpack_typeref(ty)
    return isinstance(
        ty,
        (SimTypePointer, GoSimTypeInterface, GoSimTypeSlice, GoSimTypeMap, GoSimTypeChan, GoSimTypeFunc),
    )


class GoStatement(GoConstruct):  # pylint:disable=abstract-method
    """
    Represents a statement in C.
    """

    def __init__(self, tags=None, *, codegen):
        super().__init__(codegen=codegen, tags=tags)


class GoExpression(GoConstruct):
    """
    Base class for C expressions.
    """

    __slots__ = ("_type", "collapsed")

    def __init__(self, collapsed=False, tags=None, *, codegen):
        super().__init__(codegen=codegen, tags=tags)
        self._type = None
        self.collapsed = collapsed

    @property
    def type(self) -> SimType | None:
        raise NotImplementedError(f"Class {type(self)} does not implement type().")

    def set_type(self, v):
        self._type = v

    @staticmethod
    def _try_c_repr_chunks(expr):
        if hasattr(expr, "c_repr_chunks"):
            yield from expr.c_repr_chunks()
        else:
            yield str(expr), expr


class GoStatements(GoStatement):
    """
    Represents a sequence of statements in C.
    """

    __slots__ = (
        "addr",
        "statements",
    )

    def __init__(self, statements, addr=None, **kwargs):
        super().__init__(**kwargs)

        self.statements = statements
        self.addr = addr

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent)
        if self.codegen.display_block_addrs:
            yield indent_str, None
            yield f"/* Block {hex(self.addr) if self.addr is not None else 'unknown'} */", None
            yield "\n", None
        for stmt in self.statements:
            yield from stmt.c_repr_chunks(indent=indent, asexpr=asexpr)
            if asexpr:
                yield ", ", None


class GoAILBlock(GoStatement):
    """
    Represents a block of AIL statements.
    """

    __slots__ = ("block",)

    def __init__(self, block, **kwargs):
        super().__init__(**kwargs)

        self.block = block

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        r = str(self.block)
        for stmt in r.split("\n"):
            yield indent_str, None
            yield stmt, None
            yield "\n", None


class GoLoop(GoStatement):  # pylint:disable=abstract-method
    """
    Represents a loop in C.
    """

    __slots__ = ()


class GoWhileLoop(GoLoop):
    """
    Represents a while loop in C.
    """

    __slots__ = (
        "body",
        "condition",
    )

    def __init__(self, condition, body, **kwargs):
        super().__init__(**kwargs)

        self.condition = condition
        self.body = body

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "for", self
        if self.condition is not None:
            yield " ", None
            yield from self.condition.c_repr_chunks()
        yield from _go_block_chunks(self.body, indent_str, indent, self.codegen)


class GoDoWhileLoop(GoLoop):
    """
    Represents a do-while loop in C.
    """

    __slots__ = (
        "body",
        "condition",
    )

    def __init__(self, condition, body, **kwargs):
        super().__init__(**kwargs)

        self.condition = condition
        self.body = body

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        brace = GoClosingObject("{")
        inner_indent = indent + self.codegen.indent_delta
        inner_str = self.indent_str(indent=inner_indent)
        yield indent_str, None
        yield "for", self
        yield " ", None
        yield "{", brace
        yield "\n", None
        if self.body is not None:
            yield from self.body.c_repr_chunks(indent=inner_indent)
        if self.condition is not None:
            # the loop condition is tested at the end of the body
            yield inner_str, None
            yield "if ", self
            yield from GoUnaryOp("Not", self.condition, codegen=self.codegen).c_repr_chunks()
            check_brace = GoClosingObject("{")
            yield " ", None
            yield "{", check_brace
            yield "\n", None
            yield self.indent_str(indent=inner_indent + self.codegen.indent_delta), None
            yield "break\n", self
            yield inner_str, None
            yield "}", check_brace
            yield "\n", None
        yield indent_str, None
        yield "}", brace
        yield "\n", None


class GoForLoop(GoStatement):
    """
    Represents a for-loop in C.
    """

    __slots__ = (
        "body",
        "condition",
        "initializer",
        "iterator",
    )

    def __init__(self, initializer, condition, iterator, body, **kwargs):
        super().__init__(**kwargs)

        self.initializer = initializer
        self.condition = condition
        self.iterator = iterator
        self.body = body

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        brace = GoClosingObject("{")
        paren = GoClosingObject("(")

        del brace, paren
        yield indent_str, None
        yield "for", self
        if self.initializer is None and self.iterator is None:
            if self.condition is not None:
                yield " ", None
                yield from self.condition.c_repr_chunks(indent=0)
        else:
            yield " ", None
            if self.initializer is not None:
                yield from self.initializer.c_repr_chunks(indent=0, asexpr=True)
            yield "; ", None
            if self.condition is not None:
                yield from self.condition.c_repr_chunks(indent=0)
            yield ";", None
            if self.iterator is not None:
                yield " ", None
                yield from self.iterator.c_repr_chunks(indent=0, asexpr=True)
        yield from _go_block_chunks(self.body, indent_str, indent, self.codegen)


class GoRangeLoop(GoStatement):
    """``for i, v = range coll { ... }``; ``index``/``value`` may be None (rendered as ``_``)."""

    __slots__ = ("body", "collection", "declares", "index", "value")

    def __init__(self, index, value, collection, body, **kwargs):
        super().__init__(**kwargs)
        self.index = index
        self.value = value
        self.collection = collection
        self.body = body
        self.declares = False

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        yield indent_str, None
        yield "for ", self
        if self.index is None:
            yield "_", None
        else:
            yield from GoExpression._try_c_repr_chunks(self.index)
        if self.value is not None:
            yield ", ", None
            yield from GoExpression._try_c_repr_chunks(self.value)
        yield (" := range " if self.declares else " = range "), self
        yield from GoExpression._try_c_repr_chunks(self.collection)
        yield from _go_block_chunks(self.body, indent_str, indent, self.codegen)


class GoIfElse(GoStatement):
    """
    Represents an if-else construct in C.
    """

    __slots__ = (
        "condition_and_nodes",
        "cstyle_ifs",
        "else_node",
        "simplify_else_scope",
    )

    def __init__(
        self,
        condition_and_nodes: list[tuple[GoExpression, GoStatement | None]],
        else_node=None,
        simplify_else_scope=False,
        cstyle_ifs=True,
        **kwargs,
    ):
        super().__init__(**kwargs)

        self.condition_and_nodes = condition_and_nodes
        self.else_node = else_node
        self.simplify_else_scope = simplify_else_scope
        self.cstyle_ifs = cstyle_ifs

        if not self.condition_and_nodes:
            raise ValueError("You must specify at least one condition")

    @staticmethod
    def _is_single_stmt_node(node):
        return (isinstance(node, GoStatements) and len(node.statements) == 1) or isinstance(
            node, (GoBreak, GoContinue, GoReturn, GoGoto)
        )

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        brace = GoClosingObject("{")
        for i, (condition, node) in enumerate(self.condition_and_nodes):
            if i == 0:
                yield indent_str, None
            else:
                yield " else ", self
            yield "if ", self
            yield from condition.c_repr_chunks()
            yield " ", None
            yield "{", brace
            yield "\n", None
            if node is not None:
                yield from node.c_repr_chunks(indent=self.codegen.indent_delta + indent)
            yield indent_str, None
            yield "}", brace
        if self.else_node is not None:
            if self.simplify_else_scope:
                # the else branch is hoisted out of the conditional by the region simplifier
                yield "\n", None
                yield from self.else_node.c_repr_chunks(indent=indent)
                return
            yield " else ", self
            yield "{", brace
            yield "\n", None
            yield from self.else_node.c_repr_chunks(indent=indent + self.codegen.indent_delta)
            yield indent_str, None
            yield "}", brace
        yield "\n", None


class GoIfBreak(GoStatement):
    """
    Represents an if-break statement in C.
    """

    __slots__ = (
        "condition",
        "cstyle_ifs",
    )

    def __init__(self, condition, cstyle_ifs=True, **kwargs):
        super().__init__(**kwargs)

        self.condition = condition
        self.cstyle_ifs = cstyle_ifs

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        paren = GoClosingObject("(")
        brace = GoClosingObject("{")

        del paren
        yield indent_str, None
        yield "if ", self
        yield from self.condition.c_repr_chunks()
        yield " ", None
        yield "{", brace
        yield "\n", None
        yield self.indent_str(indent=indent + self.codegen.indent_delta), self
        yield "break\n", self
        yield indent_str, None
        yield "}", brace
        yield "\n", None


class GoBreak(GoStatement):
    """
    Represents a break statement in C.
    """

    __slots__ = ()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "break\n", self


class GoContinue(GoStatement):
    """
    Represents a continue statement in C.
    """

    __slots__ = ()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "continue\n", self


class GoSwitchCase(GoStatement):
    """
    Represents a switch-case statement in C.
    """

    __slots__ = ("cases", "default", "switch")

    def __init__(self, switch, cases, default, **kwargs):
        super().__init__(**kwargs)

        self.switch = switch
        self.cases: list[tuple[int | tuple[int], GoStatements]] = cases
        self.default = default

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        paren = GoClosingObject("(")
        brace = GoClosingObject("{")

        del paren
        yield indent_str, None
        yield "switch ", self
        yield from self.switch.c_repr_chunks()
        yield " ", None
        yield "{", brace
        yield "\n", None
        bodies = [case for _, case in self.cases] + ([self.default] if self.default is not None else [])
        for i, (id_or_ids, case) in enumerate(self.cases):
            yield indent_str, None
            ids = [id_or_ids] if isinstance(id_or_ids, int) else list(id_or_ids)
            yield "case " + ", ".join(str(x) for x in ids), self
            yield ":\n", None
            yield from self._case_body_chunks(case, i + 1 < len(bodies), indent)
        if self.default is not None:
            yield indent_str, None
            yield "default:\n", self
            yield from self._case_body_chunks(self.default, False, indent)
        yield indent_str, None
        yield "}", brace
        yield "\n", None

    def _case_body_chunks(self, case, has_next: bool, indent: int):
        """Go cases do not fall through: drop the trailing break and spell out an explicit fallthrough."""
        stmts = list(case.statements) if isinstance(case, GoStatements) else [case]
        falls_through = has_next
        if stmts and isinstance(stmts[-1], GoBreak):
            stmts = stmts[:-1]
            falls_through = False
        elif stmts and isinstance(stmts[-1], (GoReturn, GoGoto, GoContinue)):
            falls_through = False
        body = GoStatements(stmts, codegen=self.codegen)
        yield from body.c_repr_chunks(indent=indent + self.codegen.indent_delta)
        if falls_through:
            yield self.indent_str(indent=indent + self.codegen.indent_delta), None
            yield "fallthrough\n", self


class GoIncompleteSwitchCase(GoStatement):
    """
    Represents an incomplete switch-case construct; this only appear in the decompilation output when switch-case
    structuring fails (for whatever reason).
    """

    __slots__ = ("cases", "head")

    def __init__(self, head, cases, **kwargs):
        super().__init__(**kwargs)

        self.head = head
        self.cases: list[tuple[int, GoStatements]] = cases

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        paren = GoClosingObject("(")
        brace = GoClosingObject("{")

        yield from self.head.c_repr_chunks(indent=indent)
        yield "\n", None
        del paren
        yield indent_str, None
        yield "switch ", self
        yield "/* incomplete */", None
        yield " ", None
        yield "{", brace
        yield "\n", None

        # cases
        for case_addr, case in self.cases:
            yield indent_str, None
            yield f"case {case_addr:#x}", self
            yield ":\n", None
            yield from case.c_repr_chunks(indent=indent + self.codegen.indent_delta)

        yield indent_str, None
        yield "}", brace
        yield "\n", None


class GoAssignment(GoStatement):
    """
    a = b
    """

    __slots__ = ("declares", "lhs", "rhs")

    def __init__(self, lhs, rhs, **kwargs):
        super().__init__(**kwargs)

        self.lhs = lhs
        self.rhs = rhs
        self.declares = False  # rendered as a short variable declaration

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        if isinstance(self.lhs, GoVariableField) and (
            _go_is_seq_field(self.lhs, "len") or _go_is_seq_field(self.lhs, "cap")
        ):
            # `len(s)` is not assignable: spell the header word out
            yield from self.lhs.variable.c_repr_chunks()
            yield ".", self.lhs
            yield from self.lhs.field.c_repr_chunks()
        else:
            yield from GoExpression._try_c_repr_chunks(self.lhs)

        compound_assignment_ops = {
            "Add": "+",
            "Sub": "-",
            "Mul": "*",
            "Div": "/",
            "And": "&",
            "Xor": "^",
            "Or": "|",
            "Shr": ">>",
            "Shl": "<<",
            "Sar": ">>",
        }
        commutative_ops = {"Add", "Mul", "And", "Xor", "Or"}

        compound_expr_rhs = None
        if (
            self.codegen.use_compound_assignments
            and not self.declares
            and isinstance(self.lhs, GoVariable)
            and isinstance(self.rhs, GoBinaryOp)
            and self.rhs.op in compound_assignment_ops
        ):
            if isinstance(self.rhs.lhs, GoVariable) and _same_variable(self.lhs, self.rhs.lhs):
                compound_expr_rhs = self.rhs.rhs
            elif (
                self.rhs.op in commutative_ops
                and isinstance(self.rhs.rhs, GoVariable)
                and _same_variable(self.lhs, self.rhs.rhs)
            ):
                compound_expr_rhs = self.rhs.lhs

        if (
            compound_expr_rhs is not None
            and self.rhs.op in ("Add", "Sub")
            and isinstance(compound_expr_rhs, GoConstant)
            and compound_expr_rhs.value == 1
        ):
            yield ("++" if self.rhs.op == "Add" else "--"), self
        elif compound_expr_rhs is not None:
            # a = a + x  =>  a += x
            # a = x + a  =>  a += x
            yield f" {compound_assignment_ops[self.rhs.op]}= ", self
            yield from GoExpression._try_c_repr_chunks(compound_expr_rhs)
        else:
            yield (" := " if self.declares else " = "), self
            yield from GoExpression._try_c_repr_chunks(self.rhs)
        if not asexpr:
            yield "\n", self


class GoMethodCall(GoExpression):
    """``recv.Method(args)`` through an interface's method table."""

    __slots__ = ("args", "method", "receiver", "signature")

    def __init__(self, receiver, method: str, args, signature=None, **kwargs):
        super().__init__(**kwargs)
        self.receiver = receiver
        self.method = method
        self.args = list(args)
        if isinstance(signature, GoSimTypeFunc):
            signature = signature.signature
        self.signature = signature
        self._type = signature.returnty if signature is not None else None

    @property
    def type(self):
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        yield from GoExpression._try_c_repr_chunks(self.receiver)
        yield ".", None
        yield self.method, self
        paren = GoClosingObject("(")
        yield "(", paren
        for i, arg in enumerate(self.args):
            if i:
                yield ", ", None
            yield from GoExpression._try_c_repr_chunks(arg)
        yield ")", paren


class GoMultiAssignment(GoStatement):
    """``a, b = f()``"""

    __slots__ = ("declares", "lhs", "rhs")

    def __init__(self, lhs, rhs, **kwargs):
        super().__init__(**kwargs)
        self.lhs = list(lhs)
        self.rhs = rhs
        self.declares = False

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield self.indent_str(indent=indent), None
        for i, target in enumerate(self.lhs):
            if i:
                yield ", ", None
            yield from GoExpression._try_c_repr_chunks(target)
        yield (" := " if self.declares else " = "), self
        yield from GoExpression._try_c_repr_chunks(self.rhs)
        if not asexpr:
            yield "\n", self


class GoSelectCase:
    """One ``select`` case: a receive (``v, ok := <-ch``), a send (``ch <- x``) or the default."""

    __slots__ = ("channel", "kind", "ok", "value")

    def __init__(self, kind: str, channel=None, value=None, ok=None):
        self.kind = kind
        self.channel = channel
        self.value = value
        self.ok = ok

    def c_repr_chunks(self):
        if self.kind == "default":
            yield "default", None
            return
        if self.kind == "send":
            yield from GoExpression._try_c_repr_chunks(self.channel)
            yield " <- ", None
            yield from GoExpression._try_c_repr_chunks(self.value)
            return
        if self.value is not None or self.ok is not None:
            yield from GoExpression._try_c_repr_chunks(
                self.value
                if self.value is not None
                else GoFakeVariable("_", SimTypeBottom(), codegen=self.channel.codegen)
            )
            if self.ok is not None:
                yield ", ", None
                yield from GoExpression._try_c_repr_chunks(self.ok)
            yield " := ", None
        yield "<-", None
        yield from GoExpression._try_c_repr_chunks(self.channel)


class GoSelect(GoStatement):
    """``select { case ...: ... }``"""

    __slots__ = ("cases",)

    def __init__(self, cases, **kwargs):
        super().__init__(**kwargs)
        self.cases = list(cases)  # (GoSelectCase, GoStatements)

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        brace = GoClosingObject("{")
        yield indent_str, None
        yield "select ", self
        yield "{", brace
        yield "\n", None
        for case, body in self.cases:
            yield indent_str, None
            if case.kind != "default":
                yield "case ", self
            yield from case.c_repr_chunks()
            yield ":", None
            yield "\n", None
            yield from body.c_repr_chunks(indent=indent + INDENT_DELTA)
        yield indent_str, None
        yield "}", brace
        yield "\n", self


class GoTypeSwitch(GoStatement):
    """``switch x := v.(type) { case T: ... default: ... }``"""

    __slots__ = ("bound_name", "cases", "default", "value")

    def __init__(self, value, bound_name: str | None, cases, default, **kwargs):
        super().__init__(**kwargs)
        self.value = value
        self.bound_name = bound_name  # None when no case reads the asserted value
        self.cases = list(cases)  # (type name, GoStatements)
        self.default = default

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        brace = GoClosingObject("{")
        yield indent_str, None
        yield "switch ", self
        if self.bound_name is not None:
            yield self.bound_name, self
            yield " := ", None
        yield from GoExpression._try_c_repr_chunks(self.value)
        yield ".(type) ", None
        yield "{", brace
        yield "\n", None
        for type_name, body in self.cases:
            yield indent_str, None
            yield "case ", self
            yield type_name, self
            yield ":", None
            yield "\n", None
            yield from body.c_repr_chunks(indent=indent + INDENT_DELTA)
        if self.default is not None:
            yield indent_str, None
            yield "default:", self
            yield "\n", None
            yield from self.default.c_repr_chunks(indent=indent + INDENT_DELTA)
        yield indent_str, None
        yield "}", brace
        yield "\n", self


class GoExpressionStatement(GoStatement):
    """
    Wraps a GoExpression so it can be used as a standalone statement.

    expr;
    """

    __slots__ = ("expr", "returning")

    def __init__(self, expr: GoExpression, returning: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.expr = expr
        self.returning = returning

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield from self.expr.c_repr_chunks(indent=0)
        if not asexpr:
            if not self.returning:
                yield " // does not return", None
            yield "\n", None


class GoFunctionCall(GoExpression):
    """
    func(arg0, arg1)

    :ivar Function callee_func:  The function getting called.
    """

    __slots__ = (
        "args",
        "callee_func",
        "callee_target",
        "show_demangled_name",
        "show_disambiguated_name",
        "site_returnty",
    )

    def __init__(
        self,
        callee_target,
        callee_func,
        args,
        show_demangled_name=True,
        show_disambiguated_name: bool = True,
        tags=None,
        *,
        codegen,
        **kwargs,
    ):
        super().__init__(tags=tags, codegen=codegen, **kwargs)

        self.callee_target = callee_target
        self.callee_func: Function | None = callee_func
        self.args = args if args is not None else []
        self.show_demangled_name = show_demangled_name
        self.show_disambiguated_name = show_disambiguated_name
        # the result type of the call-site prototype (builtins and rewritten runtime calls)
        self.site_returnty: SimType | None = None

    @property
    def prettify_thiscall(self) -> bool:
        if self.codegen is None:
            return False
        return self.codegen.prettify_thiscall

    @property
    def prototype(self) -> SimTypeFunction | None:  # TODO there should be a prototype for each callsite!
        if self.callee_func is not None and self.callee_func.prototype is not None:
            proto = self.callee_func.prototype
            if self.callee_func.prototype_libname is not None:
                # we need to deref the prototype in case it uses SimTypeRef internally
                proto = cast(SimTypeFunction, dereference_simtype_by_lib(proto, self.callee_func.prototype_libname))
            return proto
        returnty = SimTypeInt(signed=False)
        # an argument that is itself a call to a function without a result has no type
        args = [arg.type if arg.type is not None else SimTypeBottom(label="void") for arg in self.args]
        return SimTypeFunction(args, returnty).with_arch(self.codegen.project.arch)

    @property
    def prototype_returnty(self) -> SimType:
        """
        Returns returnty and avoids creating the SimTypeFunction instance if the function prototype is not available.
        Instead of self.prototype.returnty, you should use self.prototype_returnty for better performance.
        """
        if self.callee_func is not None and self.callee_func.prototype is not None:
            return self.prototype.returnty  # type: ignore
        if self.site_returnty is not None:
            return self.site_returnty
        result_type = call_tag(self, "go_result_type") if isinstance(self.callee_target, str) else None
        if result_type is not None:
            # a builtin produced by GoBuiltinRewriter
            with contextlib.suppress(Exception):
                return self.codegen.kb.go_signatures.type(result_type).with_arch(self.codegen.project.arch)
        return SimTypeInt(signed=False).with_arch(self.codegen.project.arch)

    @property
    def type(self):
        return self.prototype_returnty

    def _is_target_ambiguous(self, func_name: str) -> bool:
        """
        Check for call target name ambiguity.
        """
        caller, callee = self.codegen._func, self.callee_func

        assert self.codegen._variables_in_use is not None

        for var in self.codegen._variables_in_use.values():
            if func_name == var.name:
                return True

        # FIXME: Handle name mangle
        if callee is not None:
            func_addrs = self.codegen.kb.functions.get_addrs_by_name(callee.name)
            for func_addr in func_addrs:
                if func_addr != callee.addr:
                    func = self.codegen.kb.functions.get_by_addr(func_addr, meta_only=True)
                    if caller.binary is not callee.binary or func.binary is callee.binary:
                        return True

        return False

    @staticmethod
    def _is_func_likely_method(func_name: str, rust: bool) -> bool:
        if "::" not in func_name:
            return False
        chunks = func_name.split("::")
        if rust and re.match(r"[A-Z][a-zA-Z0-9_]*", chunks[-2]) is None:
            # let's say that rust structs are always UpperCamelCase
            return False
        return re.match(r"[a-zA-Z_][a-zA-Z0-9_]*", chunks[-1]) is not None

    def c_repr_chunks(self, indent=0, asexpr=False):
        if (builtin_chunks := render_builtin_call_value(self)) is not None:
            yield from builtin_chunks
            return
        if (chunks := render_builtin_call(self)) is not None:
            yield from chunks
            return
        if self.callee_func is not None:
            func_name = self.callee_func.name
            if (
                self.prettify_thiscall
                and self.args
                and self._is_func_likely_method(func_name, self.callee_func.is_rust_function())
            ):
                func_name = self.callee_func.short_name
                yield from self._c_repr_chunks_thiscall(func_name)
                return
            if self.show_disambiguated_name and self._is_target_ambiguous(func_name):
                func_name = self.callee_func.get_unambiguous_name(display_name=func_name)

            yield func_name, self
        elif isinstance(self.callee_target, str):
            yield self.callee_target, self
        elif isinstance(self.callee_target, GoDirtyExpression):
            # The call target is an opaque intrinsic/syscall placeholder (e.g. __debugbreak,
            # syscall). Render just its name; the parentheses + args are emitted below. This
            # also guarantees the internal "[D] ..." marker never reaches the output.
            name = self.callee_target.intrinsic_name()
            yield (name if name is not None else "/* unsupported call */"), self
        else:
            chunks = list(GoExpression._try_c_repr_chunks(self.callee_target))
            if isinstance(self.callee_target, (GoUnaryOp, GoBinaryOp)):
                yield "(", None
            yield from chunks
            if isinstance(self.callee_target, (GoUnaryOp, GoBinaryOp)):
                yield ")", None

        paren = GoClosingObject("(")
        yield "(", paren

        # builtins such as make/new take a type as their first argument
        type_args = list(call_tag(self, "go_type_args", ()))
        for i, type_arg in enumerate(type_args):
            if i:
                yield ", ", None
            yield str(type_arg), None
        for i, arg in enumerate(self.args):
            if i or type_args:
                yield ", ", None
            if i == len(self.args) - 1 and isinstance(arg, GoSliceLiteral) and self._is_variadic():
                # a variadic argument list built by the caller
                yield from arg.elem_chunks()
                continue
            yield from GoExpression._try_c_repr_chunks(arg)
        if self.args and call_tag(self, "go_ellipsis", False):
            # append(s, t...)
            yield "...", None

        yield ")", paren

    def _is_variadic(self) -> bool:
        proto = self.callee_func.prototype if self.callee_func is not None else None
        return bool(getattr(proto, "variadic", False))

    def _c_repr_chunks_thiscall(self, func_name: str):
        # The first argument is the `this` pointer
        assert self.args
        this_ref = self.args[0]
        if isinstance(this_ref, GoUnaryOp) and this_ref.op == "Reference":
            yield from GoExpression._try_c_repr_chunks(this_ref.operand)
        else:
            yield from GoExpression._try_c_repr_chunks(this_ref)

        if func_name != "<ctor>":
            yield ".", None
            yield func_name, self

        # the remaining arguments
        paren = GoClosingObject("(")
        yield "(", paren

        for i, arg in enumerate(self.args):
            if i == 0:
                continue
            if i > 1:
                yield ", ", None
            yield from GoExpression._try_c_repr_chunks(arg)

        yield ")", paren


class GoReturn(GoStatement):
    """``return`` with zero, one or several result expressions."""

    __slots__ = ("retvals",)

    def __init__(self, retval, **kwargs):
        super().__init__(**kwargs)

        if retval is None:
            self.retvals = []
        elif isinstance(retval, (list, tuple)):
            self.retvals = list(retval)
        else:
            self.retvals = [retval]

    @property
    def retval(self):
        return self.retvals[0] if self.retvals else None

    @retval.setter
    def retval(self, v):
        self.retvals = [] if v is None else [v]

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        if not self.retvals:
            yield indent_str, None
            yield "return\n", self
        else:
            yield indent_str, None
            yield "return ", self
            for i, retval in enumerate(self.retvals):
                if i:
                    yield ", ", None
                yield from retval.c_repr_chunks()
            yield "\n", self


class GoGoto(GoStatement):
    __slots__ = (
        "target",
        "target_idx",
    )

    def __init__(self, target, target_idx, **kwargs):
        super().__init__(**kwargs)

        if isinstance(target, GoConstant) and isinstance(target.value, int):
            # unpack target
            target = target.value

        self.target: int | GoExpression = target
        self.target_idx = target_idx

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        lbl = None
        if self.codegen is not None and isinstance(self.target, int):
            lbl = self.codegen.map_addr_to_label.get((self.target, self.target_idx))

        yield indent_str, None
        if self.codegen.comment_gotos:
            yield "// ", None
        yield "goto ", self
        if lbl is None:
            if isinstance(self.target, int):
                yield f"LABEL_{self.target:#x}", None
            else:
                # Go has no computed goto
                yield "/* *", None
                yield from self.target.c_repr_chunks()
                yield " */", None
        else:
            yield lbl.name, lbl
        yield "\n", None


class GoUnsupportedStatement(GoStatement):
    """
    A wrapper for unsupported AIL statement.
    """

    __slots__ = ("stmt",)

    def __init__(self, stmt, **kwargs):
        super().__init__(**kwargs)

        self.stmt = stmt

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield str(self.stmt), None
        yield "\n", None


class GoDirtyStatement(GoExpression):
    __slots__ = ("dirty",)

    def __init__(self, dirty: GoDirtyExpression, **kwargs):
        super().__init__(**kwargs)
        self.dirty = dirty

    @property
    def type(self):
        return SimTypeInt().with_arch(self.codegen.project.arch)

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield from self.dirty.c_repr_chunks()
        yield "\n", None


class GoLabel(GoStatement):
    """
    Represents a label in C code.
    """

    __slots__ = ("name",)

    def __init__(self, name: str, **kwargs):
        super().__init__(**kwargs)
        self.name = name

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield self.name, self
        yield ":", None
        yield "\n", None


class GoStructField(GoExpression):
    __slots__ = (
        "field",
        "offset",
        "struct_type",
    )

    def __init__(self, struct_type: SimStruct, offset: int, field: str, **kwargs):
        super().__init__(**kwargs)

        self.struct_type = struct_type
        self.offset = offset
        self.field = field

    @property
    def type(self):
        return self.struct_type.fields[self.field]

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        yield str(self.field), self


class GoFakeVariable(GoExpression):
    """
    An uninterpreted name to display in the decompilation output. Pretty much always represents an error?
    """

    __slots__ = ("name",)

    def __init__(self, name: str, ty: SimType, **kwargs):
        super().__init__(**kwargs)
        self.name = name
        self._type = ty.with_arch(self.codegen.project.arch)

    @property
    def type(self):
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield self.name, self


class GoVariable(GoExpression):
    """
    GoVariable represents access to a variable with the specified type (`variable_type`).

    `variable` must be a SimVariable.
    """

    __slots__ = (
        "unified_variable",
        "variable",
        "variable_type",
        "vvar_id",
    )

    def __init__(self, variable: SimVariable, unified_variable=None, variable_type=None, vvar_id=None, **kwargs):
        super().__init__(**kwargs)

        self.variable: SimVariable = variable
        self.unified_variable: SimVariable | None = unified_variable
        self.variable_type: SimType | None = (
            variable_type.with_arch(self.codegen.project.arch) if variable_type is not None else None
        )
        self.vvar_id = vvar_id

    @property
    def type(self):
        return self.variable_type

    @property
    def name(self):
        v = self.variable if self.unified_variable is None else self.unified_variable

        if v.name:
            return v.name
        if isinstance(v, SimTemporaryVariable):
            return f"tmp_{v.tmp_id}"
        return str(v)

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield self.name, self
        if self.codegen.display_vvar_ids:
            yield f"<vvar_{self.vvar_id}>", self


class GoIndexedVariable(GoExpression):
    """
    Represent a variable (an array) that is indexed.
    """

    def __init__(self, variable: GoExpression, index: GoExpression, variable_type=None, **kwargs):
        super().__init__(**kwargs)
        self.variable = variable
        self.index: GoExpression = index
        self._type = variable_type

        if self._type is None and self.variable.type is not None:
            u = unpack_typeref(self.variable.type)
            if isinstance(u, SimTypePointer):
                # special case: (&array)[x]
                u = u.pts_to.elem_type if isinstance(u.pts_to, (SimTypeArray, SimTypeFixedSizeArray)) else u.pts_to
                u = unpack_typeref(u)
            elif isinstance(u, (SimTypeArray, SimTypeFixedSizeArray)):
                u = u.elem_type
                u = unpack_typeref(u)
            else:
                u = None  # this should REALLY be an assert false
            self._type = u

    @property
    def type(self):
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return

        bracket = GoClosingObject("[")
        base = self.variable
        if _go_is_seq_field(base, "ptr"):
            # indexing through a slice/string data pointer is indexing the slice/string
            base = base.variable
        if not isinstance(base, (GoVariable, GoVariableField)):
            yield "(", None
        yield from base.c_repr_chunks()
        if not isinstance(base, (GoVariable, GoVariableField)):
            yield ")", None
        yield "[", bracket
        yield from GoExpression._try_c_repr_chunks(self.index)
        yield "]", bracket


class GoVariableField(GoExpression):
    """
    Represent a field of a variable.
    """

    def __init__(self, variable: GoExpression, field: GoStructField, var_is_ptr: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.variable = variable
        self.field = field
        self.var_is_ptr = var_is_ptr

    @property
    def type(self):
        return self.field.type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        if _go_is_seq_field(self, "len") or _go_is_seq_field(self, "cap"):
            paren = GoClosingObject("(")
            yield self.field.field, self
            yield "(", paren
            yield from self.variable.c_repr_chunks()
            yield ")", paren
            return
        yield from self.variable.c_repr_chunks()
        yield ".", self
        yield from self.field.c_repr_chunks()


class GoUnaryOp(GoExpression):
    """
    Unary operations.
    """

    __slots__ = (
        "op",
        "operand",
    )

    def __init__(self, op, operand: GoExpression, **kwargs):
        super().__init__(**kwargs)

        self.op = op
        self.operand = operand

        if operand.type is not None:
            var_type = unpack_typeref(operand.type)
            if op == "Reference":
                self._type = SimTypePointer(var_type).with_arch(self.codegen.project.arch)
            elif op == "Dereference":
                if isinstance(var_type, SimTypePointer):
                    self._type = unpack_typeref(var_type.pts_to)
                elif isinstance(var_type, (SimTypeArray, SimTypeFixedSizeArray)):
                    self._type = unpack_typeref(var_type.elem_type)

    @property
    def type(self):
        if self._type is None and self.operand is not None and hasattr(self.operand, "type"):
            self._type = self.operand.type
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return

        OP_MAP = {
            "Not": self._c_repr_chunks_not,
            "Neg": self._c_repr_chunks_neg,
            "BitwiseNeg": self._c_repr_chunks_bitwiseneg,
            "Reference": self._c_repr_chunks_reference,
            "Dereference": self._c_repr_chunks_dereference,
            "Clz": self._c_repr_chunks_clz,
        }

        handler = OP_MAP.get(self.op)
        if handler is not None:
            yield from handler()
        else:
            yield f"UnaryOp {self.op}", self

    #
    # Handlers
    #

    def _c_repr_chunks_not(self):
        yield "!", self
        if isinstance(self.operand, GoBinaryOp):
            paren = GoClosingObject("(")
            yield "(", paren
            yield from GoExpression._try_c_repr_chunks(self.operand)
            yield ")", paren
        else:
            yield from GoExpression._try_c_repr_chunks(self.operand)

    def _c_repr_chunks_bitwiseneg(self):
        yield "^", self
        yield from self._operand_chunks()

    def _operand_chunks(self):
        if isinstance(self.operand, (GoBinaryOp, GoITE)):
            paren = GoClosingObject("(")
            yield "(", paren
            yield from GoExpression._try_c_repr_chunks(self.operand)
            yield ")", paren
        else:
            yield from GoExpression._try_c_repr_chunks(self.operand)

    def _c_repr_chunks_neg(self):
        yield "-", self
        yield from self._operand_chunks()

    def _c_repr_chunks_reference(self):
        yield "&", self
        yield from self._operand_chunks()

    def _c_repr_chunks_dereference(self):
        yield "*", self
        yield from self._operand_chunks()

    def _c_repr_chunks_clz(self):
        paren = GoClosingObject("(")
        yield "Clz", self
        yield "(", paren
        yield from GoExpression._try_c_repr_chunks(self.operand)
        yield ")", paren


class GoBinaryOp(GoExpression):
    """
    Binary operations.
    """

    __slots__ = ("_cstyle_null_cmp", "common_type", "lhs", "op", "rhs")

    def __init__(self, op, lhs, rhs, **kwargs):
        super().__init__(**kwargs)

        self.op = op
        self.lhs = lhs
        self.rhs = rhs
        self._cstyle_null_cmp = self.codegen.cstyle_null_cmp

        self.common_type = self.compute_common_type(self.op, self.lhs.type, self.rhs.type)
        if self.op.startswith("Cmp"):
            self._type = SimTypeChar().with_arch(self.codegen.project.arch)
        else:
            self._type = self.common_type

    @staticmethod
    def compute_common_type(op: str, lhs_ty: SimType, rhs_ty: SimType) -> SimType:
        # C spec https://www.open-std.org/jtc1/sc22/wg14/www/docs/n2596.pdf 6.3.1.8 Usual arithmetic conversions
        rhs_ptr = isinstance(rhs_ty, SimTypePointer)
        lhs_ptr = isinstance(lhs_ty, SimTypePointer)
        rhs_cls = isinstance(unpack_typeref(rhs_ty), SimCppClass)
        lhs_cls = isinstance(unpack_typeref(lhs_ty), SimCppClass)

        if lhs_cls:
            return lhs_ty
        if rhs_cls:
            return rhs_ty

        if op in ("Add", "Sub"):
            if lhs_ptr and rhs_ptr:
                return SimTypeLength().with_arch(rhs_ty._arch)
            if lhs_ptr:
                return lhs_ty
            if rhs_ptr:
                return rhs_ty

        if lhs_ptr or rhs_ptr:
            # uh oh!
            return SimTypeLength().with_arch(rhs_ty._arch)

        if lhs_ty == rhs_ty:
            return lhs_ty

        lhs_signed = getattr(lhs_ty, "signed", None)
        rhs_signed = getattr(rhs_ty, "signed", None)
        # uhhhhhhhhhh idk
        if lhs_signed is None:
            return lhs_ty
        if rhs_signed is None:
            return rhs_ty

        if lhs_signed == rhs_signed:
            if lhs_ty.size > rhs_ty.size:  # type: ignore[operator]
                return lhs_ty
            return rhs_ty

        if lhs_signed:
            signed_ty = lhs_ty
            unsigned_ty = rhs_ty
        else:
            signed_ty = rhs_ty
            unsigned_ty = lhs_ty

        if unsigned_ty.size >= signed_ty.size:  # type: ignore[operator]
            return unsigned_ty
        if signed_ty.size > unsigned_ty.size:  # type: ignore[operator]
            return signed_ty
        # uh oh!!
        return signed_ty

    @property
    def type(self):
        return self._type

    @property
    def op_precedence(self):
        # Go operator precedence (lowest first)
        precedence_list = [
            ["Concat"],
            ["LogicalOr"],
            ["LogicalAnd"],
            [
                "CmpEQ",
                "CmpNE",
                "CmpLE",
                "CmpLT",
                "CmpGT",
                "CmpGE",
                "CmpLEs",
                "CmpLTs",
                "CmpGTs",
                "CmpGEs",
                "LogicalXor",
            ],
            ["Add", "Sub", "Or", "Xor"],
            ["Mul", "Div", "Mod", "Shl", "Shr", "Sar", "And"],
            ["SBorrow", "SCarry", "Carry"],
        ]
        for i, sublist in enumerate(precedence_list):
            if self.op in sublist:
                return i
        return len(precedence_list)

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return

        OP_MAP = {
            "Add": self._c_repr_chunks_add,
            "Sub": self._c_repr_chunks_sub,
            "Mul": self._c_repr_chunks_mul,
            "Mull": self._c_repr_chunks_mull,
            "Div": self._c_repr_chunks_div,
            "Mod": self._c_repr_chunks_mod,
            "And": self._c_repr_chunks_and,
            "Xor": self._c_repr_chunks_xor,
            "Or": self._c_repr_chunks_or,
            "Shr": self._c_repr_chunks_shr,
            "Shl": self._c_repr_chunks_shl,
            "Sar": self._c_repr_chunks_sar,
            "LogicalAnd": self._c_repr_chunks_logicaland,
            "LogicalOr": self._c_repr_chunks_logicalor,
            "LogicalXor": self._c_repr_chunks_logicalxor,
            "CmpLE": self._c_repr_chunks_cmple,
            "CmpLEs": self._c_repr_chunks_cmple,
            "CmpLT": self._c_repr_chunks_cmplt,
            "CmpLTs": self._c_repr_chunks_cmplt,
            "CmpGT": self._c_repr_chunks_cmpgt,
            "CmpGTs": self._c_repr_chunks_cmpgt,
            "CmpGE": self._c_repr_chunks_cmpge,
            "CmpGEs": self._c_repr_chunks_cmpge,
            "CmpEQ": self._c_repr_chunks_cmpeq,
            "CmpNE": self._c_repr_chunks_cmpne,
            "Concat": self._c_repr_chunks_concat,
            "Rol": self._c_repr_chunks_rol,
            "Ror": self._c_repr_chunks_ror,
        }

        handler = OP_MAP.get(self.op)
        if handler is not None:
            yield from handler()
        else:
            yield from self._c_repr_chunks_opfirst(self.op)

    def _has_const_null_rhs(self) -> bool:
        return isinstance(self.rhs, GoConstant) and self.rhs.value == 0

    #
    # Handlers
    #

    def _c_repr_chunks(self, op):
        # lhs
        if isinstance(self.lhs, GoBinaryOp) and self.op_precedence > self.lhs.op_precedence:
            paren = GoClosingObject("(")
            yield "(", paren
            yield from self._try_c_repr_chunks(self.lhs)
            yield ")", paren
        else:
            yield from self._try_c_repr_chunks(self.lhs)

        # operator
        yield op, self

        # rhs
        if isinstance(self.rhs, GoBinaryOp) and self.op_precedence > self.rhs.op_precedence - (
            1 if self.op in ["Sub", "Div"] else 0
        ):
            paren = GoClosingObject("(")
            yield "(", paren
            yield from self._try_c_repr_chunks(self.rhs)
            yield ")", paren
        else:
            yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_opfirst(self, op):
        yield op, self
        paren = GoClosingObject("(")
        yield "(", paren
        yield from self._try_c_repr_chunks(self.lhs)
        yield ", ", None
        yield from self._try_c_repr_chunks(self.rhs)
        yield ")", paren

    def _c_repr_chunks_add(self):
        yield from self._c_repr_chunks(" + ")

    def _c_repr_chunks_sub(self):
        yield from self._c_repr_chunks(" - ")

    def _c_repr_chunks_mul(self):
        yield from self._c_repr_chunks(" * ")

    def _c_repr_chunks_mull(self):
        yield from self._c_repr_chunks(" * ")

    def _c_repr_chunks_div(self):
        yield from self._c_repr_chunks(" / ")

    def _c_repr_chunks_divmod(self):
        yield from self._c_repr_chunks(" /m ")

    def _c_repr_chunks_mod(self):
        yield from self._c_repr_chunks(" % ")

    def _c_repr_chunks_and(self):
        yield from self._c_repr_chunks(" & ")

    def _c_repr_chunks_xor(self):
        yield from self._c_repr_chunks(" ^ ")

    def _c_repr_chunks_or(self):
        yield from self._c_repr_chunks(" | ")

    def _c_repr_chunks_shr(self):
        yield from self._c_repr_chunks(" >> ")

    def _c_repr_chunks_shl(self):
        yield from self._c_repr_chunks(" << ")

    def _c_repr_chunks_sar(self):
        # Sar is an arithmetic (signed) right shift, but it renders as the C `>>` operator, which only performs an
        # arithmetic shift when its left operand is signed. If the left operand renders as an unsigned integer, emit
        # an explicit signed cast; otherwise `>>` would be a logical shift and silently drop the sign bit. The cast is
        # emitted here at render time because the earlier typecast-collapsing passes treat same-size signed/unsigned
        # integer casts as redundant and would strip a cast added during code generation.
        lhs_ty = self.lhs.type
        if (
            isinstance(lhs_ty, (SimTypeInt, SimTypeChar, SimTypeNum))
            and getattr(lhs_ty, "signed", None) is False
            and lhs_ty.size is not None
        ):
            signed_ty = self.codegen.default_simtype_from_bits(lhs_ty.size, signed=True)
            paren = GoClosingObject("(")
            yield go_type_str(signed_ty), signed_ty
            yield "(", paren
            yield from self._try_c_repr_chunks(self.lhs)
            yield ")", paren
            yield " >> ", self
            if isinstance(self.rhs, GoBinaryOp) and self.op_precedence > self.rhs.op_precedence:
                paren2 = GoClosingObject("(")
                yield "(", paren2
                yield from self._try_c_repr_chunks(self.rhs)
                yield ")", paren2
            else:
                yield from self._try_c_repr_chunks(self.rhs)
            return
        yield from self._c_repr_chunks(" >> ")

    def _c_repr_chunks_logicaland(self):
        yield from self._c_repr_chunks(" && ")

    def _c_repr_chunks_logicalor(self):
        yield from self._c_repr_chunks(" || ")

    def _c_repr_chunks_logicalxor(self):
        yield from self._c_repr_chunks(" != ")

    def _c_repr_chunks_cmple(self):
        yield from self._c_repr_chunks(" <= ")

    def _c_repr_chunks_cmplt(self):
        yield from self._c_repr_chunks(" < ")

    def _c_repr_chunks_cmpgt(self):
        yield from self._c_repr_chunks(" > ")

    def _c_repr_chunks_cmpge(self):
        yield from self._c_repr_chunks(" >= ")

    def _nil_compared_value(self):
        """The Go value compared against nil, or None when this is not a nil comparison."""
        if not self._has_const_null_rhs():
            return None
        lhs = self.lhs
        if _go_is_iface_word(lhs):
            return lhs.variable
        return lhs if _go_is_nilable(lhs.type) else None

    def _c_repr_chunks_cmpeq(self):
        value = self._nil_compared_value()
        if value is not None:
            yield from self._try_c_repr_chunks(value)
            yield " == nil", self
        else:
            yield from self._c_repr_chunks(" == ")

    def _c_repr_chunks_cmpne(self):
        value = self._nil_compared_value()
        if value is not None:
            yield from self._try_c_repr_chunks(value)
            yield " != nil", self
        else:
            yield from self._c_repr_chunks(" != ")

    def _c_repr_chunks_concat(self):
        yield from self._c_repr_chunks(" CONCAT ")

    def _c_repr_chunks_rol(self):
        yield "bits.RotateLeft", self
        paren = GoClosingObject("(")
        yield "(", paren
        yield from self._try_c_repr_chunks(self.lhs)
        yield ", ", None
        yield from self._try_c_repr_chunks(self.rhs)
        yield ")", paren

    def _c_repr_chunks_ror(self):
        yield "bits.RotateRight", self
        paren = GoClosingObject("(")
        yield "(", paren
        yield from self._try_c_repr_chunks(self.lhs)
        yield ", ", None
        yield from self._try_c_repr_chunks(self.rhs)
        yield ")", paren


class GoTypeCast(GoExpression):
    __slots__ = (
        "dst_type",
        "expr",
        "src_type",
    )

    def __init__(self, src_type: SimType | None, dst_type: SimType, expr: GoExpression, **kwargs):
        super().__init__(**kwargs)

        src_type = src_type or expr.type or dst_type
        self.src_type = src_type.with_arch(self.codegen.project.arch)
        self.dst_type = dst_type.with_arch(self.codegen.project.arch)
        self.expr = expr

    @property
    def type(self):
        if self._type is None:
            return self.dst_type
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        paren = GoClosingObject("(")
        if not self.codegen.show_casts:
            yield from GoExpression._try_c_repr_chunks(self.expr)
            return
        type_str = go_type_str(self.dst_type)
        if type_str.startswith(("*", "<-", "func(")):
            # a conversion to a pointer, receive-only channel or func type needs the type parenthesized
            type_paren = GoClosingObject("(")
            yield "(", type_paren
            yield type_str, self.dst_type
            yield ")", type_paren
        else:
            yield type_str, self.dst_type
        yield "(", paren
        yield from GoExpression._try_c_repr_chunks(self.expr)
        yield ")", paren


class GoConstant(GoExpression):
    __slots__ = (
        "reference_values",
        "value",
    )

    def __init__(self, value, type_: SimType, reference_values=None, **kwargs):
        super().__init__(**kwargs)

        self.value: int | float | str = value
        self._type = type_.with_arch(self.codegen.project.arch)
        self.reference_values = reference_values

    @property
    def _ident(self) -> IdentType:
        ins_addr = (self.tags or {}).get("ins_addr", -1)
        ty_enum = CConstantType.INT
        if isinstance(self.value, float):
            ty_enum = CConstantType.FLOAT
        elif isinstance(self.value, str):
            ty_enum = CConstantType.STRING
        return ins_addr, ty_enum.value, str(self.value)

    @property
    def fmt(self):
        return self.codegen.const_formats.get(self._ident, {})

    @property
    def _fmt_setter(self):
        result = self.codegen.const_formats.get(self._ident, None)
        if result is None:
            result = {}
            self.codegen.const_formats[self._ident] = result

        return result

    @property
    def fmt_hex(self):
        result = self.fmt.get("hex", None)
        if result is None:
            result = False
            if isinstance(self.value, int):
                bits = self._type.size if self._type is not None else None
                result = should_use_hex(self.value, bits)
        return result

    @fmt_hex.setter
    def fmt_hex(self, v):
        self._fmt_setter["hex"] = v

    @property
    def fmt_neg(self):
        return self.fmt.get("neg", False)

    @fmt_neg.setter
    def fmt_neg(self, v):
        self._fmt_setter["neg"] = v

    @property
    def fmt_char(self):
        return self.fmt.get("char", False)

    @fmt_char.setter
    def fmt_char(self, v: bool):
        self._fmt_setter["char"] = v

    @property
    def fmt_float(self):
        return self.fmt.get("float", False)

    @fmt_float.setter
    def fmt_float(self, v: bool):
        self._fmt_setter["float"] = v

    @property
    def fmt_double(self):
        return self.fmt.get("double", False)

    @fmt_double.setter
    def fmt_double(self, v: bool):
        self._fmt_setter["double"] = v

    @property
    def type(self):
        return self._type

    @staticmethod
    def str_to_c_str(_str, prefix: str = "", maxlen: int | None = None) -> str:
        repr_str = repr(_str)
        base_str = repr_str[1:-1]

        if maxlen is not None and len(base_str) > maxlen:
            base_str = base_str[:maxlen] + "..."

        # check if there's double quotes in the body
        if repr_str[0] == "'" and '"' in base_str:
            base_str = base_str.replace('"', '\\"')
        return f'{prefix}"{base_str}"'

    def _is_rune_literal(self) -> bool:
        """byte/rune constants default to rune literals when printable."""
        ty = unpack_typeref(self._type)
        if not (isinstance(self.value, int) and isinstance(ty, GoSimTypeInt)):
            return False
        if not ((ty.size == 8 and not ty.signed) or ty.go_name == "rune"):
            return False
        return 0x20 <= self.value < 0x7F and self.fmt.get("char", True)

    def c_repr_chunks(self, indent=0, asexpr=False):
        def _default_output(v) -> str | None:
            if isinstance(v, MemoryData) and v.sort == MemoryDataSort.String and v.content is not None:
                return GoConstant.str_to_c_str(v.content.decode("utf-8"), maxlen=self.codegen.max_str_len)
            if isinstance(v, Function):
                return v.name
            if isinstance(v, str):
                return GoConstant.str_to_c_str(v, maxlen=self.codegen.max_str_len)
            if isinstance(v, bytes):
                return GoConstant.str_to_c_str(v.replace(b"\x00", b"").decode("utf-8"), maxlen=self.codegen.max_str_len)
            return None

        if self.collapsed:
            yield "...", self
            return

        # Check for enum type - resolve integer to enum member name
        if isinstance(self._type, SimTypeEnum) and isinstance(self.value, int):
            member_name = self._type.resolve(self.value)
            if member_name is not None:
                yield member_name, self
                return

        # Check for bitfield type - render as combined flag names
        if isinstance(self._type, SimTypeBitfield) and isinstance(self.value, int):
            rendered = self._type.render(self.value)
            yield rendered, self
            return

        if self._is_rune_literal():
            yield "'" + chr(self.value).replace("\\", "\\\\").replace("'", "\\'") + "'", self
            return

        if self.reference_values is not None:
            if self._type is not None and self._type in self.reference_values:
                if isinstance(self._type, SimTypeInt):
                    if isinstance(self.reference_values[self._type], int):
                        yield self.fmt_int(self.reference_values[self._type]), self
                        return
                    yield hex(self.reference_values[self._type]), self
                    return

                if isinstance(self._type, SimTypePointer) and isinstance(self._type.pts_to, SimTypeChar):
                    refval = self.reference_values[self._type]
                    if isinstance(refval, MemoryData):
                        v = refval.content.decode("utf-8") if refval.content else f"<unknown@{refval.addr:#x}>"
                    elif isinstance(refval, bytes):
                        v = refval.decode("latin1")
                    else:
                        # it must be a string
                        v = refval
                        assert isinstance(v, str)
                    yield GoConstant.str_to_c_str(v, maxlen=self.codegen.max_str_len), self
                    return

                if isinstance(self._type, SimTypePointer) and isinstance(self._type.pts_to, SimTypeWideChar):
                    refval = self.reference_values[self._type]
                    if isinstance(refval, MemoryData):
                        v = decode_utf16_string(refval.content) if refval.content else f"<unknown@{refval.addr:#x}>"
                    elif isinstance(refval, bytes):
                        v = decode_utf16_string(refval) if refval else "<unknown_bytes>"
                    else:
                        assert False, f"Unexpected reference value type {type(refval)} for wide char pointer"
                    yield GoConstant.str_to_c_str(v, prefix="L", maxlen=self.codegen.max_str_len), self
                    return

                if isinstance(self.reference_values[self._type], int):
                    yield self.fmt_int(self.reference_values[self._type]), self
                    return
                o = _default_output(self.reference_values[self.type])
                if o is not None:
                    yield o, self
                    return

            # default priority: string references -> variables -> other reference values
            for v in self.reference_values.values():  # pylint:disable=unused-variable
                o = _default_output(v)
                if o is not None:
                    yield o, self
                    return

        if isinstance(self.value, int) and self.value == 0 and _go_is_nilable(self.type):
            yield "nil", self
        elif isinstance(self._type, SimTypePointer) and isinstance(self.value, int):
            # Print pointers in hex
            yield hex(self.value), self

        elif isinstance(self.value, bool):
            # C doesn't have true or false, but whatever...
            yield "true" if self.value else "false", self

        elif isinstance(self.value, int):
            str_value = self.fmt_int(self.value)
            yield str_value, self
        else:
            yield str(self.value), self

    def fmt_int(self, value: int) -> str:
        """
        Format an integer using the format setup of the current node.

        :param value:   The integer value to format.
        :return:        The formatted string.
        """

        if self.fmt_float and 0 < value <= 0xFFFF_FFFF:
            return str(struct.unpack("f", struct.pack("I", value))[0])

        if self.fmt_char:
            if value < 0:
                assert self._type.size is not None
                value += 2**self._type.size
            value &= 0xFF
            return repr(chr(value)) if value < 0x80 else f"'\\x{value:x}'"

        if self.fmt_double and 0 < value <= 0xFFFF_FFFF_FFFF_FFFF:
            return str(struct.unpack("d", struct.pack("Q", value))[0])

        if self.fmt_neg:
            if value > 0:
                assert self._type.size is not None
                value -= 2**self._type.size
            elif value < 0:
                assert self._type.size is not None
                value += 2**self._type.size

        if self.fmt_hex and not -256 < value < 0:
            return hex(value)

        return str(value)


class GoRegister(GoExpression):
    __slots__ = ("reg",)

    def __init__(self, reg, **kwargs):
        super().__init__(**kwargs)

        self.reg = reg

    @property
    def type(self):
        # FIXME
        return SimTypeInt().with_arch(self.codegen.project.arch)

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield str(self.reg), None


class GoITE(GoExpression):
    __slots__ = (
        "cond",
        "iffalse",
        "iftrue",
    )

    def __init__(self, cond, iftrue, iffalse, **kwargs):
        super().__init__(**kwargs)
        self.cond = cond
        self.iftrue = iftrue
        self.iffalse = iffalse

    @property
    def type(self):
        return self.iftrue.type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        paren = GoClosingObject("(")
        brace = GoClosingObject("{")
        yield "func() ", self
        yield (go_type_str(self.type) if self.type is not None else "any"), self.type
        yield " ", None
        yield "{", brace
        yield " if ", self
        yield from self.cond.c_repr_chunks()
        yield " { return ", self
        yield from self.iftrue.c_repr_chunks()
        yield " }; return ", self
        yield from self.iffalse.c_repr_chunks()
        yield " ", None
        yield "}", brace
        yield "(", paren
        yield ")", paren


class GoMultiStatementExpression(GoExpression):
    """
    (stmt0, stmt1, stmt2, expr)
    """

    __slots__ = (
        "expr",
        "stmts",
    )

    def __init__(self, stmts: GoStatements, expr: GoExpression, **kwargs):
        super().__init__(**kwargs)
        self.stmts = stmts
        self.expr = expr

    @property
    def type(self):
        return self.expr.type

    def c_repr_chunks(self, indent=0, asexpr=False):
        paren = GoClosingObject("(")
        yield "(", paren
        yield from self.stmts.c_repr_chunks(indent=0, asexpr=True)
        yield from self.expr.c_repr_chunks()
        yield ")", paren


class GoVEXCCallExpression(GoExpression):
    """
    ccall_name(arg0, arg1, ...)
    """

    __slots__ = (
        "callee",
        "operands",
    )

    def __init__(self, callee: str, operands: list[GoExpression], **kwargs):
        super().__init__(**kwargs)
        self.callee = callee
        self.operands = operands

    @property
    def type(self):
        return SimTypeInt().with_arch(self.codegen.project.arch)

    def c_repr_chunks(self, indent=0, asexpr=False):
        paren = GoClosingObject("(")
        yield f"{self.callee}", self
        yield "(", paren
        for idx, operand in enumerate(self.operands):
            if idx != 0:
                yield ", ", None
            yield from operand.c_repr_chunks()
        yield ")", paren


class GoDirtyExpression(GoExpression):
    """
    Ideally all dirty expressions should be handled and converted to proper conversions during conversion from VEX to
    AIL. Eventually this class should not be used at all.
    """

    __slots__ = ("dirty",)

    _IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

    def __init__(self, dirty, **kwargs):
        super().__init__(**kwargs)
        self.dirty = dirty

    @property
    def type(self):
        return SimTypeInt().with_arch(self.codegen.project.arch)

    def intrinsic_name(self) -> str | None:
        """Return the dirty callee if it is a clean C identifier, else None."""
        callee = getattr(self.dirty, "callee", None)
        if isinstance(callee, str) and self._IDENT_RE.fullmatch(callee):
            return callee
        return None

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        # Never leak the internal "[D] ..." diagnostic repr into emitted C. Render a clean
        # pseudo-intrinsic call when the callee is a valid C identifier, otherwise a safe
        # placeholder comment.
        name = self.intrinsic_name()
        if name is not None:
            operands = getattr(self.dirty, "operands", None) or []
            args = ", ".join(repr(op).replace("[D] ", "") for op in operands)
            yield f"{name}({args})", None
        else:
            yield "/* unsupported instruction */", None


class GoStringLiteral(GoExpression):
    """A Go string constant (pointer, length) known at decompilation time."""

    __slots__ = ("data",)

    def __init__(self, data: str, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.data = data
        self.tags = tags
        self._type = GoSimTypeString().with_arch(self.codegen.project.arch)

    @property
    def type(self):
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield json.dumps(self.data, ensure_ascii=False), self


class GoStructLiteral(GoExpression):
    """
    A struct-shaped value assembled from its fields: a composite literal ``T{a: x, b: y}``, or ``nil``/``""`` when
    every field is zero.
    """

    __slots__ = ("field_names", "fields", "name")

    def __init__(self, name: str, fields, field_names, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.name = name
        self.fields = fields  # offset -> GoExpression
        self.field_names = field_names  # offset -> field name
        self.tags = tags
        self._type = None
        with contextlib.suppress(Exception):
            self._type = self.codegen.kb.go_signatures.type(name)

    @property
    def type(self):
        return self._type

    def _is_zero(self) -> bool:
        def zero(expr) -> bool:
            if isinstance(expr, GoConstant):
                return expr.value == 0
            if isinstance(expr, GoStructLiteral):
                return expr._is_zero()
            return False

        return bool(self.fields) and all(zero(f) for f in self.fields.values())

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        if self._is_zero():
            yield ('""' if isinstance(self._type, GoSimTypeString) else "nil"), self
            return
        brace = GoClosingObject("{")
        yield self.name, self
        yield "{", brace
        first = True
        for offset, field in self.fields.items():
            if not first:
                yield ", ", None
            first = False
            name = self.field_names.get(offset)
            if name is not None:
                yield name, self
                yield ": ", None
            yield from GoExpression._try_c_repr_chunks(field)
        yield "}", brace


class GoBoxedValue(GoExpression):
    """
    A value converted to an interface: ``x`` when its static type already is the boxed type, ``T(x)`` otherwise.
    """

    __slots__ = ("concrete", "expr", "iface_name")

    _INT_NAMES = frozenset(
        {
            "int",
            "int8",
            "int16",
            "int32",
            "int64",
            "uint",
            "uint8",
            "uint16",
            "uint32",
            "uint64",
            "uintptr",
            "byte",
            "rune",
        }
    )

    def __init__(self, expr, iface_name: str, concrete: str | None, tags=None, **kwargs):
        super().__init__(tags=tags, **kwargs)
        self.expr = expr
        self.iface_name = iface_name
        self.concrete = concrete
        self._type = None
        with contextlib.suppress(Exception):
            self._type = self.codegen.kb.go_signatures.type(iface_name).with_arch(self.codegen.project.arch)

    @property
    def type(self):
        return self._type

    def _needs_conversion(self) -> bool:
        if self.concrete is None:
            return False
        expr = self.expr
        if isinstance(expr, GoConstant) and self.concrete in self._INT_NAMES:
            return False
        if isinstance(expr, GoStringLiteral) and self.concrete == "string":
            return False
        ty = unpack_typeref(expr.type)
        if ty is None:
            return True
        with contextlib.suppress(Exception):
            return go_type_str(ty) != self.concrete
        return True

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        if not self._needs_conversion():
            yield from GoExpression._try_c_repr_chunks(self.expr)
            return
        paren = GoClosingObject("(")
        if self.concrete.startswith(("*", "<-", "func(")):
            type_paren = GoClosingObject("(")
            yield "(", type_paren
            yield self.concrete, self
            yield ")", type_paren
        else:
            yield self.concrete, self
        yield "(", paren
        yield from GoExpression._try_c_repr_chunks(self.expr)
        yield ")", paren


class GoTypeAssertion(GoExpression):
    """``x.(T)``"""

    __slots__ = ("expr", "type_name")

    def __init__(self, expr, type_name: str, tags=None, **kwargs):
        super().__init__(tags=tags, **kwargs)
        self.expr = expr
        self.type_name = type_name
        self._type = None
        with contextlib.suppress(Exception):
            self._type = self.codegen.kb.go_signatures.type(type_name).with_arch(self.codegen.project.arch)

    @property
    def type(self):
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        compound = isinstance(self.expr, (GoUnaryOp, GoBinaryOp, GoTypeCast))
        if compound:
            yield "(", None
        yield from GoExpression._try_c_repr_chunks(self.expr)
        if compound:
            yield ")", None
        paren = GoClosingObject("(")
        yield ".(", paren
        yield self.type_name, self
        yield ")", paren


class GoSliceLiteral(GoExpression):
    """``[]T{a, b, c}``"""

    __slots__ = ("elem_type", "elems")

    def __init__(self, elem_type: str, elems, tags=None, **kwargs):
        super().__init__(tags=tags, **kwargs)
        self.elem_type = elem_type
        self.elems = list(elems)
        self._type = None
        with contextlib.suppress(Exception):
            self._type = self.codegen.kb.go_signatures.type(f"[]{elem_type}").with_arch(self.codegen.project.arch)

    @property
    def type(self):
        return self._type

    def elem_chunks(self):
        for i, elem in enumerate(self.elems):
            if i:
                yield ", ", None
            yield from GoExpression._try_c_repr_chunks(elem)

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        brace = GoClosingObject("{")
        yield f"[]{self.elem_type}", self
        yield "{", brace
        yield from self.elem_chunks()
        yield "}", brace


class GoClosingObject:
    """
    A class to represent all objects that can be closed by it's correspodning character.
    Examples: (), {}, []
    """

    __slots__ = ("opening_symbol",)

    def __init__(self, opening_symbol):
        self.opening_symbol = opening_symbol


class GoArrayTypeLength:
    """
    A class to represent the type information of fixed-size array lengths.
    Examples: In "char foo[20]", this would be the "[20]".
    """

    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text


class GoStructFieldNameDef:
    """A class to represent the name of a defined field in a struct.
    Needed because it's not a GoVariable or a GoStructField (because
    GoStructField is the access of a GoStructField).
    Example: In "struct foo { int bar; }, this would be "bar".
    """

    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name


class GoStructuredCodeGenerator(BaseStructuredCodeGenerator, Analysis):
    def __init__(
        self,
        func,
        sequence,
        indent=0,
        cfg=None,
        func_args: list[SimVariable] | None = None,
        binop_depth_cutoff: int = 16,
        show_casts=True,
        braces_on_own_lines=False,
        use_compound_assignments=True,
        show_local_types=True,
        comment_gotos=False,
        cstyle_null_cmp=True,
        flavor=None,
        stmt_comments=None,
        expr_comments=None,
        show_externs=True,
        externs=None,
        const_formats=None,
        show_demangled_name=True,
        show_disambiguated_name=True,
        ail_graph=None,
        simplify_else_scope=True,
        cstyle_ifs=True,
        omit_func_header=False,
        display_block_addrs=False,
        display_vvar_ids=False,
        min_data_addr: int = 0x400_000,
        notes=None,
        display_notes: bool = True,
        max_str_len: int | None = None,
        prettify_thiscall: bool = False,
        cstyle_void_param: bool = True,
        indent_size: int = 4,
        variable_map: VariableMap | None = None,
    ):
        super().__init__(
            flavor=flavor,
            notes=notes,
            stmt_comments=stmt_comments,
            expr_comments=expr_comments,
            const_formats=const_formats,
        )

        self._handlers = {
            CodeNode: self._handle_Code,
            SequenceNode: self._handle_Sequence,
            LoopNode: self._handle_Loop,
            ConditionNode: self._handle_Condition,
            CascadingConditionNode: self._handle_CascadingCondition,
            ConditionalBreakNode: self._handle_ConditionalBreak,
            MultiNode: self._handle_MultiNode,
            Block: self._handle_AILBlock,
            BreakNode: self._handle_Break,
            SwitchCaseNode: self._handle_SwitchCase,
            IncompleteSwitchCaseNode: self._handle_IncompleteSwitchCase,
            ContinueNode: self._handle_Continue,
            # AIL statements
            Stmt.Store: self._handle_Stmt_Store,
            Stmt.Assignment: self._handle_Stmt_Assignment,
            Stmt.WeakAssignment: self._handle_Stmt_Assignment,
            Stmt.SideEffectStatement: self._handle_Stmt_SideEffectStatement,
            Stmt.Jump: self._handle_Stmt_Jump,
            Stmt.ConditionalJump: self._handle_Stmt_ConditionalJump,
            IncompleteSwitchCaseHeadStatement: self._handle_Stmt_IncompleteSwitchCaseHead,
            Stmt.Return: self._handle_Stmt_Return,
            Stmt.Label: self._handle_Stmt_Label,
            Stmt.DirtyStatement: self._handle_Stmt_Dirty,
            Stmt.CAS: self._handle_Stmt_CAS,
            # AIL expressions
            Expr.Register: self._handle_Expr_Register,
            Expr.Load: self._handle_Expr_Load,
            Expr.Tmp: self._handle_Expr_Tmp,
            Expr.Const: self._handle_Expr_Const,
            Expr.UnaryOp: self._handle_Expr_UnaryOp,
            Expr.BinaryOp: self._handle_Expr_BinaryOp,
            Expr.Convert: self._handle_Expr_Convert,
            Expr.Extract: self._handle_Expr_Extract,
            Expr.Insert: self._handle_Expr_Insert,
            Expr.StackBaseOffset: self._handle_Expr_StackBaseOffset,
            Expr.VEXCCallExpression: self._handle_Expr_VEXCCallExpression,
            Expr.DirtyExpression: self._handle_Expr_Dirty,
            Expr.ITE: self._handle_Expr_ITE,
            Expr.Call: self._handle_Expr_Call,
            Expr.Reinterpret: self._handle_Reinterpret,
            Expr.MultiStatementExpression: self._handle_MultiStatementExpression,
            Expr.VirtualVariable: self._handle_VirtualVariable,
            Struct: self._handle_Expr_Struct,
            StringLiteral: self._handle_Expr_StringLiteral,
        }

        self._func = func
        self._func_args = func_args
        self._cfg = cfg
        self._sequence = sequence
        self._variable_map: VariableMap = variable_map if variable_map is not None else VariableMap()
        self.binop_depth_cutoff = binop_depth_cutoff

        self._variables_in_use: dict | None = None
        self._inlined_strings: set[SimMemoryVariable] = set()
        self._function_pointers: set[SimMemoryVariable] = set()
        self.ailexpr2cnode: dict[tuple[Expr.Expression, bool], GoExpression] | None = None
        self.cnode2ailexpr: dict[GoExpression, Expr.Expression] | None = None
        self._indent = indent
        self.show_casts = show_casts
        self.comment_gotos = comment_gotos
        self.braces_on_own_lines = braces_on_own_lines
        self.use_compound_assignments = use_compound_assignments
        self.show_local_types = show_local_types
        self.cstyle_null_cmp = cstyle_null_cmp
        self.externs = externs or set()
        self.show_externs = show_externs
        self.show_demangled_name = show_demangled_name
        self.show_disambiguated_name = show_disambiguated_name
        self.ail_graph = ail_graph
        self.simplify_else_scope = simplify_else_scope
        self.cstyle_ifs = cstyle_ifs
        self.omit_func_header = omit_func_header
        self.display_block_addrs = display_block_addrs
        self.display_vvar_ids = display_vvar_ids
        self.min_data_addr = min_data_addr
        self.text = None
        self.map_pos_to_node = None
        self.map_pos_to_addr = None
        self.map_addr_to_pos = None
        self.map_ast_to_pos: dict[SimVariable, set[PositionMappingElement]] | None = None
        self.map_addr_to_label: dict[tuple[int, int | None], GoLabel] = {}
        self.cfunc: GoFunction | None = None
        self.cexterns: set[GoVariable] | None = None
        self._array_length_cexprs: dict[SimVariable, GoExpression] = {}
        self.display_notes = display_notes
        self.max_str_len = max_str_len
        self.prettify_thiscall = prettify_thiscall
        self.cstyle_void_param = cstyle_void_param
        # Number of space characters per indentation level in the emitted pseudocode.
        self.indent_delta = indent_size

        self._analyze()

    def reapply_options(self, options):
        for option, value in options:
            if option.param == "braces_on_own_lines":
                self.braces_on_own_lines = value
            elif option.param == "show_casts":
                self.show_casts = value
            elif option.param == "comment_gotos":
                self.comment_gotos = value
            elif option.param == "use_compound_assignments":
                self.use_compound_assignments = value
            elif option.param == "show_local_types":
                self.show_local_types = value
            elif option.param == "show_externs":
                self.show_externs = value
            elif option.param == "show_demangled_name":
                self.show_demangled_name = value
            elif option.param == "cstyle_null_cmp":
                self.cstyle_null_cmp = value
            elif option.param == "simplify_else_scope":
                self.simplify_else_scope = value
            elif option.param == "cstyle_ifs":
                self.cstyle_ifs = value
            elif option.param == "cstyle_void_param":
                self.cstyle_void_param = value
            elif option.param == "indent_size":
                self.indent_delta = value

    def _analyze(self):
        self._variables_in_use = {}

        # memo
        self.ailexpr2cnode = {}

        arg_list = [self._variable(arg, None) for arg in self._func_args] if self._func_args else []

        self.reset_ident_counters()
        obj = self._handle(self._sequence)

        # render the runtime dimension of every variable-length array (e.g. ``blk[e->bs]``) through the
        # regular expression handler, so the field name/type match the rest of the output
        self._array_length_cexprs = {
            var: self._handle(dim_expr)
            for var, dim_expr in self.kb.dec_variables[self._func.addr].array_length_exprs.items()
        }

        self.cnode2ailexpr = {v: k[0] for k, v in self.ailexpr2cnode.items()}

        self.cfunc = GoFunction(
            self._func.addr,
            self._func.name,
            self._func.prototype,
            arg_list,
            obj,
            self._variables_in_use,
            self.kb.dec_variables[self._func.addr],
            demangled_name=self._func.demangled_name,
            show_demangled_name=self.show_demangled_name,
            codegen=self,
            omit_header=self.omit_func_header,
        )
        self.cfunc = FieldReferenceCleanup().handle(self.cfunc)
        self.cfunc = PointerArithmeticFixer().handle(self.cfunc)
        self.cfunc = MakeTypecastsImplicit().handle(self.cfunc)
        self.cfunc = InterfaceMethodCalls(self).handle(self.cfunc)
        TypeAssertionRecovery(self, self.cfunc).run()
        self.cfunc = RangeLoopRecovery(self).handle(self.cfunc)
        TupleDestructuring(self, self.cfunc).run()
        TypeSwitchRecovery(self, self.cfunc).run()
        MapRangeRecovery(self, self.cfunc).run()
        ChannelRangeRecovery(self, self.cfunc).run()
        SelectRecovery(self, self.cfunc).run()
        self.cfunc = PrintFolding(self).handle(self.cfunc)
        CopyCleanup(self, self.cfunc).run()
        # the cleanup exposes counting loops the spills and phi copies hid, and those expose method calls
        self.cfunc = RangeLoopRecovery(self).handle(self.cfunc)
        CopyCleanup(self, self.cfunc).run()
        self.cfunc = InterfaceMethodCalls(self).handle(self.cfunc)
        CopyCleanup(self, self.cfunc).run()
        ITEHoisting(self, self.cfunc).run()
        NamedFieldRetyping(self, self.cfunc).run()
        self.cfunc.statements = _TypedCopies(self).handle(self.cfunc.statements)
        ShortDeclarations(self, self.cfunc).run()

        # TODO store extern fallback size somewhere lol
        self.cexterns = {
            self._variable(v, 1, mark_used=False)
            for v in self.externs
            if v not in self._inlined_strings and v not in self._function_pointers
        }

        self.regenerate_text()

    def cleanup(self):
        """
        Remove existing rendering results.
        """
        self.map_pos_to_node = None
        self.map_pos_to_addr = None
        self.map_addr_to_pos = None
        self.map_ast_to_pos = None
        self.text = None

    def regenerate_text(self) -> None:
        """
        Re-render text and re-generate all sorts of mapping information.
        """
        if self.cfunc is None:
            return
        # recompute the unified local variables and their types from the (possibly updated or freshly deserialized)
        # variable manager, so re-rendering reflects the current variable types
        self.cfunc.refresh()
        self.cleanup()
        (
            self.text,
            self.map_pos_to_node,
            self.map_pos_to_addr,
            self.map_addr_to_pos,
            self.map_ast_to_pos,
        ) = self.render_text(self.cfunc)

    def render_text(self, cfunc: GoFunction) -> RenderResult:
        pos_to_node = PositionMapping()
        pos_to_addr = PositionMapping()
        addr_to_pos = InstructionMapping()
        ast_to_pos = defaultdict(set)

        text = cfunc.c_repr(
            initial_pos=0,
            indent=self._indent,
            pos_to_node=pos_to_node,
            pos_to_addr=pos_to_addr,
            addr_to_pos=addr_to_pos,
        )

        if self.display_notes:
            notes = self.render_notes()
            pos_to_node, pos_to_addr, addr_to_pos = self.adjust_mapping_positions(
                len(notes), pos_to_node, pos_to_addr, addr_to_pos
            )
            text = notes + text

        for elem, node in pos_to_node.items():
            if isinstance(node.obj, GoConstant):
                ast_to_pos[node.obj.value].add(elem)
            elif isinstance(node.obj, GoVariable):
                if node.obj.unified_variable is not None:
                    ast_to_pos[node.obj.unified_variable].add(elem)
                else:
                    ast_to_pos[node.obj.variable].add(elem)
            elif isinstance(node.obj, SimType):
                ast_to_pos[node.obj].add(elem)
            elif isinstance(node.obj, GoFunctionCall):
                if node.obj.callee_func is not None:
                    ast_to_pos[node.obj.callee_func].add(elem)
                else:
                    ast_to_pos[node.obj.callee_target].add(elem)
            elif isinstance(node.obj, GoStructField):
                key = (node.obj.struct_type, node.obj.offset)
                ast_to_pos[key].add(elem)
            else:
                ast_to_pos[node.obj].add(elem)

        return text, pos_to_node, pos_to_addr, addr_to_pos, ast_to_pos

    def render_notes(self) -> str:
        """
        Render decompilation notes.

        :return: A string containing all notes.
        """
        if not self.notes:
            return ""

        lines = []
        for note in self.notes.values():
            note_lines = str(note).split("\n")
            lines += [f"// {line}" for line in note_lines]
        return "\n".join(lines) + "\n\n"

    def _get_variable_type(self, var, is_global=False):
        if is_global:
            return self.kb.dec_variables["global"].get_variable_type(var)
        return self.kb.dec_variables[self._func.addr].get_variable_type(var)

    def _get_derefed_type(self, ty: SimType) -> SimType | None:
        if ty is None:
            return None
        ty = unpack_typeref(ty)
        if isinstance(ty, SimTypePointer):
            return unpack_typeref(ty.pts_to).with_arch(self.project.arch)
        if isinstance(ty, SimTypeArray):
            return unpack_typeref(ty.elem_type).with_arch(self.project.arch)
        return ty

    def reload_variable_types(self) -> None:
        if self._variables_in_use is not None:
            for var in self._variables_in_use.values():
                if isinstance(var, GoVariable):
                    var.variable_type = self._get_variable_type(
                        var.variable,
                        is_global=isinstance(var.variable, SimMemoryVariable)
                        and not isinstance(var.variable, SimStackVariable),
                    )

        if self.cexterns is not None:
            for var in self.cexterns:
                if isinstance(var, GoVariable):
                    var.variable_type = self._get_variable_type(var.variable, is_global=True)

        if self.cfunc is not None:
            for cvar in self.cfunc.arg_list:
                vartype = self._get_variable_type(
                    cvar.variable,
                    is_global=isinstance(cvar.variable, SimMemoryVariable)
                    and not isinstance(cvar.variable, SimStackVariable),
                )
                if vartype is not None:
                    cvar.variable_type = vartype.with_arch(self.project.arch)

    #
    # Util methods
    #

    def default_simtype_from_bits(self, n: int, signed: bool = True) -> SimType:
        _mapping = {
            64: SimTypeLongLong,
            32: SimTypeInt,
            16: SimTypeShort,
            8: SimTypeChar,
        }
        if n in _mapping:
            return _mapping.get(n)(signed=signed).with_arch(self.project.arch)
        return SimTypeNum(n, signed=signed).with_arch(self.project.arch)

    def _variable(
        self, variable: SimVariable, fallback_type_size: int | None, vvar_id: int | None = None, mark_used: bool = True
    ) -> GoVariable:
        # TODO: we need to fucking make sure that variable recovery and type inference actually generates a size
        # TODO: for each variable it links into the fucking ail. then we can remove fallback_type_size.
        unified = self.kb.dec_variables[self._func.addr].unified_variable(variable)
        variable_type = self._get_variable_type(
            variable, is_global=isinstance(variable, SimMemoryVariable) and not isinstance(variable, SimStackVariable)
        )
        if variable_type is None:
            variable_type = self.default_simtype_from_bits(
                (fallback_type_size or self.project.arch.bytes) * self.project.arch.byte_width
            )
        cvar = GoVariable(
            variable, unified_variable=unified, variable_type=variable_type, codegen=self, vvar_id=vvar_id
        )
        if mark_used:
            self._variables_in_use[variable] = cvar
        return cvar

    def _get_variable_reference(self, cvar: GoVariable) -> GoExpression:
        """
        Return a reference to a GoVariable instance with special handling of arrays and array pointers.

        :param cvar:    The GoVariable object.
        :return:        A reference to a GoVariable object.
        """

        if isinstance(cvar.type, (SimTypeArray, SimTypeFixedSizeArray)):
            return cvar
        if isinstance(cvar.type, SimTypePointer) and isinstance(
            cvar.type.pts_to, (SimTypeArray, SimTypeFixedSizeArray)
        ):
            return cvar
        return GoUnaryOp("Reference", cvar, codegen=self)

    def _access_reference(self, expr: GoExpression, data_type: SimType) -> GoExpression:
        result = self._access(expr, data_type, True)
        if isinstance(result, GoUnaryOp) and result.op == "Dereference":
            result = result.operand
        else:
            result = GoUnaryOp("Reference", result, codegen=self)
        return result

    def _access_constant_offset_reference(
        self, expr: GoExpression, offset: int, data_type: SimType | None
    ) -> GoExpression:
        result = self._access_constant_offset(expr, offset, data_type or SimTypeBottom(), True)
        if isinstance(result, GoTypeCast) and data_type is None:
            result = result.expr
        if isinstance(result, GoUnaryOp) and result.op == "Dereference":
            result = result.operand
            if isinstance(result, GoTypeCast) and data_type is None:
                result = result.expr
        else:
            result = GoUnaryOp("Reference", result, codegen=self)
        return result

    def _access_constant_offset(
        self,
        expr: GoExpression,
        offset: int,
        data_type: SimType,
        lvalue: bool,
        renegotiate_type: Callable[[SimType, SimType], SimType] = lambda old, proposed: old,
    ) -> GoExpression:
        def _force_type_cast(src_type_: SimType, dst_type_: SimType, expr_: GoExpression) -> GoUnaryOp:
            src_type_ptr = SimTypePointer(src_type_).with_arch(self.project.arch)
            dst_type_ptr = SimTypePointer(dst_type_).with_arch(self.project.arch)
            return GoUnaryOp(
                "Dereference",
                GoTypeCast(
                    src_type_ptr,
                    dst_type_ptr,
                    GoUnaryOp("Reference", expr_, codegen=self),
                    codegen=self,
                ),
                codegen=self,
            )

        # expr must express a POINTER to the base
        # returns a value which has a simtype of data_type as if it were dereferenced out of expr
        data_type = unpack_typeref(data_type)
        base_type = unpack_typeref(unpack_pointer_and_array(expr.type)) if expr.type is not None else None
        if base_type is None:
            # well, not much we can do
            if data_type is None:
                raise TypeError("GoStructuredCodeGenerator programming error: no type whatsoever for dereference")
            if offset:
                expr = GoBinaryOp("Add", expr, GoConstant(offset, SimTypeInt(), codegen=self), codegen=self)
            return GoUnaryOp(
                "Dereference",
                GoTypeCast(expr.type, SimTypePointer(data_type).with_arch(self.project.arch), expr, codegen=self),
                codegen=self,
            )

        base_expr = expr.operand if isinstance(expr, GoUnaryOp) and expr.op == "Reference" else None

        if offset == 0:
            data_type = renegotiate_type(data_type, base_type)
            if _is_go_value_read_as_int(base_type, data_type):
                # a struct-shaped or pointer-shaped Go value loaded as a plain integer of the same width is that value
                data_type = base_type
            if type_equals(base_type, data_type) or (
                base_type.size is not None and data_type.size is not None and base_type.size < data_type.size
            ):
                # case 1: we're done because we found it
                # case 2: we're done because we can never find it and we might as well stop early
                if base_expr:
                    if not type_equals(base_type, data_type):
                        return _force_type_cast(base_type, data_type, base_expr)
                    return base_expr

                if not type_equals(base_type, data_type):
                    return _force_type_cast(base_type, data_type, expr)
                return GoUnaryOp("Dereference", expr, codegen=self)

        stride = 1 if base_type.size is None else base_type.size // self.project.arch.byte_width or 1
        index, remainder = divmod(offset, stride)
        if index != 0:
            index = GoConstant(index, SimTypeInt(), codegen=self)
            kernel = expr
            # create a GoIndexedVariable indicating the index access
            if base_expr and isinstance(base_expr, GoIndexedVariable):
                old_index = base_expr.index
                kernel = base_expr.variable
                if not isinstance(old_index, GoConstant) or old_index.value != 0:
                    index = GoBinaryOp("Add", old_index, index, codegen=self)
            result = GoUnaryOp(
                "Reference", GoIndexedVariable(kernel, index, variable_type=base_type, codegen=self), codegen=self
            )
            return self._access_constant_offset(result, remainder, data_type, lvalue, renegotiate_type)

        if isinstance(base_type, SimStruct) and base_type.offsets:
            # find the field that we're accessing
            field_name, field_offset = max(
                ((x, y) for x, y in base_type.offsets.items() if y <= remainder), key=lambda x: x[1]
            )
            field = GoStructField(base_type, field_offset, field_name, codegen=self)
            if base_expr:
                result = GoUnaryOp("Reference", GoVariableField(base_expr, field, False, codegen=self), codegen=self)
            else:
                result = GoUnaryOp("Reference", GoVariableField(expr, field, True, codegen=self), codegen=self)
            return self._access_constant_offset(result, remainder - field_offset, data_type, lvalue, renegotiate_type)

        if isinstance(base_type, (SimTypeFixedSizeArray, SimTypeArray)):
            result = base_expr or expr  # death to C
            if isinstance(result, GoIndexedVariable):
                # unpack indexed variable
                var = result.variable
                result = GoUnaryOp(
                    "Reference",
                    GoIndexedVariable(var, result.index, variable_type=base_type.elem_type, codegen=self),
                    codegen=self,
                )
            else:
                result = GoUnaryOp(
                    "Reference",
                    GoIndexedVariable(
                        result,
                        GoConstant(0, SimTypeInt(), codegen=self),
                        variable_type=base_type.elem_type,
                        codegen=self,
                    ),
                    codegen=self,
                )
            return self._access_constant_offset(result, remainder, data_type, lvalue, renegotiate_type)

        # TODO is it a big-endian downcast?
        # e.g. int x; *((char*)x + 3) is actually just (char)x

        if remainder != 0:
            # pointer cast time!
            # TODO: BYTE2() and other ida-isms if we're okay with an rvalue
            if stride != 1:
                # a pointer type inference made up is integer math to the reader; a known pointee keeps byte steps
                as_int = _go_anonymous_pointee(expr.type)
                cast_to = (
                    (SimTypeLongLong(signed=False) if self.project.arch.bits == 64 else SimTypeInt(signed=False))
                    if as_int
                    else SimTypePointer(SimTypeChar())
                )
                expr = GoTypeCast(expr.type, cast_to.with_arch(self.project.arch), expr, codegen=self)
            expr_with_offset = GoBinaryOp("Add", expr, GoConstant(remainder, SimTypeInt(), codegen=self), codegen=self)
            return GoUnaryOp(
                "Dereference",
                GoTypeCast(
                    expr_with_offset.type,
                    SimTypePointer(data_type).with_arch(self.project.arch),
                    expr_with_offset,
                    codegen=self,
                ),
                codegen=self,
            )

        # the case where we don't need a cast is handled at the start
        # if we've requested the result be an lvalue we have to do a pointer cast
        # if the value is not a trivial reference we have to do a pointer cast (?)
        if lvalue or not base_expr:
            return GoUnaryOp(
                "Dereference", GoTypeCast(expr.type, SimTypePointer(data_type), expr, codegen=self), codegen=self
            )
        # otherwise, normal cast
        return GoTypeCast(base_type, data_type, base_expr, codegen=self)

    def _access(
        self,
        expr: GoExpression,
        data_type: SimType,
        lvalue: bool,
        renegotiate_type: Callable[[SimType, SimType], SimType] = lambda old, proposed: old,
    ) -> GoExpression:
        # same rule as _access_constant_offset wrt pointer expressions
        data_type = unpack_typeref(data_type)
        base_type = unpack_pointer_and_array(expr.type) if expr.type is not None else None
        if base_type is None:
            # use the fallback from above
            return self._access_constant_offset(expr, 0, data_type, lvalue, renegotiate_type)

        o_constant, o_terms = extract_terms(expr)

        def bail_out():
            if len(o_terms) == 0:
                # probably a plain integer, return as *(int_type*)expr
                return GoUnaryOp(
                    "Dereference", GoTypeCast(expr.type, SimTypePointer(data_type), expr, codegen=self), codegen=self
                )
            result = None
            pointer_length_int_type = (
                SimTypeLongLong(signed=False) if self.project.arch.bits == 64 else SimTypeInt(signed=False)
            )

            def _byte_pointer(t):
                # a pointer to a known type keeps byte arithmetic explicit; a pointer only type inference
                # made up (an anonymous struct, an unknown pointee) is integer math to the reader
                if not isinstance(t.type, SimTypePointer):
                    return t
                pointee = unpack_typeref(t.type.pts_to)
                if isinstance(pointee, SimTypeBottom) or (
                    isinstance(pointee, GoSimStruct) and _go_descriptor_name(pointee) is None
                ):
                    return GoTypeCast(t.type, pointer_length_int_type, t, codegen=self)
                return GoTypeCast(t.type, SimTypePointer(SimTypeChar()), t, codegen=self)

            for c, t in o_terms:
                op = "Add"
                if c == -1 and result is not None:
                    op = "Sub"
                    piece = _byte_pointer(t)
                elif c == 1:
                    piece = _byte_pointer(t)
                else:
                    assert t.type is not None
                    piece = GoBinaryOp(
                        "Mul",
                        GoConstant(c, t.type, codegen=self),
                        (
                            t
                            if not isinstance(t.type, SimTypePointer)
                            else GoTypeCast(t.type, pointer_length_int_type, t, codegen=self)
                        ),
                        codegen=self,
                    )
                result = piece if result is None else GoBinaryOp(op, result, piece, codegen=self)
            if o_constant != 0:
                if o_constant < 0:
                    result = GoBinaryOp(
                        "Sub", result, GoConstant(-o_constant, SimTypeInt(), codegen=self), codegen=self
                    )
                else:
                    result = GoBinaryOp("Add", result, GoConstant(o_constant, SimTypeInt(), codegen=self), codegen=self)

            return GoUnaryOp(
                "Dereference", GoTypeCast(result.type, SimTypePointer(data_type), result, codegen=self), codegen=self
            )

        # pain.
        # step 1 is split expr into a sum of terms, each of which is a product of a constant stride and an index
        # also identify the "kernel", the root of the expression
        constant, terms = o_constant, list(o_terms)
        if constant < 0:
            # a whole number of elements back (p[i - 1]) folds into the index term below; anything else bails
            kernel_candidates = [t for c, t in terms if c == 1 and isinstance(unpack_typeref(t.type), SimTypePointer)]
            kt = unpack_typeref(unpack_pointer_and_array(kernel_candidates[0].type)) if kernel_candidates else None
            stride = (kt.size or 0) // self.project.arch.byte_width if kt is not None and kt.size else 0
            if stride <= 0 or constant % stride != 0 or not any(c == stride for c, _ in terms):
                return bail_out()
            back = constant // stride
            terms = [
                (c, GoBinaryOp("Sub", t, GoConstant(-back, SimTypeInt(), codegen=self), codegen=self))
                if c == stride
                else (c, t)
                for c, t in terms
            ]
            back_applied = False
            new_terms = []
            for c, t in terms:
                if c == stride and not back_applied:
                    new_terms.append((c, t))
                    back_applied = True
                else:
                    new_terms.append((c, t.lhs if isinstance(t, GoBinaryOp) and t.op == "Sub" and c == stride else t))
            terms = new_terms
            constant = 0

        i = 0
        kernel = None
        while i < len(terms):
            c, t = terms[i]
            if isinstance(unpack_typeref(t.type), (SimTypePointer, SimTypeArray)):
                if c not in (1, -1) and _go_anonymous_pointee(t.type):
                    # `8 * p` is an index whose type inference guessed wrong, not a pointer
                    i += 1
                    continue
                if kernel is not None:
                    l.warning("Summing two different pointers together. Uh oh!")
                    return bail_out()
                if c == -1:
                    # legit case: you can deduct a pointer from another pointer and get an integer as result in C
                    return bail_out()
                if c != 1:
                    l.warning("Multiplying a pointer by a constant??")
                    return bail_out()
                kernel = t
                terms.pop(i)
                continue
            i += 1

        if kernel is None:
            # Dereferencing a plain integer
            return bail_out()

        terms.sort(key=lambda x: x[0])

        # suffering.
        seen: set[tuple] = set()
        while terms:
            assert kernel.type is not None
            kernel_type = unpack_typeref(unpack_pointer_and_array(kernel.type))
            assert kernel_type
            # descending into a field or element that leaves the kernel type unchanged would loop forever
            state = (type(kernel_type), getattr(kernel_type, "name", None), kernel_type.size, constant, len(terms))
            if state in seen or len(seen) > 64:
                return bail_out()
            seen.add(state)

            if kernel_type.size is None or kernel_type.size == 0:
                return bail_out()
            kernel_stride = kernel_type.size // self.project.arch.byte_width
            if kernel_stride == 0:
                return bail_out()

            # if the constant offset is larger than the current fucker, uh, do something about that first
            if constant >= kernel_stride:
                index, remainder = divmod(constant, kernel_stride)
                kernel = GoUnaryOp(
                    "Reference",
                    self._access_constant_offset(kernel, index * kernel_stride, kernel_type, True, renegotiate_type),
                    codegen=self,
                )
                constant = remainder
                continue

            # next, uh, check if there's an appropriately sized stride term that we can apply
            next_stride, next_term = terms[-1]
            if next_stride % kernel_stride == 0:
                index_multiplier = next_stride // kernel_stride
                if index_multiplier != 1:
                    index = GoBinaryOp(
                        "Mul", GoConstant(index_multiplier, SimTypeInt(), codegen=self), next_term, codegen=self
                    )
                else:
                    index = next_term
                if (
                    isinstance(kernel, GoUnaryOp)
                    and kernel.op == "Reference"
                    and isinstance(kernel.operand, GoIndexedVariable)
                ):
                    old_index = kernel.operand.index
                    kernel = kernel.operand.variable
                    if not isinstance(old_index, GoConstant) or old_index.value != 0:
                        index = GoBinaryOp("Add", old_index, index, codegen=self)
                kernel = GoUnaryOp("Reference", GoIndexedVariable(kernel, index, codegen=self), codegen=self)
                terms.pop()
                continue

            if next_stride > kernel_stride:
                l.warning("Oddly-sized array access stride. Uh oh!")
                return bail_out()

            # nothing has the ability to escape the kernel
            # go in deeper
            if isinstance(kernel_type, SimStruct) and kernel_type.offsets:
                field_name, field_offset = max(
                    ((x, y) for x, y in kernel_type.offsets.items() if y <= constant), key=lambda x: x[1]
                )
                field_type = kernel_type.fields[field_name]
                kernel = GoUnaryOp(
                    "Reference",
                    self._access_constant_offset(kernel, field_offset, field_type, True, renegotiate_type),
                    codegen=self,
                )
                constant -= field_offset
                continue

            if isinstance(kernel_type, (SimTypeArray, SimTypeFixedSizeArray)):
                inner = self._access_constant_offset(kernel, 0, kernel_type.elem_type, True, renegotiate_type)
                if isinstance(inner, GoUnaryOp) and inner.op == "Dereference":
                    # unpack
                    kernel = inner.operand
                else:
                    kernel = GoUnaryOp("Reference", inner, codegen=self)
                if unpack_typeref(unpack_pointer_and_array(kernel.type)) == kernel_type:
                    # we are not making progress
                    pass
                else:
                    continue

            l.warning("There's a variable offset with stride shorter than the primitive type. What does this mean?")
            return bail_out()

        return self._access_constant_offset(kernel, constant, data_type, lvalue, renegotiate_type)

    #
    # Handlers
    #

    def _handle(
        self,
        node,
        is_expr: bool = True,
        lvalue: bool = False,
        likely_signed=False,
        type_: SimType | None = None,
        ref: bool = False,
    ):
        assert self.ailexpr2cnode is not None
        if (node, is_expr) in self.ailexpr2cnode:
            return self.ailexpr2cnode[(node, is_expr)]

        handler: Callable | None = self._handlers.get(_dispatch_key(node), None)
        if handler is not None:
            # special case for Call
            converted = (
                handler(node, is_expr=is_expr)
                if isinstance(node, Stmt.SideEffectStatement)
                else handler(node, lvalue=lvalue, likely_signed=likely_signed, type_=type_, ref=ref)
            )
            self.ailexpr2cnode[(node, is_expr)] = converted
            return converted
        raise UnsupportedNodeTypeError(
            f"Node type {getattr(node, 'kind', None) or type(node).__name__} is not supported yet."
        )

    def _handle_Code(self, node, **kwargs):
        return self._handle(node.node, is_expr=False)

    def _handle_Sequence(self, seq, **kwargs):
        lines = []

        for node in seq.nodes:
            lines.append(self._handle(node, is_expr=False))

        return lines[0] if len(lines) == 1 else GoStatements(lines, codegen=self, addr=seq.addr)

    def _handle_Loop(self, loop_node, **kwargs):
        tags = {"ins_addr": loop_node.addr}

        if loop_node.sort == "while":
            return GoWhileLoop(
                None if loop_node.condition is None else self._handle(loop_node.condition),
                None if loop_node.sequence_node is None else self._handle(loop_node.sequence_node, is_expr=False),
                tags=tags,
                codegen=self,
            )
        if loop_node.sort == "do-while":
            return GoDoWhileLoop(
                self._handle(loop_node.condition),
                None if loop_node.sequence_node is None else self._handle(loop_node.sequence_node, is_expr=False),
                tags=tags,
                codegen=self,
            )
        if loop_node.sort == "for":
            return GoForLoop(
                None if loop_node.initializer is None else self._handle(loop_node.initializer),
                None if loop_node.condition is None else self._handle(loop_node.condition),
                None if loop_node.iterator is None else self._handle(loop_node.iterator),
                None if loop_node.sequence_node is None else self._handle(loop_node.sequence_node, is_expr=False),
                tags=tags,
                codegen=self,
            )

        raise NotImplementedError

    def _handle_Condition(self, condition_node: ConditionNode, **kwargs):
        tags = {"ins_addr": condition_node.addr}

        condition_and_nodes = [
            (
                self._handle(condition_node.condition),
                self._handle(condition_node.true_node, is_expr=False) if condition_node.true_node else None,
            )
        ]

        else_node = self._handle(condition_node.false_node, is_expr=False) if condition_node.false_node else None

        return GoIfElse(
            condition_and_nodes,
            else_node=else_node,
            simplify_else_scope=self.simplify_else_scope
            and structured_node_is_simple_return(condition_node.true_node, self.ail_graph)
            and else_node is not None,
            cstyle_ifs=self.cstyle_ifs,
            tags=tags,
            codegen=self,
        )

    def _handle_CascadingCondition(self, cond_node: CascadingConditionNode, **kwargs):
        tags = {"ins_addr": cond_node.addr}

        condition_and_nodes = [
            (self._handle(cond), self._handle(node, is_expr=False)) for cond, node in cond_node.condition_and_nodes
        ]
        else_node = self._handle(cond_node.else_node) if cond_node.else_node is not None else None

        return GoIfElse(
            condition_and_nodes,
            else_node=else_node,
            tags=tags,
            cstyle_ifs=self.cstyle_ifs,
            codegen=self,
        )

    def _handle_ConditionalBreak(self, node, **kwargs):
        tags = {"ins_addr": node.addr}

        return GoIfBreak(self._handle(node.condition), cstyle_ifs=self.cstyle_ifs, tags=tags, codegen=self)

    def _handle_Break(self, node, **kwargs):
        tags = {"ins_addr": node.addr}

        return GoBreak(tags=tags, codegen=self)

    def _handle_MultiNode(self, node, **kwargs):
        lines = []

        for n in node.nodes:
            r = self._handle(n, is_expr=False)
            lines.append(r)

        return lines[0] if len(lines) == 1 else GoStatements(lines, codegen=self, addr=node.addr)

    def _handle_SwitchCase(self, node, **kwargs):
        """

        :param SwitchCaseNode node:
        :return:
        """

        switch_expr = self._handle(node.switch_expr)
        cases = [(idx, self._handle(case, is_expr=False)) for idx, case in node.cases.items()]
        default = self._handle(node.default_node, is_expr=False) if node.default_node is not None else None
        tags = {"ins_addr": node.addr}
        return GoSwitchCase(switch_expr, cases, default=default, tags=tags, codegen=self)

    def _handle_IncompleteSwitchCase(self, node: IncompleteSwitchCaseNode, **kwargs):
        head = self._handle(node.head, is_expr=False)
        cases = [(case.addr, self._handle(case, is_expr=False)) for case in node.cases]
        tags = {"ins_addr": node.addr}
        return GoIncompleteSwitchCase(head, cases, tags=tags, codegen=self)

    def _handle_Continue(self, node, **kwargs):
        tags = {"ins_addr": node.addr}

        return GoContinue(tags=tags, codegen=self)

    def _handle_AILBlock(self, node, **kwargs):
        """

        :param Block node:
        :return:
        """

        # return GoStatements([ GoAILBlock(node) ])
        cstmts = []
        for stmt in node.statements:
            try:
                cstmt = self._handle(stmt, is_expr=False)
            except UnsupportedNodeTypeError:
                l.warning(
                    "Unsupported AIL statement or expression %s.",
                    getattr(stmt, "kind", None) or type(stmt).__name__,
                    exc_info=True,
                )
                cstmt = GoUnsupportedStatement(stmt, codegen=self)
            cstmts.append(cstmt)

        return GoStatements(cstmts, codegen=self, addr=node.addr)

    #
    # AIL statement handlers
    #

    def _handle_Stmt_Store(self, stmt: Stmt.Store, **kwargs):
        cdata = self._handle(stmt.data)

        store_bits = stmt.size * self.project.arch.byte_width
        if cdata.type is not None and cdata.type.size != store_bits:
            if cdata.type.size is not None:
                l.error(
                    "Store data lifted to a C type of a different size: %s is %d bits, the store is %d bits. "
                    "Using the store width.",
                    cdata.type,
                    cdata.type.size,
                    store_bits,
                )
            if qualifies_for_width_cast(unpack_typeref(cdata.type)):
                cdata = GoTypeCast(
                    cdata.type,
                    self.default_simtype_from_bits(store_bits, signed=getattr(cdata.type, "signed", False)),
                    cdata,
                    codegen=self,
                )

        def negotiate(old_ty, proposed_ty):
            # transfer casts from the dst to the src if possible
            # if we see something like *(size_t*)&v4 = x; where v4 is a pointer, change to v4 = (void*)x;
            nonlocal cdata
            if old_ty != proposed_ty and qualifies_for_simple_cast(old_ty, proposed_ty):
                cdata = GoTypeCast(cdata.type, proposed_ty, cdata, codegen=self)
                return proposed_ty
            return old_ty

        stmt_var = self._variable_map.variable(stmt)
        if stmt_var is not None and cdata.type is not None:
            cvar = self._variable(stmt_var, stmt.size)
            offset = self._variable_map.variable_offset(stmt) or 0
            assert type(offset) is int  # I refuse to deal with the alternative

            cdst = self._access_constant_offset(self._get_variable_reference(cvar), offset, cdata.type, True, negotiate)
        else:
            addr_expr = self._handle(stmt.addr)
            cdst = self._access(addr_expr, cdata.type if cdata.type is not None else SimTypeBottom(), True, negotiate)

        return GoAssignment(cdst, cdata, tags=stmt.tags, codegen=self)

    def variables_unify(self, v1: Expr.VirtualVariable, v2: Expr.VirtualVariable) -> bool:
        vmi = self.kb.dec_variables[self._func.addr]
        v1_var = self._variable_map.variable(v1)
        v2_var = self._variable_map.variable(v2)
        v1v = vmi.unified_variable(v1_var) if v1_var is not None else None
        v2v = vmi.unified_variable(v2_var) if v2_var is not None else None
        return v1v == v2v

    def _handle_Stmt_Assignment(self, stmt, **kwargs):
        if (
            isinstance(stmt.dst, Expr.VirtualVariable)
            and stmt.dst.was_stack
            and self._variable_map.variable(stmt.dst) is not None
            and isinstance(stmt.src, Expr.Insert)
            and isinstance(stmt.src.offset, Expr.Const)
            and isinstance(stmt.src.offset.value, int)
            and (
                (isinstance(stmt.src.base, Expr.VirtualVariable) and self.variables_unify(stmt.src.base, stmt.dst))
                or stmt.src.base.tags.get("uninitialized", False)
            )
        ):
            offset = stmt.src.offset.value
            var = self._variable_map.variable(stmt.dst)
            cvar = self._variable(var, stmt.dst.size, vvar_id=stmt.dst.varid)
            csrc = self._handle(stmt.src.value)
            src_type = csrc.type
            dst_type = src_type
            if "type" in stmt.tags:
                src_type = stmt.tags["type"].get("src")
                dst_type = stmt.tags["type"].get("dst")

            def negotiate(old_ty, proposed_ty):
                # transfer casts from the dst to the src if possible
                # if we see something like *(size_t*)&v4 = x; where v4 is a pointer, change to v4 = (void*)x;
                nonlocal csrc
                if not type_equals(old_ty, proposed_ty) and qualifies_for_simple_cast(old_ty, proposed_ty):
                    csrc = GoTypeCast(csrc.type, proposed_ty, csrc, codegen=self)
                    return proposed_ty
                return old_ty

            assert dst_type is not None
            cdst = self._access_constant_offset(self._get_variable_reference(cvar), offset, dst_type, True, negotiate)
        else:
            csrc = self._handle(stmt.src, lvalue=False)
            cdst = self._handle(stmt.dst, lvalue=True)
            if csrc.type is not None and cdst.type is not None and not type_equals(cdst.type, csrc.type):
                csrc = GoTypeCast(csrc.type, cdst.type, csrc, codegen=self)

        return GoAssignment(cdst, csrc, tags=stmt.tags, codegen=self)

    def _handle_Stmt_SideEffectStatement(self, stmt: Stmt.SideEffectStatement, is_expr: bool = False, **kwargs):
        try:
            # Try to handle it as a normal function call
            target = (
                self._handle(stmt.expr.target, lvalue=True)
                if not isinstance(stmt.expr.target, str)
                else stmt.expr.target
            )
        except UnsupportedNodeTypeError:
            target = stmt.expr.target

        if (
            isinstance(target, GoUnaryOp)
            and target.op == "Reference"
            and isinstance(target.operand, GoVariable)
            and isinstance(target.operand.variable, SimMemoryVariable)
            and not isinstance(target.operand.variable, SimStackVariable)
            and target.operand.variable.size == 1
        ):
            # special case: convert &global_var to just global_var if it's used as the call target
            target = target.operand

        target_func = self.kb.functions.function(addr=target.value) if isinstance(target, GoConstant) else None

        args = []
        if stmt.expr.args is not None:
            for i, arg in enumerate(stmt.expr.args):
                type_ = None
                if (
                    target_func is not None
                    and target_func.prototype is not None
                    and i < len(target_func.prototype.args)
                ):
                    type_ = target_func.prototype.args[i].with_arch(self.project.arch)
                    if target_func.prototype_libname is not None:
                        type_ = dereference_simtype_by_lib(type_, target_func.prototype_libname)

                if isinstance(arg, Expr.Const):
                    if isinstance(arg.value, int) and (
                        type_ is None or is_machine_word_size_type(type_, self.project.arch)
                    ):
                        type_ = guess_value_type(arg.value, self.project) or type_

                    new_arg = self._handle_Expr_Const(arg, type_=type_)
                else:
                    new_arg = self._handle(arg, type_=type_)
                args.append(new_arg)

        ret_expr = None
        if not is_expr and stmt.ret_expr is not None:
            ret_expr = self._handle(stmt.ret_expr)

        call_expr = GoFunctionCall(
            target,
            target_func,
            args,
            tags=stmt.tags,
            show_demangled_name=self.show_demangled_name,
            show_disambiguated_name=self.show_disambiguated_name,
            codegen=self,
        )
        if isinstance(stmt.expr.target, str) and target_func is None:
            site_proto = self._variable_map.prototype(stmt.expr)
            if site_proto is not None and site_proto.returnty is not None:
                call_expr.site_returnty = site_proto.returnty.with_arch(self.project.arch)

        if is_expr:
            # Used as an expression (e.g. nested in another expression)
            if call_expr.type.size != stmt.size * self.project.arch.byte_width:
                call_expr = GoTypeCast(
                    call_expr.type,
                    self.default_simtype_from_bits(
                        stmt.size * self.project.arch.byte_width, signed=getattr(call_expr.type, "signed", False)
                    ),
                    call_expr,
                    codegen=self,
                )
            return call_expr

        returning = target_func.returning if target_func is not None else True

        if ret_expr is not None:
            # ret_expr = call()  =>  GoAssignment(ret_expr, call_expr)
            return GoAssignment(ret_expr, call_expr, tags=stmt.tags, codegen=self)

        # Standalone call statement
        return GoExpressionStatement(call_expr, returning=returning, tags=stmt.tags, codegen=self)

    def _handle_Expr_Call(self, expr: Expr.Call, **kwargs):
        """Handle a Call expression (not wrapped in SideEffectStatement)."""
        if isinstance(expr.target, str):
            kind = expr.tags.get("go_render")
            if kind == "box" and expr.args:
                return GoBoxedValue(
                    self._handle(expr.args[0]), expr.target, expr.tags.get("go_box_type"), tags=expr.tags, codegen=self
                )
            if kind == "slice_literal":
                elems = [self._handle(arg) for arg in expr.args or []]
                return GoSliceLiteral(expr.tags.get("go_elem_type", "any"), elems, tags=expr.tags, codegen=self)
            if kind == "assert" and expr.args:
                return GoTypeAssertion(
                    self._handle(expr.args[0]), expr.tags.get("go_assert_type", "any"), tags=expr.tags, codegen=self
                )
        try:
            target = self._handle(expr.target, lvalue=True) if not isinstance(expr.target, str) else expr.target
        except UnsupportedNodeTypeError:
            target = expr.target

        if (
            isinstance(target, GoUnaryOp)
            and target.op == "Reference"
            and isinstance(target.operand, GoVariable)
            and isinstance(target.operand.variable, SimMemoryVariable)
            and not isinstance(target.operand.variable, SimStackVariable)
            and target.operand.variable.size == 1
        ):
            target = target.operand

        target_func = self.kb.functions.function(addr=target.value) if isinstance(target, GoConstant) else None
        # the call-site prototype (builtins and rewritten calls) when there is no callee function
        site_proto = self._variable_map.prototype(expr) if target_func is None else None

        args = []
        if expr.args is not None:
            for i, arg in enumerate(expr.args):
                type_ = None
                if (
                    target_func is not None
                    and target_func.prototype is not None
                    and i < len(target_func.prototype.args)
                ):
                    type_ = target_func.prototype.args[i].with_arch(self.project.arch)
                    if target_func.prototype_libname is not None:
                        type_ = dereference_simtype_by_lib(type_, target_func.prototype_libname)
                elif site_proto is not None and i < len(site_proto.args):
                    type_ = site_proto.args[i].with_arch(self.project.arch)

                if isinstance(arg, Expr.Const):
                    if isinstance(arg.value, int) and (
                        type_ is None or is_machine_word_size_type(type_, self.project.arch)
                    ):
                        type_ = guess_value_type(arg.value, self.project) or type_
                    new_arg = self._handle_Expr_Const(arg, type_=type_)
                else:
                    new_arg = self._handle(arg, type_=type_)
                args.append(new_arg)

        call_expr = GoFunctionCall(
            target,
            target_func,
            args,
            tags=expr.tags,
            show_demangled_name=self.show_demangled_name,
            show_disambiguated_name=self.show_disambiguated_name,
            codegen=self,
        )
        if site_proto is not None and site_proto.returnty is not None:
            call_expr.site_returnty = site_proto.returnty.with_arch(self.project.arch)

        if (
            expr.bits
            and not isinstance(target, str)
            and call_expr.type is not None
            and not isinstance(call_expr.type, GoSimStruct)
            and call_expr.type.size != expr.size * self.project.arch.byte_width
        ):
            call_expr = GoTypeCast(
                call_expr.type,
                self.default_simtype_from_bits(
                    expr.size * self.project.arch.byte_width, signed=getattr(call_expr.type, "signed", False)
                ),
                call_expr,
                codegen=self,
            )
        return call_expr

    def _handle_Stmt_Jump(self, stmt: Stmt.Jump, **kwargs):
        return GoGoto(self._handle(stmt.target), stmt.target_idx, tags=stmt.tags, codegen=self)

    def _handle_Stmt_ConditionalJump(self, stmt: Stmt.ConditionalJump, **kwargs):
        else_node = (
            None
            if stmt.false_target is None
            else GoGoto(self._handle(stmt.false_target), None, tags=stmt.tags, codegen=self)
        )
        return GoIfElse(
            [
                (
                    self._handle(stmt.condition),
                    GoGoto(self._handle(stmt.true_target), None, tags=stmt.tags, codegen=self),
                )
            ],
            else_node=else_node,
            cstyle_ifs=self.cstyle_ifs,
            tags=stmt.tags,
            codegen=self,
        )

    def _handle_Stmt_IncompleteSwitchCaseHead(self, stmt: IncompleteSwitchCaseHeadStatement, **kwargs):
        # an IncompleteSwitchCaseHeadStatement only reaches the code generator when structuring failed to turn it
        # into a proper switch-case construct. degrade gracefully: render the dispatch semantics that the statement
        # describes as a cascade of if-gotos instead of an unsupported-statement placeholder.
        switch_var = self._handle(stmt.switch_variable)
        bits = getattr(stmt.switch_variable, "bits", None) or self.project.arch.bits
        const_type = self.default_simtype_from_bits(bits, signed=False)
        condition_and_nodes = []
        default_goto = None
        for _, case_value, target_addr, target_idx, _ in stmt.case_addrs:
            goto = GoGoto(target_addr, target_idx, tags=stmt.tags, codegen=self)
            if isinstance(case_value, str):
                if case_value == "default":
                    default_goto = goto
                continue
            cond = GoBinaryOp(
                "CmpEQ",
                switch_var,
                GoConstant(case_value, const_type, codegen=self, tags=stmt.tags),
                codegen=self,
                tags=stmt.tags,
            )
            condition_and_nodes.append((cond, goto))
        if not condition_and_nodes:
            return default_goto if default_goto is not None else GoUnsupportedStatement(stmt, codegen=self)
        return GoIfElse(
            condition_and_nodes,
            else_node=default_goto,
            cstyle_ifs=self.cstyle_ifs,
            tags=stmt.tags,
            codegen=self,
        )

    def _handle_Stmt_Return(self, stmt: Stmt.Return, **kwargs):
        if not stmt.ret_exprs:
            return GoReturn(None, tags=stmt.tags, codegen=self)
        return GoReturn([self._handle(ret_expr) for ret_expr in stmt.ret_exprs], tags=stmt.tags, codegen=self)

    def _handle_Stmt_Label(self, stmt: Stmt.Label, **kwargs):
        clabel = GoLabel(stmt.name, tags=stmt.tags, codegen=self)
        if "ins_addr" in stmt.tags:
            self.map_addr_to_label[(stmt.tags["ins_addr"], stmt.tags.get("block_idx"))] = clabel
        return clabel

    def _handle_Stmt_Dirty(self, stmt: Stmt.DirtyStatement, **kwargs):
        dirty = self._handle(stmt.dirty)
        return GoDirtyStatement(dirty, codegen=self)

    def _handle_Stmt_CAS(self, stmt: Stmt.CAS, **kwargs):
        # CASIntrinsics normally rewrites compare-and-swap statements into intrinsic calls before we get here, but it
        # only recognizes a handful of statement shapes. Render whatever it left behind as the same intrinsic call
        # instead of failing the whole function.
        if stmt.old_hi is None:
            os_name = self.project.simos.name if self.project.simos is not None else None
            call = Expr.Call(
                stmt.idx,
                cas_intrinsic_name(f"cmpxchg{stmt.bits}", os_name),
                args=[stmt.addr, stmt.data_lo, stmt.expd_lo],
                bits=stmt.bits,
                **stmt.tags,
            )
            return self._handle(Stmt.Assignment(stmt.idx, stmt.old_lo, call, **stmt.tags), is_expr=False)
        # a double-width CAS writes two destinations, which no single C expression captures
        return GoUnsupportedStatement(stmt, codegen=self)

    #
    # AIL expression handlers
    #

    def _handle_Expr_Register(self, expr: Expr.Register, lvalue: bool = False, **kwargs):
        def negotiate(old_ty: SimType, proposed_ty: SimType) -> SimType:
            # we do not allow returning a struct for a primitive type
            if old_ty.size == proposed_ty.size and (
                not isinstance(proposed_ty, SimStruct) or isinstance(old_ty, SimStruct)
            ):
                return proposed_ty
            return old_ty

        expr_var = self._variable_map.variable(expr)
        if expr_var:
            cvar = self._variable(expr_var, None)
            if expr_var.size == expr.size:
                return cvar
            expr_var_offset = self._variable_map.variable_offset(expr)
            offset = 0 if expr_var_offset is None else expr_var_offset
            # FIXME: The type should be associated to the register expression itself
            type_ = self.default_simtype_from_bits(expr.bits, signed=False)
            return self._access_constant_offset(self._get_variable_reference(cvar), offset, type_, lvalue, negotiate)
        return GoRegister(expr, tags=expr.tags, codegen=self)

    def _handle_Expr_Load(self, expr: Expr.Load, type_: SimType | None = None, **kwargs):
        if expr.size == UNDETERMINED_SIZE:
            # the size is undetermined; we force it to 1
            expr_size = 1
            expr_bits = 8
        else:
            expr_size = expr.size
            expr_bits = expr.bits

        if expr_size > 100 and isinstance(expr.addr, Expr.Const):
            return self._handle_Expr_Const(expr.addr, type_=SimTypePointer(SimTypeChar()).with_arch(self.project.arch))

        # the type the consumer expects (a typed call argument) beats the width-based default
        expected = unpack_typeref(type_)
        if expected is not None and expected.size == expr_bits and not isinstance(expected, SimTypeBottom):
            ty = expected
        else:
            ty = self.default_simtype_from_bits(expr_bits)

        def negotiate(old_ty: SimType, proposed_ty: SimType) -> SimType:
            # we do not allow returning a struct for a primitive type
            if (
                old_ty.size == proposed_ty.size
                and not isinstance(proposed_ty, SimStruct)
                and not isinstance(old_ty, SimStruct)
            ):
                return proposed_ty
            return old_ty

        expr_var = self._variable_map.variable(expr)
        if expr_var is not None:
            cvar = self._variable(expr_var, expr_size)
            offset = self._variable_map.variable_offset(expr) or 0

            assert type(offset) is int  # I refuse to deal with the alternative
            return self._access_constant_offset(
                GoUnaryOp("Reference", cvar, codegen=self), offset, ty, False, negotiate
            )

        addr_expr = self._handle(expr.addr)
        return self._access(addr_expr, ty, False, negotiate)

    def _handle_Expr_Tmp(self, expr: Tmp, **kwargs):
        l.warning("FIXME: Leftover Tmp expressions are found.")
        return self._variable(SimTemporaryVariable(expr.tmp_idx, expr.bits), expr.size)

    def _handle_Expr_Const(
        self,
        expr: Expr.Const,
        type_=None,
        reference_values: dict[SimType | str, str | bytes | int | float | Function | GoExpression] | None = None,
        variable=None,
        likely_signed=True,
        **kwargs,
    ):
        inline_string = False
        function_pointer = False

        if type_ is None and "type" in expr.tags:
            type_ = expr.tags["type"]

        expr_var = self._variable_map.variable(expr)
        if type_ is None and expr_var is not None:
            type_ = self._get_variable_type(expr_var)

        expr_reference_values = self._variable_map.reference_values(expr)
        if reference_values is None and expr_reference_values is not None:
            reference_values = expr_reference_values.copy()
        if type_ is None and reference_values is not None and len(reference_values) == 1:  # type: ignore
            type_ = next(iter(reference_values))  # type: ignore

        if reference_values is None:
            reference_values = {}
            type_ = unpack_typeref(type_)
            if expr.value in self.kb.obfuscations.type1_deobfuscated_strings:
                deobf_str = self.kb.obfuscations.type1_deobfuscated_strings[expr.value]
                reference_values[SimTypePointer(SimTypeChar())] = deobf_str
                if "deobfuscated_strings" not in self.notes:
                    self.notes["deobfuscated_strings"] = DeobfuscatedStringsNote()
                self.notes["deobfuscated_strings"].add_string("1", deobf_str, ref_addr=expr.value)
                inline_string = True
            elif expr.value in self.kb.obfuscations.type2_deobfuscated_strings:
                deobf_str = self.kb.obfuscations.type2_deobfuscated_strings[expr.value]
                reference_values[SimTypePointer(SimTypeChar())] = deobf_str
                if "deobfuscated_strings" not in self.notes:
                    self.notes["deobfuscated_strings"] = DeobfuscatedStringsNote()
                self.notes["deobfuscated_strings"].add_string("2", deobf_str, ref_addr=expr.value)
                inline_string = True
            elif isinstance(type_, SimTypePointer) and isinstance(type_.pts_to, (SimTypeChar, SimTypeBottom)):
                # char* or void*
                # Try to get a string
                if (
                    self._cfg is not None
                    and expr.value in self._cfg.memory_data
                    and self._cfg.memory_data[expr.value].sort == MemoryDataSort.String
                ):
                    reference_values[type_] = self._cfg.memory_data[expr.value]
                    inline_string = True
            elif isinstance(type_, SimTypeInt):
                # int
                reference_values[type_] = u2s(expr.value, expr.bits) if type_.signed else expr.value

            # we don't know the type of this argument, or the type is not what we are expecting
            # edge cases: (void*)"this is a constant string pointer". in this case, the type_ will be a void*
            # (BOT*) instead of a char*.

            if not reference_values and isinstance(expr.value, int):
                if expr.value in self.project.kb.functions:
                    # It's a function pointer
                    # We don't care about the actual prototype here
                    type_ = SimTypePointer(SimTypeBottom(label="void")).with_arch(self.project.arch)
                    reference_values[type_] = self.project.kb.functions[expr.value]
                    function_pointer = True

                # pure guessing: is it possible that it's a string?
                elif (
                    self._cfg is not None
                    and expr.bits == self.project.arch.bits
                    and expr.value > 0x10000
                    and expr.value in self._cfg.memory_data
                ):
                    md = self._cfg.memory_data[expr.value]
                    if md.sort == MemoryDataSort.String:
                        type_ = SimTypePointer(SimTypeChar().with_arch(self.project.arch)).with_arch(self.project.arch)
                        reference_values[type_] = self._cfg.memory_data[expr.value]
                        # is it a constant string?
                        if is_in_readonly_segment(self.project, expr.value) or is_in_readonly_section(
                            self.project, expr.value
                        ):
                            inline_string = True
                    elif md.sort == MemoryDataSort.UnicodeString:
                        type_ = SimTypePointer(SimTypeWideChar().with_arch(self.project.arch)).with_arch(
                            self.project.arch
                        )
                        reference_values[type_] = self._cfg.memory_data[expr.value]
                        # is it a constant string?
                        if is_in_readonly_segment(self.project, expr.value) or is_in_readonly_section(
                            self.project, expr.value
                        ):
                            inline_string = True

        if type_ is None:
            # default to int or unsigned int, determined by likely_signed
            type_ = self.default_simtype_from_bits(expr.bits, signed=likely_signed)

        expr_reference_variable = self._variable_map.reference_variable(expr)
        if variable is None and expr_reference_variable is not None:
            variable = expr_reference_variable
            if inline_string:
                self._inlined_strings.add(expr_reference_variable)
            elif function_pointer:
                self._function_pointers.add(expr_reference_variable)

        var_access = None
        if variable is not None and not reference_values:
            cvar = self._variable(variable, None)
            offset = self._variable_map.reference_variable_offset(expr)
            var_access = self._access_constant_offset_reference(self._get_variable_reference(cvar), offset, None)

        if var_access is not None:
            if expr.value >= self.min_data_addr:
                return var_access
            reference_values["offset"] = var_access
        return GoConstant(expr.value, type_, reference_values=reference_values, tags=expr.tags, codegen=self)

    def _handle_Expr_UnaryOp(self, expr, type_: SimType | None = None, **kwargs):
        data_type = None
        ref = False
        if expr.op == "Reference":
            ref = True
            if isinstance(type_, SimTypePointer) and not isinstance(type_.pts_to, SimTypeBottom):
                data_type = type_.pts_to

        operand = self._handle(expr.operand, lvalue=expr.op == "Reference", type_=data_type, ref=ref)

        if expr.op == "Reference" and isinstance(operand, GoUnaryOp) and operand.op == "Dereference":
            # cancel out
            return operand.operand
        return GoUnaryOp(
            expr.op,
            operand,
            tags=expr.tags,
            codegen=self,
        )

    def _handle_Expr_BinaryOp(self, expr: BinaryOp, **kwargs):
        expr_var = self._variable_map.variable(expr)
        if expr_var is not None:
            cvar = self._variable(expr_var, None)
            return self._access_constant_offset_reference(
                self._get_variable_reference(cvar), self._variable_map.variable_offset(expr) or 0, None
            )

        lhs = self._handle(expr.operands[0])
        rhs = self._handle(expr.operands[1], likely_signed=expr.op not in {"And", "Or"})
        if isinstance(rhs, GoConstant) and expr.op in {"Shl", "Shr", "Sar", "Rol", "Ror"}:
            # a shift count is a number, never a rune
            rhs.fmt_char = False
        if expr.op.startswith("Cmp"):
            # `x > 0` with a nilable-typed zero on one side and an integer on the other is an integer comparison
            for const, other in ((lhs, rhs), (rhs, lhs)):
                if (
                    isinstance(const, GoConstant)
                    and const.value == 0
                    and _go_is_nilable(const.type)
                    and other.type is not None
                    and isinstance(unpack_typeref(other.type), SimTypeInt)
                ):
                    const._type = other.type

        return GoBinaryOp(
            expr.op,
            lhs,
            rhs,
            tags=expr.tags,
            codegen=self,
            collapsed=expr.depth > self.binop_depth_cutoff,
        )

    def _handle_Expr_Convert(self, expr: Expr.Convert, **kwargs):
        child = self._handle(expr.operand)

        # Use a mask to represent non-standard size conversions
        if expr.to_bits < expr.from_bits and expr.to_bits not in _CAST_TYPES_BY_BITS:
            const_type = child.type if child.type is not None else self.default_simtype_from_bits(expr.from_bits, False)
            mask = GoConstant((1 << expr.to_bits) - 1, const_type, codegen=self, tags=expr.tags)
            return GoBinaryOp("And", child, mask, codegen=self, tags=expr.tags)

        # Cast to the smallest size that can hold the new value
        dst_type_cls = next((cls for bits, cls in _CAST_TYPES_BY_BITS.items() if bits >= expr.to_bits), None)
        if dst_type_cls is None or expr.to_bits < 1:
            raise UnsupportedNodeTypeError(f"Unsupported conversion bits {expr.to_bits}.")
        dst_type: SimTypeInt | SimTypeChar = dst_type_cls()

        orig_child_signed = getattr(child.type, "signed", False)

        # signedness of converted type is hard
        if expr.to_bits < expr.from_bits:
            # very sketchy. basically a guess
            # can we even generate signed downcasts?
            dst_type.signed = orig_child_signed | expr.is_signed
        else:
            dst_type.signed = expr.is_signed

        # do we need an intermediate cast?
        if orig_child_signed != expr.is_signed and expr.to_bits > expr.from_bits and child.type is not None:
            # this is a problem. sign-extension only happens when the SOURCE of the cast is signed
            child_ty = self.default_simtype_from_bits(child.type.size, expr.is_signed)
            child = GoTypeCast(None, child_ty, child, codegen=self)

        return GoTypeCast(None, dst_type.with_arch(self.project.arch), child, tags=expr.tags, codegen=self)

    def _handle_Expr_Struct(self, expr: Struct, **kwargs):
        return GoStructLiteral(
            expr.name,
            OrderedDict((offset, self._handle(field)) for offset, field in expr.fields.items()),
            dict(expr.field_names),
            tags=expr.tags,
            codegen=self,
        )

    def _handle_Expr_StringLiteral(self, expr: StringLiteral, **kwargs):
        return GoStringLiteral(expr.data, tags=expr.tags, codegen=self)

    def _handle_Expr_Extract(self, expr: Expr.Extract, **kwargs):
        child = self._handle(expr.base)
        target_type = self.default_simtype_from_bits(expr.bits, False)
        offset = (
            expr.offset.value if isinstance(expr.offset, Expr.Const) and isinstance(expr.offset.value, int) else None
        )
        child_type = child.type
        assert child_type is not None
        if isinstance(child_type, TypeRef):
            child_type = child_type.type
        if isinstance(child_type, SimStruct) and offset is not None:
            field = next((name for name, off in child_type.offsets.items() if off == offset), None)
            if field is not None and expr.bits == child_type.fields[field].size:
                return GoVariableField(child, GoStructField(child_type, offset, field, codegen=self), codegen=self)
        if isinstance(child_type, SimTypeInt) and offset == 0:  # TODO not big-endian safe
            return GoTypeCast(child_type, target_type, child, codegen=self)

        voidp = SimTypePointer(SimTypeBottom()).with_arch(self.project.arch)
        inner_expr = GoTypeCast(
            SimTypePointer(child_type).with_arch(self.project.arch),
            voidp,
            GoUnaryOp("Reference", child, codegen=self),
            codegen=self,
        )
        if offset != 0:
            inner_expr = GoBinaryOp(
                "Add",
                inner_expr,
                GoConstant(offset, SimTypeInt(), codegen=self),
                codegen=self,
            )
        return GoUnaryOp(
            "Dereference",
            GoTypeCast(
                voidp,
                SimTypePointer(target_type).with_arch(self.project.arch),
                inner_expr,
                codegen=self,
            ),
            codegen=self,
        )

    def _handle_Expr_Insert(self, expr: Expr.Insert, **kwargs):
        # should never really be used - should be handled by Assignment
        return GoFunctionCall(
            "_INSERT",
            None,
            [self._handle(expr.base), self._handle(expr.offset), self._handle(expr.value)],
            codegen=self,
        )

    def _handle_Expr_VEXCCallExpression(self, expr: Expr.VEXCCallExpression, **kwargs):
        operands = [self._handle(arg) for arg in expr.operands]
        return GoVEXCCallExpression(expr.callee, operands, tags=expr.tags, codegen=self)

    def _handle_Expr_Dirty(self, expr: Expr.DirtyExpression, **kwargs):
        return GoDirtyExpression(expr, codegen=self)

    def _handle_Expr_ITE(self, expr: Expr.ITE, **kwargs):
        return GoITE(
            self._handle(expr.cond), self._handle(expr.iftrue), self._handle(expr.iffalse), tags=expr.tags, codegen=self
        )

    def _handle_Reinterpret(self, expr: Expr.Reinterpret, **kwargs):
        def _to_type(bits, typestr):
            if typestr == "I":
                if bits == 32:
                    r = SimTypeInt()
                elif bits == 64:
                    r = SimTypeLongLong()
                else:
                    raise TypeError(f"Unsupported integer type with bits {bits} in Reinterpret")
            elif typestr == "F":
                if bits == 32:
                    r = SimTypeFloat()
                elif bits == 64:
                    r = SimTypeDouble()
                else:
                    raise TypeError(f"Unsupported floating-point type with bits {bits} in Reinterpret")
            else:
                raise TypeError(f"Unexpected reinterpret type {typestr}")
            return r.with_arch(self.project.arch)

        src_type = _to_type(expr.from_bits, expr.from_type)
        dst_type = _to_type(expr.to_bits, expr.to_type)
        return GoTypeCast(src_type, dst_type, self._handle(expr.operand), tags=expr.tags, codegen=self)

    def _handle_MultiStatementExpression(self, expr: Expr.MultiStatementExpression, **kwargs):
        cstmts = GoStatements([self._handle(stmt, is_expr=False) for stmt in expr.stmts], codegen=self)
        cexpr = self._handle(expr.expr)
        return GoMultiStatementExpression(cstmts, cexpr, tags=expr.tags, codegen=self)

    def _handle_VirtualVariable(
        self,
        expr: Expr.VirtualVariable,
        lvalue: bool = False,
        type_: SimType | None = None,
        ref: bool = False,
        **kwargs,
    ):
        expr_var = self._variable_map.variable(expr)
        if expr_var is not None:
            cvar = self._variable(expr_var, None, vvar_id=expr.varid)

            if not lvalue and expr_var.size != expr.size:
                l.warning(
                    "VirtualVariable size (%d) and variable size (%d) do not match. Force a type cast.",
                    expr.size,
                    expr_var.size,
                )
                src_type = cvar.type
                dst_type = {
                    64: SimTypeLongLong(signed=False),
                    32: SimTypeInt(signed=False),
                    16: SimTypeShort(signed=False),
                    8: SimTypeChar(signed=False),
                }.get(expr.bits)
                if dst_type is not None:
                    dst_type = dst_type.with_arch(self.project.arch)
                    return GoTypeCast(src_type, dst_type, cvar, tags=expr.tags, codegen=self)
            return cvar
        return GoDirtyExpression(expr, codegen=self)

    def _handle_Expr_StackBaseOffset(self, expr: StackBaseOffset, **kwargs):
        expr_var = self._variable_map.variable(expr)
        if expr_var is not None:
            var_thing = self._variable(expr_var, expr.size)
            var_thing.tags = dict(expr.tags)
            if "def_at" in var_thing.tags and "ins_addr" not in var_thing.tags:
                var_thing.tags["ins_addr"] = var_thing.tags["def_at"].tags["ins_addr"]
            return self._get_variable_reference(var_thing)

        # FIXME
        stack_base = GoFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=self)
        return GoBinaryOp("Add", stack_base, GoConstant(expr.offset, SimTypeInt(), codegen=self), codegen=self)

    #
    # Serialization
    #


class GoStructuredCodeWalker:
    def handle(self, obj):
        handler = getattr(self, "handle_" + type(obj).__name__, self.handle_default)
        return handler(obj)

    def handle_default(self, obj):
        return obj

    def handle_GoFunction(self, obj):
        obj.statements = self.handle(obj.statements)
        return obj

    def handle_GoStatements(self, obj):
        obj.statements = [self.handle(stmt) for stmt in obj.statements]
        return obj

    def handle_GoWhileLoop(self, obj):
        obj.condition = self.handle(obj.condition)
        obj.body = self.handle(obj.body)
        return obj

    def handle_GoDoWhileLoop(self, obj):
        obj.condition = self.handle(obj.condition)
        obj.body = self.handle(obj.body)
        return obj

    def handle_GoRangeLoop(self, obj):
        obj.collection = self.handle(obj.collection)
        obj.body = self.handle(obj.body)
        return obj

    def handle_GoMethodCall(self, obj):
        obj.receiver = self.handle(obj.receiver)
        obj.args = [self.handle(arg) for arg in obj.args]
        return obj

    def handle_GoMultiAssignment(self, obj):
        obj.lhs = [self.handle(x) for x in obj.lhs]
        obj.rhs = self.handle(obj.rhs)
        return obj

    def handle_GoStructLiteral(self, obj):
        obj.fields = OrderedDict((k, self.handle(v)) for k, v in obj.fields.items())
        return obj

    def handle_GoBoxedValue(self, obj):
        obj.expr = self.handle(obj.expr)
        return obj

    def handle_GoTypeSwitch(self, obj):
        obj.value = self.handle(obj.value)
        obj.cases = [(name, self.handle(body)) for name, body in obj.cases]
        if obj.default is not None:
            obj.default = self.handle(obj.default)
        return obj

    def handle_GoSelect(self, obj):
        for case in [c for c, _ in obj.cases]:
            if case.channel is not None:
                case.channel = self.handle(case.channel)
            if case.kind == "send" and case.value is not None:
                case.value = self.handle(case.value)
        obj.cases = [(case, self.handle(body)) for case, body in obj.cases]
        return obj

    def handle_GoTypeAssertion(self, obj):
        obj.expr = self.handle(obj.expr)
        return obj

    def handle_GoSliceLiteral(self, obj):
        obj.elems = [self.handle(e) for e in obj.elems]
        return obj

    def handle_GoForLoop(self, obj):
        obj.initializer = self.handle(obj.initializer)
        obj.condition = self.handle(obj.condition)
        obj.iterator = self.handle(obj.iterator)
        obj.body = self.handle(obj.body)
        return obj

    def handle_GoIfElse(self, obj):
        obj.condition_and_nodes = [
            (self.handle(condition), self.handle(node)) for condition, node in obj.condition_and_nodes
        ]
        obj.else_node = self.handle(obj.else_node)
        return obj

    def handle_GoIfBreak(self, obj):
        obj.condition = self.handle(obj.condition)
        return obj

    def handle_GoSwitchCase(self, obj):
        obj.switch = self.handle(obj.switch)
        obj.cases = [(case, self.handle(body)) for case, body in obj.cases]
        obj.default = self.handle(obj.default)
        return obj

    def handle_GoAssignment(self, obj):
        obj.lhs = self.handle(obj.lhs)
        obj.rhs = self.handle(obj.rhs)
        return obj

    def handle_GoExpressionStatement(self, obj):
        obj.expr = self.handle(obj.expr)
        return obj

    def handle_GoFunctionCall(self, obj):
        obj.callee_target = self.handle(obj.callee_target)
        obj.args = [self.handle(arg) for arg in obj.args]
        return obj

    def handle_GoReturn(self, obj):
        obj.retvals = [self.handle(retval) for retval in obj.retvals]
        return obj

    def handle_GoGoto(self, obj):
        obj.target = self.handle(obj.target)
        return obj

    def handle_GoIndexedVariable(self, obj):
        obj.variable = self.handle(obj.variable)
        obj.index = self.handle(obj.index)
        return obj

    def handle_GoVariableField(self, obj):
        obj.variable = self.handle(obj.variable)
        return obj

    def handle_GoUnaryOp(self, obj):
        obj.operand = self.handle(obj.operand)
        return obj

    def handle_GoBinaryOp(self, obj):
        obj.lhs = self.handle(obj.lhs)
        obj.rhs = self.handle(obj.rhs)
        return obj

    def handle_GoTypeCast(self, obj):
        obj.expr = self.handle(obj.expr)
        return obj

    def handle_GoITE(self, obj):
        obj.cond = self.handle(obj.cond)
        obj.iftrue = self.handle(obj.iftrue)
        obj.iffalse = self.handle(obj.iffalse)
        return obj


def _go_expr_children(node):
    names = [slot for cls in type(node).__mro__ for slot in cls.__dict__.get("__slots__", ())]
    names += [name for name in getattr(node, "__dict__", {}) if name != "codegen"]
    for slot in names:
        child = getattr(node, slot, None)
        if isinstance(child, GoConstruct):
            yield child
        elif isinstance(child, (list, tuple)):
            for item in child:
                if isinstance(item, GoConstruct):
                    yield item
                elif isinstance(item, tuple):
                    yield from (x for x in item if isinstance(x, GoConstruct))
        elif isinstance(child, dict):
            yield from (x for x in child.values() if isinstance(x, GoConstruct))


def _go_mentions_variable(node, var: GoVariable, skip=None) -> bool:
    """Whether ``var`` is referenced anywhere under ``node`` (excluding the ``skip`` node)."""
    if node is None or node is skip:
        return False
    if isinstance(node, GoVariable) and _same_variable(node, var):
        return True
    return any(_go_mentions_variable(child, var, skip) for child in _go_expr_children(node))


def _go_length_of(expr):
    """The collection whose length ``expr`` denotes (``s.len`` or ``len(s)``), or None."""
    if isinstance(expr, GoVariableField) and expr.field.field == "len":
        base = expr.variable
        if isinstance(unpack_typeref(base.type), (GoSimTypeSlice, GoSimTypeString)):
            return base
    if isinstance(expr, GoFunctionCall) and expr.callee_target == "len" and len(expr.args) == 1:
        return expr.args[0]
    return None


def _go_leaf(stmts: list, last: bool = False):
    """(container list, index) of the first (or last) statement, descending into nested GoStatements blocks."""
    container = stmts
    while container:
        idx = len(container) - 1 if last else 0
        stmt = container[idx]
        if isinstance(stmt, GoStatements):
            container = stmt.statements
            continue
        return container, idx
    return None, None


def _go_is_var(expr, var) -> bool:
    return isinstance(expr, GoVariable) and isinstance(var, GoVariable) and _same_variable(expr, var)


def _go_is_plus_one(stmt, dst, src) -> bool:
    """``dst = src + 1``"""
    return (
        isinstance(stmt, GoAssignment)
        and _go_is_var(stmt.lhs, dst)
        and isinstance(stmt.rhs, GoBinaryOp)
        and stmt.rhs.op == "Add"
        and _go_is_var(stmt.rhs.lhs, src)
        and isinstance(stmt.rhs.rhs, GoConstant)
        and stmt.rhs.rhs.value == 1
    )


def _go_is_increment(stmt, var) -> bool:
    return _go_is_plus_one(stmt, var, var)


class _PointerWalkSubstituter(GoStructuredCodeWalker):
    """Reads through a pointer that walks a slice become reads of the range value it points at."""

    ITAB_FUN_OFFSET = 24

    def __init__(self, codegen, pointer, value, elem_type):
        self._codegen = codegen
        self._pointer = pointer
        self._value = value
        self._elem = elem_type
        self.count = 0

    def _is_pointer(self, expr) -> bool:
        while isinstance(expr, GoTypeCast):
            expr = expr.expr
        return isinstance(expr, GoVariable) and _same_variable(expr, self._pointer)

    def _field_at(self, offset: int):
        elem = self._elem
        if isinstance(elem, GoSimTypeInterface):
            ws = self._codegen.project.arch.bytes
            name = {0: "tab", ws: "data"}.get(offset)
            return GoStructField(elem, offset, name, codegen=self._codegen) if name is not None else None
        if isinstance(elem, SimStruct):
            for name, off in elem.offsets.items():
                if off == offset:
                    return GoStructField(elem, offset, name, codegen=self._codegen)
        return None

    def handle_GoFunctionCall(self, obj):
        # p.tab.fun[i](p.data, args): a method of the element's interface
        target = obj.callee_target
        while isinstance(target, GoTypeCast):
            target = target.expr
        if (
            isinstance(self._elem, GoSimTypeInterface)
            and isinstance(target, GoVariableField)
            and isinstance(target.variable, GoVariableField)
            and self._is_pointer(target.variable.variable)
            and target.variable.field.offset == 0
            and isinstance(target.field.offset, int)
        ):
            index, rem = divmod(target.field.offset - self.ITAB_FUN_OFFSET, self._codegen.project.arch.bytes)
            if not rem and 0 <= index < len(self._elem.methods):
                name, sig = self._elem.methods[index]
                args = [self.handle(a) for a in list(obj.args)[1:]]
                self.count += 1
                return GoMethodCall(self._value, name, args, signature=sig, tags=obj.tags, codegen=self._codegen)
        return super().handle_GoFunctionCall(obj)

    def handle_GoVariableField(self, obj):
        if self._is_pointer(obj.variable) and isinstance(obj.field.offset, int):
            field = self._field_at(obj.field.offset)
            if field is not None:
                self.count += 1
                return GoVariableField(self._value, field, codegen=self._codegen)
        return super().handle_GoVariableField(obj)

    def handle_GoUnaryOp(self, obj):
        if obj.op == "Dereference" and self._is_pointer(obj.operand):
            self.count += 1
            return self._value
        return super().handle_GoUnaryOp(obj)

    def handle_GoIndexedVariable(self, obj):
        if self._is_pointer(obj.variable) and isinstance(obj.index, GoConstant) and obj.index.value == 0:
            self.count += 1
            return self._value
        return super().handle_GoIndexedVariable(obj)

    def handle_GoStructLiteral(self, obj):
        obj = super().handle_GoStructLiteral(obj)
        # a two-word result split into (call, dangling register): the call already carries the whole value
        fields = list(obj.fields.values())
        if (
            len(fields) == 2
            and isinstance(fields[0], GoMethodCall)
            and fields[0].signature is not None
            and _go_var_named(fields[1])
            and obj.type is not None
            and unpack_typeref(fields[0].type) is not None
            and getattr(unpack_typeref(fields[0].type), "size", None) == obj.type.size
        ):
            return fields[0]
        return obj


class RangeLoopRecovery(GoStructuredCodeWalker):
    """
    Turn a counting loop over a slice or string into ``for i, x = range s``: the index starts at zero (in the loop
    initializer or just before the loop), the condition is ``i < len(s)`` (the length possibly hoisted into a
    variable or the initializer) and the index advances by one per iteration. The range value is bound from
    ``x = s.ptr[i]`` at the top of the body, or from a pointer that starts at ``s.ptr`` and advances by one element
    at the end of the body.
    """

    def __init__(self, codegen):
        self._codegen = codegen
        self._extra_decls = []

    def handle_GoFunction(self, obj):
        obj = super().handle_GoFunction(obj)
        obj.extra_decls.extend(self._extra_decls)
        return obj

    def handle_GoStatements(self, obj):
        stmts = _go_stmt_list(GoStatements([self.handle(stmt) for stmt in obj.statements], codegen=self._codegen))
        out = []
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, GoForLoop):
                replaced = self._try_range(stmt, out, stmts[i + 1 :])
                if replaced is not None:
                    out.extend(replaced)
                    continue
            out.append(stmt)
        obj.statements = out
        return obj

    @staticmethod
    def _zero_assignment(stmt, var) -> bool:
        return (
            isinstance(stmt, GoAssignment)
            and _go_is_var(stmt.lhs, var)
            and isinstance(stmt.rhs, GoConstant)
            and stmt.rhs.value == 0
        )

    def _try_range(self, loop: GoForLoop, preceding: list, following: list):
        if loop.condition is None or not isinstance(loop.body, GoStatements):
            return None
        cond = loop.condition
        if not isinstance(cond, GoBinaryOp):
            return None
        if cond.op in ("CmpGT", "CmpGTs"):
            length, index = cond.lhs, cond.rhs
        elif cond.op in ("CmpLT", "CmpLTs"):
            index, length = cond.lhs, cond.rhs
        else:
            return None
        if not isinstance(index, GoVariable):
            return None

        # the collection: len(s) itself, or a variable holding it (assigned in the initializer or just before)
        coll = _go_length_of(length)
        len_in_init = False
        len_stmt_idx = None
        init = loop.initializer
        if coll is None and isinstance(length, GoVariable):
            if isinstance(init, GoAssignment) and _go_is_var(init.lhs, length) and _go_length_of(init.rhs) is not None:
                coll = _go_length_of(init.rhs)
                len_in_init = True
            elif preceding and isinstance(preceding[-1], GoAssignment) and _go_is_var(preceding[-1].lhs, length):
                coll = _go_length_of(preceding[-1].rhs)
                len_stmt_idx = len(preceding) - 1
        if coll is None:
            return None

        body = list(loop.body.statements)
        iterator = loop.iterator
        if not (isinstance(iterator, GoAssignment) and _go_is_var(iterator.lhs, index)):
            return None
        drop_first = False
        first = body[0] if body else None
        if _go_is_increment(iterator, index):
            pass
        elif isinstance(iterator.rhs, GoVariable) and first is not None and _go_is_plus_one(first, iterator.rhs, index):
            # next = i + 1 at the top of the body; the temporary must not be used anywhere else
            if any(_go_mentions_variable(stmt, iterator.rhs, skip=first) for stmt in body):
                return None
            drop_first = True
        else:
            return None
        # a hoisted length must not be used anywhere else
        if isinstance(length, GoVariable) and (
            any(_go_mentions_variable(stmt, length) for stmt in body)
            or any(_go_mentions_variable(stmt, length) for stmt in following)
        ):
            return None

        # the index starts at zero: in the initializer, or in one of the few statements before the loop
        hoisted = []
        drop_before = set()
        if len_stmt_idx is not None:
            drop_before.add(len_stmt_idx)
        if not len_in_init and isinstance(init, GoAssignment) and _go_is_var(init.lhs, index):
            if not (isinstance(init.rhs, GoConstant) and init.rhs.value == 0):
                return None
        else:
            zero_idx = None
            for k in range(len(preceding) - 1, max(-1, len(preceding) - 4), -1):
                if k in drop_before:
                    continue
                st = preceding[k]
                if isinstance(st, GoAssignment) and _go_is_var(st.lhs, index):
                    if self._zero_assignment(st, index):
                        zero_idx = k
                    break
            if zero_idx is None:
                return None
            drop_before.add(zero_idx)
            if init is not None and not len_in_init:
                hoisted.append(init)

        # the range value: x = s.ptr[i] at the top, or a pointer walking the slice
        value = None
        walker = None
        if drop_first:
            body = body[1:]
        first = body[0] if body else None
        if isinstance(first, GoAssignment) and isinstance(first.lhs, GoVariable):
            rhs = first.rhs
            if (
                isinstance(rhs, GoIndexedVariable)
                and _go_is_var(rhs.index, index)
                and isinstance(rhs.variable, GoVariableField)
                and rhs.variable.field.field == "ptr"
                and isinstance(rhs.variable.variable, GoVariable)
                and _same_variable(rhs.variable.variable, coll)
            ):
                value = first.lhs
                body = body[1:]
        last = body[-1] if body else None
        if value is None and isinstance(last, GoAssignment) and isinstance(last.lhs, GoVariable):
            pointer = last.lhs
            if _go_is_increment(last, pointer):
                for k in range(len(preceding) - 1, max(-1, len(preceding) - 4), -1):
                    if k in drop_before:
                        continue
                    st = preceding[k]
                    if isinstance(st, GoAssignment) and _go_is_var(st.lhs, pointer):
                        rhs = st.rhs
                        if (
                            isinstance(rhs, GoVariableField)
                            and rhs.field.field == "ptr"
                            and isinstance(rhs.variable, GoVariable)
                            and _same_variable(rhs.variable, coll)
                            and not any(_go_mentions_variable(x, pointer) for x in following)
                        ):
                            walker = (pointer, k)
                        break
        new_body = body
        if walker is not None:
            pointer, k = walker
            elem = unpack_typeref(coll.type)
            elem = elem.elem_type if isinstance(elem, GoSimTypeSlice) else None
            if elem is None:
                return None
            taken = {v.name for v in self._codegen.cfunc.unified_local_vars if v.name} if self._codegen.cfunc else set()
            name = "x"
            n = 1
            while name in taken:
                n += 1
                name = f"x{n}"
            elem = elem.with_arch(self._codegen.project.arch)
            fake = GoFakeVariable(name, elem, codegen=self._codegen)
            probe = GoStatements(body[:-1], codegen=self._codegen)
            sub = _PointerWalkSubstituter(self._codegen, pointer, fake, elem)
            probe = sub.handle(probe)
            # every remaining mention of the pointer must have been a read through it
            if sub.count == 0 or any(_go_mentions_variable(st, pointer) for st in probe.statements):
                return None
            new_body = probe.statements
            value = fake
            self._extra_decls.append((name, elem))
            drop_before.add(k)

        for k in sorted(drop_before, reverse=True):
            preceding.pop(k)
        body_node = GoStatements(new_body, addr=loop.body.addr, codegen=self._codegen)
        return [*hoisted, GoRangeLoop(index, value, coll, body_node, tags=loop.tags, codegen=self._codegen)]


def _go_var_key(var: GoVariable):
    return var.unified_variable if var.unified_variable is not None else var.variable


def _go_tuple_result_call(expr):
    """The call in ``expr`` (possibly under a cast) whose result is a tuple, or None."""
    inner = expr.expr if isinstance(expr, GoTypeCast) else expr
    if isinstance(inner, GoFunctionCall) and isinstance(unpack_typeref(inner.type), GoSimTypeTuple):
        return inner
    return None


class TupleDestructuring(GoStructuredCodeWalker):
    """
    ``v = f()`` followed by ``v.~r0`` / ``v.~r1`` accesses of a multi-result value becomes ``a, err = f()`` with
    one variable per result, when the value is only ever read through its fields.
    """

    def __init__(self, codegen, cfunc: GoFunction):
        self._codegen = codegen
        self._cfunc = cfunc
        self._defs: dict = defaultdict(list)
        self._ok: dict = {}
        self._fakes: dict = {}
        self._tuples: dict = {}

    # -- pass 1: eligibility
    def collect(self, node, parent=None, attr=None):
        if isinstance(node, GoVariable):
            key = _go_var_key(node)
            if isinstance(parent, GoAssignment) and attr == "lhs":
                call = _go_tuple_result_call(parent.rhs)
                if call is None:
                    self._ok[key] = False
                else:
                    self._defs[key].append(parent)
                    self._tuples.setdefault(key, unpack_typeref(call.type))
            elif isinstance(parent, GoVariableField) and attr == "variable":
                tup = self._tuples.get(key) or unpack_typeref(node.type)
                if not (isinstance(tup, GoSimTypeTuple) and parent.field.field in tup.names):
                    self._ok[key] = False
            else:
                self._ok[key] = False
            return
        for name in _go_node_attr_names(node):
            child = getattr(node, name, None)
            if isinstance(child, GoConstruct):
                self.collect(child, node, name)
            elif isinstance(child, (list, tuple)):
                for item in child:
                    if isinstance(item, GoConstruct):
                        self.collect(item, node, name)
                    elif isinstance(item, tuple):
                        for x in item:
                            if isinstance(x, GoConstruct):
                                self.collect(x, node, name)
            elif isinstance(child, dict):
                for x in child.values():
                    if isinstance(x, GoConstruct):
                        self.collect(x, node, name)

    def run(self):
        self.collect(self._cfunc.statements)
        taken = {v.name for v in self._cfunc.unified_local_vars if v.name}
        for key, assignments in self._defs.items():
            if not self._ok.get(key, True) or key not in self._tuples:
                continue
            tup = self._tuples[key]
            var = assignments[0].lhs
            var_name = (var.unified_variable or var.variable).name or "v"
            # the destructured value itself disappears, so its name can be reused
            taken.discard(var_name)
            names = []
            first_plain = True
            is_recv = call_tag(assignments[0].rhs, "go_render") == "recv"
            for i, (rname, elem) in enumerate(zip(tup.names, tup.elems)):
                if not rname.startswith("~"):
                    base = rname
                elif isinstance(unpack_typeref(elem), GoSimTypeInterface) and unpack_typeref(elem).go_name == "error":
                    base = "err"
                elif isinstance(unpack_typeref(elem), (SimTypeBool, GoSimTypeBool)):
                    base = "ok"
                elif first_plain:
                    # a received value is conventionally "v"
                    base = "v" if is_recv else var_name
                    first_plain = False
                else:
                    base = f"{var_name}{i}"
                name = base
                n = 1
                while name in taken:
                    n += 1
                    name = f"{base}{n}"
                taken.add(name)
                names.append(name)
            fakes = [GoFakeVariable(n, t, codegen=self._codegen) for n, t in zip(names, tup.elems)]
            self._fakes[key] = fakes
            for fake, ty in zip(fakes, tup.elems):
                self._cfunc.extra_decls.append((fake.name, ty))
        if self._fakes:
            self._cfunc.statements = self.handle(self._cfunc.statements)

    # -- pass 2: rewrite
    def handle_GoAssignment(self, obj):
        if isinstance(obj.lhs, GoVariable):
            fakes = self._fakes.get(_go_var_key(obj.lhs))
            call = _go_tuple_result_call(obj.rhs)
            if fakes is not None and call is not None:
                return GoMultiAssignment(fakes, self.handle(call), tags=obj.tags, codegen=self._codegen)
        return super().handle_GoAssignment(obj)

    def handle_GoVariableField(self, obj):
        if isinstance(obj.variable, GoVariable):
            fakes = self._fakes.get(_go_var_key(obj.variable))
            tup = self._tuples.get(_go_var_key(obj.variable))
            if fakes is not None and tup is not None and obj.field.field in tup.names:
                return fakes[tup.names.index(obj.field.field)]
        return super().handle_GoVariableField(obj)


def _go_node_attr_names(node) -> list[str]:
    names = [slot for cls in type(node).__mro__ for slot in cls.__dict__.get("__slots__", ())]
    names += [name for name in getattr(node, "__dict__", {}) if name != "codegen"]
    return names


_PRINT_VALUE_FUNCS = frozenset(
    {
        "runtime.printbool",
        "runtime.printfloat",
        "runtime.printcomplex",
        "runtime.printint",
        "runtime.printuint",
        "runtime.printhex",
        "runtime.printpointer",
        "runtime.printuintptr",
        "runtime.printstring",
        "runtime.printslice",
        "runtime.printeface",
        "runtime.printiface",
    }
)


def _go_leaf_statements(stmts: GoStatements):
    """(container list, index, statement) for every statement, descending into nested GoStatements only."""
    for i, stmt in enumerate(list(stmts.statements)):
        if isinstance(stmt, GoStatements):
            yield from _go_leaf_statements(stmt)
        else:
            yield stmts.statements, i, stmt


def _go_runtime_call_name(stmt) -> str | None:
    if isinstance(stmt, GoExpressionStatement) and isinstance(stmt.expr, GoFunctionCall):
        func = stmt.expr.callee_func
        if func is not None:
            return normalize_go_func_name(func.name)
        if isinstance(stmt.expr.callee_target, str):
            return stmt.expr.callee_target
    return None


class PrintFolding(GoStructuredCodeWalker):
    """
    Fold the ``printlock; print<T>(a); printsp; ...; printnl; printunlock`` sequence the compiler emits for the
    ``print``/``println`` builtins back into one call.
    """

    def __init__(self, codegen):
        self._codegen = codegen

    def handle_GoStatements(self, obj):
        obj.statements = [self.handle(stmt) for stmt in obj.statements]
        leaves = list(_go_leaf_statements(obj))
        i = 0
        while i < len(leaves):
            if _go_runtime_call_name(leaves[i][2]) != "runtime.printlock":
                i += 1
                continue
            args = []
            newline = False
            j = i + 1
            while j < len(leaves):
                name = _go_runtime_call_name(leaves[j][2])
                if name == "runtime.printunlock":
                    break
                if name in _PRINT_VALUE_FUNCS and leaves[j][2].expr.args:
                    args.append(leaves[j][2].expr.args[0])
                elif name == "runtime.printnl":
                    newline = True
                elif name != "runtime.printsp":
                    break
                j += 1
            if j >= len(leaves) or _go_runtime_call_name(leaves[j][2]) != "runtime.printunlock":
                i += 1
                continue
            lock = leaves[i][2]
            call = GoFunctionCall("println" if newline else "print", None, args, tags=lock.tags, codegen=self._codegen)
            folded = GoExpressionStatement(call, tags=lock.tags, codegen=self._codegen)
            # drop the whole run (from the back so indices stay valid) and put the folded call where the lock was
            for container, idx, _ in sorted(leaves[i + 1 : j + 1], key=lambda x: -x[1]):
                container.pop(idx)
            leaves[i][0][leaves[i][1]] = folded
            leaves = list(_go_leaf_statements(obj))
            i += 1
        return obj


def _go_itab_slot(expr):
    """(interface value, byte offset) when ``expr`` reads a slot of an interface value's itab; else None."""
    while isinstance(expr, GoTypeCast):
        expr = expr.expr
    if isinstance(expr, GoIndexedVariable) and isinstance(expr.index, GoConstant):
        base, offset = expr.variable, expr.index.value
    elif isinstance(expr, GoVariableField) and isinstance(expr.field.offset, int) and _go_is_iface_word(expr.variable):
        # the method table read as a field of the itab word
        base, offset = expr.variable, expr.field.offset
    elif isinstance(expr, GoUnaryOp) and expr.op == "Dereference":
        inner = expr.operand
        while isinstance(inner, GoTypeCast):
            inner = inner.expr
        if isinstance(inner, GoBinaryOp) and inner.op == "Add" and isinstance(inner.rhs, GoConstant):
            base, offset = inner.lhs, inner.rhs.value
        else:
            return None
    else:
        return None
    if _go_is_iface_word(base) and isinstance(offset, int):
        return base.variable, offset
    return None


class InterfaceMethodCalls(GoStructuredCodeWalker):
    """``x.tab[24 + 8*i](x.data, args...)`` becomes ``x.Method(args...)`` using the interface's method set."""

    ITAB_FUN_OFFSET = 24

    def __init__(self, codegen):
        self._codegen = codegen

    def handle_GoFunctionCall(self, obj):
        obj = super().handle_GoFunctionCall(obj)
        if obj.callee_func is not None or isinstance(obj.callee_target, str):
            return obj
        slot = _go_itab_slot(obj.callee_target)
        if slot is None:
            return obj
        receiver, offset = slot
        iface = unpack_typeref(receiver.type)
        index, rem = divmod(offset - self.ITAB_FUN_OFFSET, self._codegen.project.arch.bytes)
        if rem or index < 0 or index >= len(iface.methods):
            return obj
        name, sig = iface.methods[index]
        args = list(obj.args)
        if args and isinstance(args[0], GoVariableField) and args[0].field.field == "data":
            args = args[1:]
        return GoMethodCall(receiver, name, args, signature=sig, tags=obj.tags, codegen=self._codegen)


def _go_descriptor_addr(expr) -> int | None:
    """The address of the runtime type descriptor or itab that ``expr`` references, or None."""
    if isinstance(expr, GoConstant) and isinstance(expr.value, int):
        return expr.value
    if isinstance(expr, GoUnaryOp) and expr.op == "Reference":
        operand = expr.operand
        offset = 0
        # &global.field.sub: the innermost field's address
        while isinstance(operand, GoVariableField) and isinstance(operand.field.offset, int):
            offset += operand.field.offset
            operand = operand.variable
        if isinstance(operand, GoVariable):
            var = operand.variable
            if isinstance(var, SimMemoryVariable) and not isinstance(var, SimStackVariable):
                return var.addr + offset
    return None


def _go_iface_word(expr, names: tuple[str, ...]):
    """The interface value whose ``tab``/``data`` word ``expr`` is, or None."""
    if isinstance(expr, GoVariableField) and expr.field.field in names:
        value = expr.variable
        if isinstance(unpack_typeref(value.type), GoSimTypeInterface):
            return value
    return None


def _go_text(expr) -> str:
    return "".join(str(c) for c, _ in expr.c_repr_chunks())


def _go_same_value(a, b) -> bool:
    if isinstance(a, GoVariable) and isinstance(b, GoVariable):
        return _same_variable(a, b)
    return type(a) is type(b) and _go_text(a) == _go_text(b)


def _go_assertion_var_name(type_name: str) -> str:
    base = type_name.lstrip("*[]")
    if base in ("int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64"):
        return "n"
    if base == "string":
        return "s"
    if base == "error":
        return "err"
    if base == "bool":
        return "b"
    name = base.rsplit(".", 1)[-1]
    name = re.sub(r"[^A-Za-z0-9_]", "", name)
    return (name[:1].lower() + name[1:]) if name else "x"


class _DataReadSubstituter(GoStructuredCodeWalker):
    """Replaces reads of an interface value's data word with the asserted value."""

    def __init__(self, value, replacement, holder_type=None):
        self._value = value
        self._replacement = replacement  # None counts the reads without changing anything
        self._holder_type = holder_type  # set when the holder is untyped: its second word is the data word
        self.count = 0

    def _is_data_of_value(self, expr) -> bool:
        holder = _go_iface_word(expr, ("data",))
        if holder is None and self._holder_type is not None and isinstance(expr, GoVariableField):
            ws = expr.codegen.project.arch.bytes if expr.codegen is not None else 8
            if expr.field.offset == ws and _go_var_named(expr.variable):
                holder = expr.variable
        return holder is not None and _go_same_value(holder, self._value)

    def handle_GoUnaryOp(self, obj):
        if obj.op == "Dereference":
            inner = obj.operand
            target = inner.expr if isinstance(inner, GoTypeCast) else inner
            if self._is_data_of_value(target):
                self.count += 1
                return obj if self._replacement is None else self._replacement
        return super().handle_GoUnaryOp(obj)

    def handle_GoVariableField(self, obj):
        if self._is_data_of_value(obj):
            self.count += 1
            return obj if self._replacement is None else self._replacement
        return super().handle_GoVariableField(obj)


class TypeAssertionRecovery(GoStructuredCodeWalker):
    """
    ``if v.tab == &type:T`` guarding reads of ``v.data`` becomes ``x, ok := v.(T)`` followed by ``if ok``; the
    same check guarding only a ``runtime.panicdottype*`` call is the panicking form ``v.(T)``.
    """

    PANIC_NAMES = frozenset({"runtime.panicdottypeE", "runtime.panicdottypeI", "runtime.panicnildottype"})

    def __init__(self, codegen, cfunc: GoFunction):
        self._codegen = codegen
        self._cfunc = cfunc
        self._taken = {v.name for v in cfunc.unified_local_vars if v.name} | {n for n, _ in cfunc.extra_decls}
        self._taken |= {arg.name for arg in getattr(cfunc, "arg_list", []) if getattr(arg, "name", None)}

    def run(self):
        root = self._cfunc.statements
        if not isinstance(root, GoStatements):
            # a body that is a single compound statement
            root = GoStatements([root], addr=getattr(root, "addr", None), codegen=self._codegen)
        self._cfunc.statements = self.handle(root)

    def handle_GoStatements(self, obj):
        out = []
        for stmt in obj.statements:
            stmt = self.handle(stmt)
            if isinstance(stmt, GoIfElse):
                replaced = self._try_assertion(stmt)
                if replaced is not None:
                    out.extend(replaced)
                    continue
            out.append(stmt)
        obj.statements = out
        return obj

    def _match_check(self, cond):
        """(value, concrete type name, equal?) for ``v.tab ==/!= descriptor``."""
        if not isinstance(cond, GoBinaryOp) or cond.op not in ("CmpEQ", "CmpNE"):
            return None
        for word, desc in ((cond.lhs, cond.rhs), (cond.rhs, cond.lhs)):
            value = _go_iface_word(word, ("tab", "_type"))
            addr = _go_descriptor_addr(desc)
            if value is None or addr is None:
                continue
            go_types = self._codegen.kb.go_types
            itab = go_types.itab_at(addr)
            concrete = itab[1] if itab is not None else go_types.name_at(addr)
            if concrete is None:
                return None
            return value, concrete, cond.op == "CmpEQ"
        return None

    def _is_panic_only(self, node) -> bool:
        stmts = node.statements if isinstance(node, GoStatements) else [node]
        stmts = [st for st in stmts if st is not None]
        if len(stmts) != 1 or not isinstance(stmts[0], GoExpressionStatement):
            return False
        call = stmts[0].expr
        return (
            isinstance(call, GoFunctionCall)
            and call.callee_func is not None
            and normalize_go_func_name(call.callee_func.name) in self.PANIC_NAMES
        )

    def _fresh(self, base: str) -> str:
        name, n = base, 1
        while name in self._taken:
            n += 1
            name = f"{base}{n}"
        self._taken.add(name)
        return name

    def _try_assertion(self, stmt: GoIfElse):
        if len(stmt.condition_and_nodes) != 1:
            return None
        cond, node = stmt.condition_and_nodes[0]
        match = self._match_check(cond)
        if match is None:
            return None
        value, concrete, equal = match
        assertion = GoTypeAssertion(value, concrete, codegen=self._codegen)

        # panicking form: the failing branch only panics
        if not equal and self._is_panic_only(node):
            self._substitute(value, assertion)
            return (
                list(stmt.else_node.statements)
                if isinstance(stmt.else_node, GoStatements)
                else ([stmt.else_node] if stmt.else_node is not None else [])
            )
        if equal and stmt.else_node is not None and self._is_panic_only(stmt.else_node):
            self._substitute(value, assertion)
            return list(node.statements) if isinstance(node, GoStatements) else [node]

        # comma-ok form
        ok = GoFakeVariable(
            self._fresh("ok"), SimTypeBool().with_arch(self._codegen.project.arch), codegen=self._codegen
        )
        ty = assertion.type
        reads = self._count_reads(value)
        if reads and ty is not None:
            target = GoFakeVariable(self._fresh(_go_assertion_var_name(concrete)), ty, codegen=self._codegen)
            self._substitute(value, target)
            self._cfunc.extra_decls.append((target.name, ty))
        else:
            target = GoFakeVariable("_", SimTypeBottom(), codegen=self._codegen)
        self._cfunc.extra_decls.append((ok.name, ok.type))
        assign = GoMultiAssignment([target, ok], assertion, tags=stmt.tags, codegen=self._codegen)
        new_cond = ok if equal else GoUnaryOp("Not", ok, codegen=self._codegen)
        stmt.condition_and_nodes = [(new_cond, node)]
        return [assign, stmt]

    def _count_reads(self, value) -> int:
        counter = _DataReadSubstituter(value, None)
        counter.handle(self._cfunc.statements)
        return counter.count

    def _substitute(self, value, replacement) -> None:
        _DataReadSubstituter(value, replacement).handle(self._cfunc.statements)


def _go_interface_switch_cases(codegen, addr: int) -> list[str] | None:
    """The interface types of an ``internal/abi.InterfaceSwitch`` descriptor: ``Cache``, ``NCases``, ``Cases[]``."""
    project = codegen.project
    ws = project.arch.bytes
    try:
        ncases = project.loader.memory.unpack_word(addr + ws, size=ws)
        if not 0 < ncases <= 64:
            return None
        names = []
        for i in range(ncases):
            desc = project.loader.memory.unpack_word(addr + 2 * ws + i * ws, size=ws)
            name = codegen.kb.go_types.name_at(desc)
            if name is None:
                return None
            names.append(name)
        return names
    except Exception:  # pylint:disable=broad-exception-caught
        return None


def _go_var_named(expr) -> bool:
    return isinstance(expr, (GoVariable, GoFakeVariable))


def _go_stmt_list(node) -> list:
    """The statements of ``node`` with nested statement blocks flattened."""
    if node is None:
        return []
    if not isinstance(node, GoStatements):
        return [node]
    out = []
    for stmt in node.statements:
        out.extend(_go_stmt_list(stmt) if isinstance(stmt, GoStatements) else [stmt])
    return out


class _UseCounter(GoStructuredCodeWalker):
    """Counts references of variables by identity key."""

    def __init__(self):
        self.counts: Counter = Counter()

    @staticmethod
    def key(var):
        if isinstance(var, GoVariable):
            return ("v", _go_var_key(var))
        return ("f", getattr(var, "name", None))

    def handle_GoVariable(self, obj):
        self.counts[self.key(obj)] += 1
        return obj

    def handle_GoFakeVariable(self, obj):
        self.counts[self.key(obj)] += 1
        return obj


class _ItabMethodCalls(GoStructuredCodeWalker):
    """Calls through the method table of a known interface's itab become method calls on the bound value."""

    ITAB_FUN_OFFSET = 24

    def __init__(self, codegen, itab_vars, receiver, iface):
        self._codegen = codegen
        self._itab_keys = {_UseCounter.key(v) for v in itab_vars}
        self._receiver = receiver
        self._iface = iface
        self.count = 0

    def _slot(self, target):
        while isinstance(target, GoTypeCast):
            target = target.expr
        if (
            isinstance(target, GoVariableField)
            and _go_var_named(target.variable)
            and _UseCounter.key(target.variable) in self._itab_keys
        ):
            return target.field.offset
        if (
            isinstance(target, GoIndexedVariable)
            and isinstance(target.index, GoConstant)
            and _go_var_named(target.variable)
            and _UseCounter.key(target.variable) in self._itab_keys
        ):
            return target.index.value
        if isinstance(target, GoUnaryOp) and target.op == "Dereference":
            inner = target.operand
            while isinstance(inner, GoTypeCast):
                inner = inner.expr
            if (
                isinstance(inner, GoBinaryOp)
                and inner.op == "Add"
                and isinstance(inner.rhs, GoConstant)
                and _go_var_named(inner.lhs)
                and _UseCounter.key(inner.lhs) in self._itab_keys
            ):
                return inner.rhs.value
        return None

    def handle_GoFunctionCall(self, obj):
        obj = super().handle_GoFunctionCall(obj)
        if obj.callee_func is not None or isinstance(obj.callee_target, str):
            return obj
        offset = self._slot(obj.callee_target)
        if offset is None:
            return obj
        index, rem = divmod(offset - self.ITAB_FUN_OFFSET, self._codegen.project.arch.bytes)
        if rem or index < 0 or index >= len(self._iface.methods):
            return obj
        name, sig = self._iface.methods[index]
        self.count += 1
        # the first argument is always the receiver's data word
        return GoMethodCall(
            self._receiver, name, list(obj.args)[1:], signature=sig, tags=obj.tags, codegen=self._codegen
        )

    def handle_GoStructLiteral(self, obj):
        obj = super().handle_GoStructLiteral(obj)
        # a two-word result split into (call, dangling register): the call already carries the whole value
        fields = list(obj.fields.values())
        if (
            len(fields) == 2
            and isinstance(fields[0], GoMethodCall)
            and fields[0].signature is not None
            and _go_var_named(fields[1])
            and obj.type is not None
            and unpack_typeref(fields[0].type) is not None
            and getattr(unpack_typeref(fields[0].type), "size", None) == obj.type.size
        ):
            return fields[0]
        return obj


class _FieldRetyper(GoStructuredCodeWalker):
    """``x.field_N`` on a variable whose type is now known becomes the named field at that offset."""

    def __init__(self, codegen, var):
        self._codegen = codegen
        self._key = _UseCounter.key(var)
        self._type = unpack_typeref(var.type)

    def _struct(self):
        ty = self._type
        if isinstance(ty, SimTypePointer):
            ty = unpack_typeref(ty.pts_to)
        return ty if isinstance(ty, SimStruct) else None

    def _access_size(self, field) -> int | None:
        with contextlib.suppress(Exception):
            return field.struct_type.fields[field.field].size // self._codegen.project.arch.byte_width
        return None

    def _path(self, struct, offset: int, size: int | None):
        """The (field, ...) path from ``struct`` to the access at ``offset`` of ``size`` bytes, or None."""
        byte_width = self._codegen.project.arch.byte_width
        for name, off in struct.offsets.items():
            fty = unpack_typeref(struct.fields[name])
            fsize = (fty.size or 0) // byte_width if fty is not None else 0
            if fsize == 0 or not off <= offset < off + fsize:
                # zero-size fields (noCopy markers) share their offset with the real field
                continue
            if offset == off and (size is None or size == fsize or not isinstance(fty, SimStruct)):
                return [(struct, off, name)]
            if isinstance(fty, SimStruct):
                inner = self._path(fty, offset - off, size)
                if inner is not None:
                    return [(struct, off, name), *inner]
        return None

    def handle_GoVariableField(self, obj):
        obj = super().handle_GoVariableField(obj)
        struct = self._struct()
        base = obj.variable
        while isinstance(base, GoTypeCast):
            base = base.expr
        if (
            struct is not None
            and _go_var_named(base)
            and _UseCounter.key(base) == self._key
            and isinstance(obj.field.offset, int)
        ):
            path = self._path(struct, obj.field.offset, self._access_size(obj.field))
            if path is None or (len(path) == 1 and path[0][2] == obj.field.field):
                return obj
            expr = base
            for owner, off, name in path:
                expr = GoVariableField(
                    expr, GoStructField(owner, off, name, codegen=self._codegen), codegen=self._codegen
                )
            return expr
        return obj


def _go_call_name(call) -> str | None:
    """The callee's name for a direct call, whichever node carries it."""
    if getattr(call, "callee_func", None) is not None:
        return call.callee_func.name
    target = call.callee_target
    if isinstance(target, str):
        return target
    if isinstance(target, GoConstant):
        if isinstance(target.value, Function):
            return target.value.name
        if isinstance(target.value, str):
            return target.value
    return None


class _TypedCopies(GoStructuredCodeWalker):
    """``runtime.memmove(dst, src, sizeof(T))`` / ``runtime.typedmemmove(&type:T, dst, src)`` become ``*dst = *src``."""

    def __init__(self, codegen):
        self._codegen = codegen

    def handle_GoExpressionStatement(self, obj):
        obj = super().handle_GoExpressionStatement(obj)
        call = obj.expr
        if not isinstance(call, GoFunctionCall):
            return obj
        name = _go_call_name(call)
        if name is None:
            return obj
        name = normalize_go_func_name(name)
        dst = src = struct = None
        if name == "runtime.memmove" and len(call.args) == 3 and isinstance(call.args[2], GoConstant):
            dst, src, n = call.args
            struct = _go_named_struct_behind(dst.type) if dst.type is not None else None
            if struct is None or struct.size != n.value * self._codegen.project.arch.byte_width:
                return obj
        elif name == "runtime.typedmemmove" and len(call.args) == 3:
            dst, src = call.args[1], call.args[2]
            struct = _go_named_struct_behind(dst.type) if dst.type is not None else None
            if struct is None:
                return obj
        else:
            return obj
        arch = self._codegen.project.arch
        ptr_ty = SimTypePointer(struct).with_arch(arch)
        if src.type is None or _go_named_struct_behind(src.type) is not struct:
            src = GoTypeCast(src.type, ptr_ty, src, codegen=self._codegen)
        lhs = GoUnaryOp("Dereference", dst, codegen=self._codegen)
        rhs = GoUnaryOp("Dereference", src, codegen=self._codegen)
        return GoAssignment(lhs, rhs, tags=obj.tags, codegen=self._codegen)


class ITEHoisting:
    """
    ``x = c ? a : b`` renders as an immediately invoked closure in Go. Inside a statement list the value is hoisted
    into a temporary assigned by an ``if/else`` placed before the statement; ITEs in loop headers stay as they are.
    """

    def __init__(self, codegen, cfunc: GoFunction):
        self._codegen = codegen
        self._cfunc = cfunc
        self._taken = {v.name for v in cfunc.unified_local_vars if v.name} | {n for n, _ in cfunc.extra_decls}
        self._counter = 0

    def _fresh(self, ty) -> GoFakeVariable:
        while True:
            self._counter += 1
            name = f"t{self._counter}" if self._counter > 1 else "t"
            if name not in self._taken:
                self._taken.add(name)
                break
        self._cfunc.extra_decls.append((name, ty))
        return GoFakeVariable(name, ty, codegen=self._codegen)

    def run(self):
        root = self._cfunc.statements
        if not isinstance(root, GoStatements):
            root = GoStatements([root], addr=getattr(root, "addr", None), codegen=self._codegen)
            self._cfunc.statements = root
        self._cfunc.statements = self._handle_list(root)

    def _handle_list(self, stmts: GoStatements) -> GoStatements:
        out = []
        for stmt in stmts.statements:
            stmt = self._recurse(stmt)
            if isinstance(stmt, (GoAssignment, GoExpressionStatement, GoReturn, GoIfElse)):
                out.extend(self._hoist_from(stmt))
            else:
                out.append(stmt)
        stmts.statements = out
        return stmts

    def _recurse(self, stmt):
        # descend into nested statement lists (bodies), not into loop headers
        for attr in ("body", "else_node"):
            child = getattr(stmt, attr, None)
            if isinstance(child, GoStatements):
                setattr(stmt, attr, self._handle_list(child))
        if isinstance(stmt, GoIfElse):
            stmt.condition_and_nodes = [
                (cond, self._handle_list(node) if isinstance(node, GoStatements) else node)
                for cond, node in stmt.condition_and_nodes
            ]
        if isinstance(stmt, GoSwitchCase):
            stmt.cases = [
                (ids, self._handle_list(node) if isinstance(node, GoStatements) else node) for ids, node in stmt.cases
            ]
            if isinstance(stmt.default, GoStatements):
                stmt.default = self._handle_list(stmt.default)
        if isinstance(stmt, GoStatements):
            return self._handle_list(stmt)
        return stmt

    def _hoist_from(self, stmt) -> list:
        """Replace every ITE reachable from ``stmt`` (outside nested bodies) by a temporary; innermost first."""
        prelude: list = []
        codegen = self._codegen
        hoister = self

        class _Replace(GoStructuredCodeWalker):
            def handle_GoStatements(inner, obj):
                return obj  # bodies were handled by the recursion

            def handle_GoITE(inner, obj):
                obj = super().handle_GoITE(obj)  # inner ITEs first
                ty = obj.type if obj.type is not None else SimTypeLongLong()
                tmp = hoister._fresh(ty)
                then = GoStatements([GoAssignment(tmp, obj.iftrue, codegen=codegen)], codegen=codegen)
                other = GoStatements([GoAssignment(tmp, obj.iffalse, codegen=codegen)], codegen=codegen)
                prelude.append(GoIfElse([(obj.cond, then)], else_node=other, tags=obj.tags, codegen=codegen))
                return tmp

        if isinstance(stmt, GoIfElse):
            stmt.condition_and_nodes = [(_Replace().handle(cond), node) for cond, node in stmt.condition_and_nodes]
        else:
            stmt = _Replace().handle(stmt)
        return [*prelude, stmt]


class NamedFieldRetyping:
    """
    Field accesses built on register copies carry the copy's inferred struct; once copy cleanup has folded them onto
    an expression whose type is a named Go struct, name the fields after that struct. Variables defined by such a
    read take its type, so the fix propagates through chains of copies and indexing.
    """

    MAX_ROUNDS = 4

    def __init__(self, codegen, cfunc: GoFunction):
        self._codegen = codegen
        self._cfunc = cfunc

    def run(self):
        for _ in range(self.MAX_ROUNDS):
            fixer = _NamedFieldFixer(self._codegen)
            self._cfunc.statements = fixer.handle(self._cfunc.statements)
            retyped = self._retype_defined_variables()
            if not fixer.changed and not retyped:
                break

    def _retype_defined_variables(self) -> bool:
        """``v := expr`` where ``expr`` has a named type and ``v`` an inferred one: ``v`` takes the named type."""
        types: dict = {}

        class _Collect(GoStructuredCodeWalker):
            def handle_GoAssignment(inner, obj):
                obj = super().handle_GoAssignment(obj)
                if isinstance(obj.lhs, GoVariable) and _go_var_named(obj.lhs) and obj.rhs.type is not None:
                    rhs_ty = unpack_typeref(obj.rhs.type)
                    lhs_ty = unpack_typeref(obj.lhs.type) if obj.lhs.type is not None else None
                    if (
                        _go_mentions_named(rhs_ty)
                        and not _go_mentions_named(lhs_ty)
                        and (lhs_ty is None or lhs_ty.size == rhs_ty.size)
                    ):
                        key = _UseCounter.key(obj.lhs)
                        types.setdefault(key, obj.rhs.type)
                return obj

        _Collect().handle(self._cfunc.statements)
        # a variable assigned from several places keeps its own type unless every source agrees
        if not types:
            return False
        self._cfunc.statements = _Retyper(types).handle(self._cfunc.statements)
        return True


def _go_mentions_named(ty, depth: int = 0) -> bool:
    """Whether ``ty`` is, points to, or is a sequence of a named Go type (up to three levels deep)."""
    ty = unpack_typeref(ty)
    if ty is None or depth > 3:
        return False
    if _go_descriptor_name(ty):
        return True
    if isinstance(ty, SimTypePointer):
        return _go_mentions_named(ty.pts_to, depth + 1)
    if isinstance(ty, GoSimTypeSlice):
        return _go_mentions_named(ty.elem_type, depth + 1)
    if isinstance(ty, (SimTypeArray, SimTypeFixedSizeArray)):
        return _go_mentions_named(ty.elem_type, depth + 1)
    return False


def _go_anonymous_pointee(ty) -> bool:
    """Whether ``ty`` (through any chain of pointers) ends in a struct only type inference named (``struct_N``)."""
    ty = unpack_typeref(ty)
    if not isinstance(ty, SimTypePointer):
        return False
    pointee = unpack_typeref(ty.pts_to)
    while isinstance(pointee, SimTypePointer):
        pointee = unpack_typeref(pointee.pts_to)
    return isinstance(pointee, GoSimStruct) and _go_descriptor_name(pointee) is None


def _go_off_stride_step(obj) -> bool:
    """``p + c`` on an inferred pointer where ``c`` is not a multiple of the pointee size: integer math, not a step."""
    if not _go_anonymous_pointee(obj.type):
        return False
    const = obj.rhs if isinstance(obj.rhs, GoConstant) else obj.lhs if isinstance(obj.lhs, GoConstant) else None
    if const is None or not isinstance(const.value, int):
        return False
    pointee = unpack_typeref(unpack_typeref(obj.type).pts_to)
    size = (pointee.size or 0) // 8 if pointee is not None and pointee.size else 0
    return size == 0 or const.value % size != 0


def _go_descriptor_name(ty) -> str | None:
    """The qualified Go name of a struct-shaped type from the binary; type inference's ``struct_N`` does not count."""
    name = getattr(ty, "go_name", None) if isinstance(ty, GoSimStruct) else None
    return name if name and not name.startswith("struct_") else None


def _go_named_struct_behind(ty):
    """The named Go struct ``ty`` is, or points to (one level), else None."""
    ty = unpack_typeref(ty)
    if isinstance(ty, SimTypePointer):
        ty = unpack_typeref(ty.pts_to)
    return ty if _go_descriptor_name(ty) else None


class _NamedFieldFixer(GoStructuredCodeWalker):
    """``base.field_N`` where ``base`` has a named struct type becomes the named field path at that offset."""

    def __init__(self, codegen):
        self._codegen = codegen
        self.changed = False

    def handle_GoVariableField(self, obj):
        obj = super().handle_GoVariableField(obj)
        base = obj.variable
        while isinstance(base, GoTypeCast):
            base = base.expr
        struct = None
        if isinstance(base, GoIndexedVariable) and base.variable.type is not None:
            # the element type follows the (possibly retyped) variable, not the type recorded when it was built
            vt = unpack_typeref(base.variable.type)
            elem = vt.pts_to if isinstance(vt, SimTypePointer) else getattr(vt, "elem_type", None)
            struct = _go_named_struct_behind(elem) if elem is not None else None
        elif base.type is not None:
            struct = _go_named_struct_behind(base.type)
        if struct is None or not isinstance(obj.field.offset, int) or struct is obj.field.struct_type:
            return obj
        if getattr(obj.field.struct_type, "go_name", None) == struct.go_name:
            return obj
        helper = _FieldRetyper(self._codegen, base)
        helper._type = struct
        path = helper._path(struct, obj.field.offset, helper._access_size(obj.field))
        if path is None or (len(path) == 1 and path[0][2] == obj.field.field):
            return obj
        expr = base
        for owner, off, name in path:
            expr = GoVariableField(expr, GoStructField(owner, off, name, codegen=self._codegen), codegen=self._codegen)
        self.changed = True
        return expr


class TypeSwitchRecovery(GoStructuredCodeWalker):
    """
    An if/else-if chain comparing one interface value's type word against type descriptors becomes
    ``switch x := v.(type)``; a trailing ``runtime.interfaceSwitch`` dispatch adds the interface cases.
    """

    def __init__(self, codegen, cfunc: GoFunction):
        self._codegen = codegen
        self._cfunc = cfunc
        self._taken = {v.name for v in cfunc.unified_local_vars if v.name} | {n for n, _ in cfunc.extra_decls}
        self._dead_copies: set = set()
        self._scan = None

    def run(self):
        root = self._cfunc.statements
        if not isinstance(root, GoStatements):
            root = GoStatements([root], addr=getattr(root, "addr", None), codegen=self._codegen)
            self._cfunc.statements = root
        self._scan = _Scan(self._cfunc)
        self._cfunc.statements = self.handle(root)
        if self._dead_copies:
            self._cfunc.statements = _DeadCopyRemover(self._dead_copies, self._cfunc).handle(self._cfunc.statements)
            # declarations introduced for the dispatch results are dead with them
            counter = _UseCounter()
            counter.handle(self._cfunc.statements)
            self._cfunc.extra_decls = [
                (name, ty) for name, ty in self._cfunc.extra_decls if counter.counts[("f", name)] > 0
            ]

    def handle_GoStatements(self, obj):
        out = []
        for stmt in obj.statements:
            stmt = self.handle(stmt)
            if isinstance(stmt, GoSwitchCase):
                # the structurer's switch over descriptor addresses: name them, then treat it as the if-chain it is
                chain = self._descriptor_switch_to_chain(stmt)
                if chain is not None:
                    stmt = chain
            if isinstance(stmt, GoIfElse):
                replaced = self._try_switch(stmt)
                if replaced is not None:
                    out.append(replaced)
                    continue
            out.append(stmt)
        obj.statements = out
        return obj

    def handle_GoSwitchCase(self, obj):
        # a switch sitting directly under an if or a loop (not in a statement list)
        obj = super().handle_GoSwitchCase(obj)
        chain = self._descriptor_switch_to_chain(obj)
        if chain is None:
            return obj
        replaced = self._try_switch(chain)
        return replaced if replaced is not None else chain

    def _descriptor_reference(self, addr: int):
        """``&type:T`` / ``&go:itab.C,I`` for a descriptor address, as a reference to its global variable."""
        go_types = self._codegen.kb.go_types
        if go_types.itab_at(addr) is None and go_types.name_at(addr) is None:
            return None
        manager = self._codegen.kb.dec_variables["global"]
        for var in manager.get_global_variables(addr):
            if var.addr == addr:
                cvar = self._codegen._variable(var, None)
                return self._codegen._get_variable_reference(cvar)
        return None

    def _descriptor_switch_to_chain(self, stmt):
        ids = []
        for id_or_ids, _ in stmt.cases:
            values = id_or_ids if isinstance(id_or_ids, tuple) else (id_or_ids,)
            ids.append(values)
        if not ids or any(len(v) != 1 for v in ids):
            return None
        refs = [self._descriptor_reference(v[0]) for v in ids]
        if any(r is None for r in refs):
            return None

        def without_switch_break(body):
            stmts = _go_stmt_list(body)
            if stmts and isinstance(stmts[-1], GoBreak):
                stmts = stmts[:-1]
            return GoStatements(stmts, codegen=self._codegen)

        conditions = [
            (GoBinaryOp("CmpEQ", stmt.switch, ref, codegen=self._codegen), without_switch_break(body))
            for ref, (_, body) in zip(refs, stmt.cases)
        ]
        default = without_switch_break(stmt.default) if stmt.default is not None else None
        return GoIfElse(conditions, else_node=default, tags=stmt.tags, codegen=self._codegen)

    def _match_check(self, cond):
        """(holder, concrete type, interface type or None) for ``v.tab == descriptor``."""
        if not isinstance(cond, GoBinaryOp) or cond.op != "CmpEQ":
            return None
        for word, desc in ((cond.lhs, cond.rhs), (cond.rhs, cond.lhs)):
            addr = _go_descriptor_addr(desc)
            if addr is None:
                continue
            go_types = self._codegen.kb.go_types
            itab = go_types.itab_at(addr)
            value = _go_iface_word(word, ("tab", "_type"))
            iface_name = None
            if value is None and itab is not None:
                # the first word of an untyped holder compared against an itab: the holder is that interface
                holder = self._untyped_holder(word)
                if holder is None:
                    continue
                value, iface_name = holder, itab[0]
            if value is None:
                continue
            concrete = itab[1] if itab is not None else go_types.name_at(addr)
            return (value, concrete, iface_name) if concrete is not None else None
        return None

    def _word_of(self, expr, offset: int):
        """The holder whose word at ``offset`` ``expr`` reads, directly or through a single-assignment copy."""
        if _go_var_named(expr):
            # the assignment that reads a holder's word at this offset (a reused register may have others)
            defs = self._scan.assigns.get(_UseCounter.key(expr), []) if self._scan is not None else []
            sources = [
                d.rhs
                for d in defs
                if isinstance(d, GoAssignment) and isinstance(d.rhs, GoVariableField) and d.rhs.field.offset == offset
            ]
            if len(sources) == 1:
                expr = sources[0]
        if isinstance(expr, GoVariableField) and expr.field.offset == offset and _go_var_named(expr.variable):
            return expr.variable
        return None

    def _untyped_holder(self, word):
        """The variable whose word at offset 0 ``word`` reads (``h.field_0``), when ``h`` is not interface-typed."""
        holder = self._word_of(word, 0)
        if holder is not None and not isinstance(unpack_typeref(holder.type), GoSimTypeInterface):
            return holder
        return None

    def _data_aliases(self, holder) -> list:
        """Variables assigned once from the holder's second word (its data pointer), and copies of those."""
        ws = self._codegen.project.arch.bytes
        out = []
        assigns = self._scan.assigns.items() if self._scan is not None else ()
        for key, defs in assigns:
            if len(defs) == 1 and isinstance(defs[0], GoAssignment):
                rhs = defs[0].rhs
                if (
                    isinstance(rhs, GoVariableField)
                    and rhs.field.offset == ws
                    and _go_var_named(rhs.variable)
                    and _go_same_value(rhs.variable, holder)
                ):
                    out.append(key)
        # copies of copies
        changed = True
        while changed:
            changed = False
            for key, defs in assigns:
                if key in out or len(defs) != 1 or not isinstance(defs[0], GoAssignment):
                    continue
                rhs = defs[0].rhs
                while isinstance(rhs, GoTypeCast):
                    rhs = rhs.expr
                if _go_var_named(rhs) and _UseCounter.key(rhs) in out:
                    out.append(key)
                    changed = True
        return out

    def _fresh(self, base: str) -> str:
        name, n = base, 1
        while name in self._taken:
            n += 1
            name = f"{base}{n}"
        self._taken.add(name)
        return name

    def _try_switch(self, stmt: GoIfElse):
        checks = [self._match_check(cond) for cond, _ in stmt.condition_and_nodes]
        if not checks or any(c is None for c in checks):
            return None
        value = checks[0][0]
        if not all(_go_same_value(c[0], value) for c in checks[1:]):
            return None
        concretes = [c[1] for c in checks]
        if len(set(concretes)) != len(concretes):
            return None
        iface_names = {c[2] for c in checks}
        if len(iface_names) != 1:
            return None
        iface_name = next(iter(iface_names))
        holder_type = None
        if iface_name is not None:
            # the holder was untyped: it is a value of the interface every compared itab belongs to
            with contextlib.suppress(Exception):
                holder_type = self._codegen.kb.go_signatures.type(iface_name).with_arch(self._codegen.project.arch)
            if not isinstance(holder_type, GoSimTypeInterface):
                return None
        bound = self._fresh("x")
        cases = []
        reads = 0
        for (_, node), concrete in zip(stmt.condition_and_nodes, concretes):
            body = node if isinstance(node, GoStatements) else GoStatements([node], codegen=self._codegen)
            ty = None
            with contextlib.suppress(Exception):
                ty = self._codegen.kb.go_signatures.type(concrete).with_arch(self._codegen.project.arch)
            if ty is not None:
                target = GoFakeVariable(bound, ty, codegen=self._codegen)
                sub = _DataReadSubstituter(value, target, holder_type=holder_type)
                body = sub.handle(body)
                reads += sub.count
                if holder_type is not None:
                    for key in self._data_aliases(value):
                        n = _go_reads_in(body, key)
                        if n:
                            body = _VarSubstituter(key, target).handle(body)
                            reads += n
                    # the alias copies themselves are now x = x
                    body = GoStatements(
                        [
                            st
                            for st in _go_stmt_list(body)
                            if not (
                                isinstance(st, GoAssignment)
                                and _go_var_named(st.lhs)
                                and _go_var_named(st.rhs)
                                and _UseCounter.key(st.lhs) == _UseCounter.key(st.rhs)
                            )
                        ],
                        codegen=self._codegen,
                    )
                body = _FieldRetyper(self._codegen, target).handle(body)
            cases.append((concrete, body))
        if holder_type is not None:
            # every node of the holder now carries its interface type (renders as v.(type), v.tab, v.data)
            self._cfunc.statements = _Retyper({_UseCounter.key(value): holder_type}).handle(self._cfunc.statements)
            if isinstance(value, GoVariable):
                value.variable_type = holder_type
        default = stmt.else_node
        iface_cases, default, iface_reads = self._interface_cases(default, value, bound)
        cases += iface_cases
        reads += iface_reads
        if default is not None and not isinstance(default, GoStatements):
            default = GoStatements([default], codegen=self._codegen)
        if default is not None and not _go_stmt_list(default):
            default = None
        if reads == 0:
            self._taken.discard(bound)
            bound = None
        return GoTypeSwitch(value, bound, cases, default, tags=stmt.tags, codegen=self._codegen)

    def _interface_cases(self, node, value, bound: str):
        """``c, itab = runtime.interfaceSwitch(&sw, v.tab); if c == k {...}`` in ``node`` -> interface cases."""
        stmts = _go_stmt_list(node)
        if not stmts:
            return [], node, 0
        # simple copies before and after the dispatch are resolved by name
        aliases: dict = {}
        data_copies: set = set()
        dispatch = None
        for i, st in enumerate(stmts):
            if isinstance(st, GoAssignment) and _go_var_named(st.lhs) and _go_var_named(st.rhs):
                aliases[_UseCounter.key(st.lhs)] = st
                continue
            if isinstance(st, GoAssignment) and _go_var_named(st.lhs):
                holder = _go_iface_word(st.rhs, ("data",))
                if holder is not None and _go_same_value(holder, value):
                    data_copies.add(_UseCounter.key(st.lhs))
            if (
                isinstance(st, GoMultiAssignment)
                and len(st.lhs) == 2
                and isinstance(st.rhs, GoFunctionCall)
                and st.rhs.callee_func is not None
                and normalize_go_func_name(st.rhs.callee_func.name) == "runtime.interfaceSwitch"
                and len(st.rhs.args) == 2
            ):
                dispatch = (i, st)
                break
            if isinstance(st, GoAssignment):
                # the data-word copy the compiler makes before dispatching
                continue
            return [], node, 0
        if dispatch is None:
            return [], node, 0
        idx, st = dispatch
        addr = _go_descriptor_addr(st.rhs.args[0])
        if addr is None:
            return [], node, 0
        # &sw.Cache is the address of the descriptor itself
        names = _go_interface_switch_cases(self._codegen, addr)
        if not names:
            return [], node, 0
        case_var, itab_var = st.lhs
        # following statements: copies, then the case dispatch
        rest = stmts[idx + 1 :]
        case_keys = {_UseCounter.key(case_var)}
        itab_keys = {_UseCounter.key(itab_var)}
        copies = []
        while rest and isinstance(rest[0], GoAssignment) and _go_var_named(rest[0].lhs) and _go_var_named(rest[0].rhs):
            src_key = _UseCounter.key(rest[0].rhs)
            if src_key in case_keys:
                case_keys.add(_UseCounter.key(rest[0].lhs))
            elif src_key in itab_keys:
                itab_keys.add(_UseCounter.key(rest[0].lhs))
            copies.append(rest[0])
            rest = rest[1:]
        if not rest or not isinstance(rest[0], GoIfElse):
            return [], node, 0
        chain = rest[0]
        cases = []
        reads = 0
        for cond, body in chain.condition_and_nodes:
            k = self._case_index(cond, case_keys)
            if k is None or k >= len(names):
                return [], node, 0
            iface_name = names[k]
            iface = None
            with contextlib.suppress(Exception):
                iface = self._codegen.kb.go_signatures.type(iface_name).with_arch(self._codegen.project.arch)
            if not isinstance(iface, GoSimTypeInterface):
                return [], node, 0
            body = body if isinstance(body, GoStatements) else GoStatements([body], codegen=self._codegen)
            receiver = GoFakeVariable(bound, iface, codegen=self._codegen)
            calls = _ItabMethodCalls(
                self._codegen, [GoFakeVariable(k_, iface, codegen=self._codegen) for k_ in ()], receiver, iface
            )
            calls._itab_keys = set(itab_keys)
            body = calls.handle(body)
            reads += calls.count
            sub = _DataReadSubstituter(value, receiver)
            body = sub.handle(body)
            reads += sub.count
            cases.append((iface_name, body))
        # everything the dispatch introduced is now dead: the copies, the dispatch and its results
        self._dead_copies |= set(aliases) | case_keys | itab_keys | data_copies
        leftover = stmts[:idx]
        leftover = [
            x for x in leftover if not (isinstance(x, GoAssignment) and _UseCounter.key(x.lhs) in self._dead_copies)
        ]
        default_stmts = leftover + _go_stmt_list(chain.else_node) + rest[1:]
        default = GoStatements(default_stmts, codegen=self._codegen) if default_stmts else None
        return cases, default, reads

    @staticmethod
    def _case_index(cond, case_keys) -> int | None:
        if not (isinstance(cond, GoBinaryOp) and cond.op == "CmpEQ"):
            return None
        for a, b in ((cond.lhs, cond.rhs), (cond.rhs, cond.lhs)):
            if _go_var_named(a) and _UseCounter.key(a) in case_keys and isinstance(b, GoConstant):
                return b.value
        return None


def _go_call_named(stmt, name):
    """The call expression of ``stmt`` when it is a plain call statement to ``name`` (or one of ``name``), else None."""
    names = {name} if isinstance(name, str) else set(name)
    if not isinstance(stmt, GoExpressionStatement):
        return None
    call = stmt.expr
    if not isinstance(call, GoFunctionCall):
        return None
    if call.callee_func is not None and normalize_go_func_name(call.callee_func.name) in names:
        return call
    if isinstance(call.callee_target, str) and call.callee_target in names:
        return call
    return None


# go1.22 hash maps and go1.24+ swiss maps name the iterator runtime differently
_MAP_ITER_INIT = frozenset({"runtime.mapiterinit", "runtime.mapIterStart"})
_MAP_ITER_NEXT = frozenset({"runtime.mapiternext", "runtime.mapIterNext"})


def _go_referenced_var(expr):
    """The variable ``expr`` takes the address of, or None."""
    if isinstance(expr, GoUnaryOp) and expr.op == "Reference" and isinstance(expr.operand, GoVariable):
        return expr.operand
    return None


def _go_is_true_const(expr) -> bool:
    return isinstance(expr, GoConstant) and isinstance(expr.value, int) and expr.value != 0


def _go_break_only(node) -> bool:
    stmts = _go_stmt_list(node)
    return len(stmts) == 1 and isinstance(stmts[0], GoBreak)


class _PointerReadSubstituter(GoStructuredCodeWalker):
    """Replaces whole-value reads through a set of pointer expressions (``*p``, ``p[0]``) with a variable."""

    def __init__(self, is_pointer, replacement):
        self._is_pointer = is_pointer
        self._replacement = replacement
        self.count = 0
        self.partial = 0

    def _strip(self, expr):
        while isinstance(expr, GoTypeCast):
            expr = expr.expr
        return expr

    def handle_GoUnaryOp(self, obj):
        if obj.op == "Dereference" and self._is_pointer(self._strip(obj.operand)):
            self.count += 1
            return obj if self._replacement is None else self._replacement
        return super().handle_GoUnaryOp(obj)

    def handle_GoIndexedVariable(self, obj):
        if self._is_pointer(self._strip(obj.variable)) and isinstance(obj.index, GoConstant):
            if obj.index.value == 0:
                self.count += 1
                return obj if self._replacement is None else self._replacement
            self.partial += 1
        return super().handle_GoIndexedVariable(obj)


class MapRangeRecovery(GoStructuredCodeWalker):
    """
    ``runtime.mapiterinit(T, m, &it)`` followed by a loop on ``it.key != nil`` that ends with
    ``runtime.mapiternext(&it)`` becomes ``for k, v = range m``; reads through the iterator's key and element
    pointers become ``k`` and ``v``.
    """

    def __init__(self, codegen, cfunc: GoFunction):
        self._codegen = codegen
        self._cfunc = cfunc
        self._taken = {v.name for v in cfunc.unified_local_vars if v.name} | {n for n, _ in cfunc.extra_decls}
        self._taken |= {arg.name for arg in getattr(cfunc, "arg_list", []) if getattr(arg, "name", None)}

    def run(self):
        root = self._cfunc.statements
        if not isinstance(root, GoStatements):
            root = GoStatements([root], addr=getattr(root, "addr", None), codegen=self._codegen)
        self._cfunc.statements = self.handle(root)

    def _fresh(self, base: str) -> str:
        name, n = base, 1
        while name in self._taken:
            n += 1
            name = f"{base}{n}"
        self._taken.add(name)
        return name

    def handle_GoStatements(self, obj):
        # nested blocks carry no scope of their own: flatten them so the loop follows its initializer
        stmts = _go_stmt_list(GoStatements([self.handle(st) for st in obj.statements], codegen=self._codegen))
        out = []
        i = 0
        while i < len(stmts):
            stmt = stmts[i]
            init = _go_call_named(stmt, _MAP_ITER_INIT)
            if init is not None and len(init.args) == 3:
                # plain assignments may sit between the iterator setup and the loop
                j = i + 1
                while j < len(stmts) and isinstance(stmts[j], GoAssignment):
                    j += 1
                if j < len(stmts):
                    replaced = self._try_range(init, stmts[j], out)
                    if replaced is not None:
                        out.extend(stmts[i + 1 : j])
                        out.extend(replaced)
                        i = j + 1
                        continue
            out.append(stmt)
            i += 1
        obj.statements = out
        return obj

    def _try_range(self, init: GoFunctionCall, loop, preceding: list):
        it = _go_referenced_var(init.args[2])
        collection = init.args[1]
        if it is None or not isinstance(it.variable, SimStackVariable):
            return None
        ws = self._codegen.project.arch.bytes
        it_offset = it.variable.offset

        def key_ptr(expr) -> bool:
            if isinstance(expr, GoVariable) and _same_variable(expr, it):
                return True
            return isinstance(expr, GoVariableField) and expr.field.field == "key" and _go_same_value(expr.variable, it)

        def elem_ptr(expr) -> bool:
            if isinstance(expr, GoVariableField) and expr.field.field == "elem" and _go_same_value(expr.variable, it):
                return True
            return (
                isinstance(expr, GoVariable)
                and isinstance(expr.variable, SimStackVariable)
                and expr.variable.offset == it_offset + ws
                and expr.variable.size == ws
            )

        hoisted = []
        body_stmts = None
        tail = []
        aliases = []  # p = (*T)(it) statements naming the key pointer
        if isinstance(loop, GoForLoop) and loop.condition is not None:
            if not self._is_end_check(loop.condition, key_ptr, negated=True):
                return None
            body_stmts = _go_stmt_list(loop.body)
            if loop.initializer is not None:
                hoisted.append(loop.initializer)
            if loop.iterator is not None:
                tail.append(loop.iterator)
        elif isinstance(loop, GoWhileLoop):
            body_stmts = _go_stmt_list(loop.body)
            if _go_is_true_const(loop.condition):
                # for { p = (*T)(it); if p == nil { break } ... }
                while body_stmts and isinstance(body_stmts[0], GoAssignment) and _go_var_named(body_stmts[0].lhs):
                    rhs = body_stmts[0].rhs
                    while isinstance(rhs, GoTypeCast):
                        rhs = rhs.expr
                    if not key_ptr(rhs):
                        break
                    aliases.append(body_stmts[0])
                    body_stmts = body_stmts[1:]
                if not body_stmts or not isinstance(body_stmts[0], GoIfElse):
                    return None
                check = body_stmts[0]
                if len(check.condition_and_nodes) != 1 or check.else_node is not None:
                    return None
                cond, node = check.condition_and_nodes[0]
                alias_keys = {_UseCounter.key(a.lhs) for a in aliases}

                def key_ptr_or_alias(expr, _base=key_ptr):
                    return _base(expr) or (_go_var_named(expr) and _UseCounter.key(expr) in alias_keys)

                if not (self._is_end_check(cond, key_ptr_or_alias, negated=False) and _go_break_only(node)):
                    return None
                key_ptr = key_ptr_or_alias
                body_stmts = body_stmts[1:]
            elif not self._is_end_check(loop.condition, key_ptr, negated=True):
                return None
        else:
            return None
        if not body_stmts or _go_call_named(body_stmts[-1], _MAP_ITER_NEXT) is None:
            return None
        nxt = _go_call_named(body_stmts[-1], _MAP_ITER_NEXT)
        if len(nxt.args) != 1 or _go_referenced_var(nxt.args[0]) is None:
            return None
        if not _same_variable(_go_referenced_var(nxt.args[0]), it):
            return None
        body_stmts = body_stmts[:-1] + tail

        # the map's key and element types
        # the map type: from the value when it is typed, else from the descriptor passed to mapiterinit
        map_type = unpack_typeref(collection.type)
        if not isinstance(map_type, GoSimTypeMap):
            map_type = None
            desc = _go_descriptor_addr(init.args[0])
            if desc is not None:
                with contextlib.suppress(Exception):
                    map_type = self._codegen.kb.go_signatures.type(go_type_name_at(self._codegen.project, desc))
        key_type = elem_type = None
        if isinstance(map_type, GoSimTypeMap):
            key_type, elem_type = map_type.key_type, map_type.elem_type
        body = GoStatements(body_stmts, codegen=self._codegen)
        key_var = value_var = None
        if key_type is not None:
            # only whole-value reads can be renamed; a key read piecewise keeps its pointer
            probe = _PointerReadSubstituter(key_ptr, None)
            probe.handle(body)
            if probe.count and not probe.partial:
                key_var = GoFakeVariable(
                    self._fresh("k"), key_type.with_arch(self._codegen.project.arch), codegen=self._codegen
                )
                body = _PointerReadSubstituter(key_ptr, key_var).handle(body)
        if key_var is None and aliases:
            body = GoStatements([*aliases, *body.statements], codegen=self._codegen)
        if elem_type is not None:
            probe = _PointerReadSubstituter(elem_ptr, None)
            probe.handle(body)
            if probe.count and not probe.partial:
                value_var = GoFakeVariable(
                    self._fresh("v"), elem_type.with_arch(self._codegen.project.arch), codegen=self._codegen
                )
                body = _PointerReadSubstituter(elem_ptr, value_var).handle(body)
        # zeroing of the iterator before the loop is part of the idiom: a duffzero call, or zero stores that cover
        # the iterator's stack region
        it_type = unpack_typeref(it.type)
        it_size = it_type.size // self._codegen.project.arch.byte_width if it_type is not None and it_type.size else ws
        while preceding:
            last = preceding[-1]
            if _go_call_named(last, "runtime.duffzero") is not None:
                preceding.pop()
                continue
            if (
                isinstance(last, GoAssignment)
                and isinstance(last.lhs, GoVariable)
                and isinstance(last.lhs.variable, SimStackVariable)
                and it_offset <= last.lhs.variable.offset < it_offset + it_size
                and isinstance(last.rhs, GoConstant)
                and last.rhs.value == 0
            ):
                preceding.pop()
                continue
            break
        for var in (key_var, value_var):
            if var is not None:
                self._cfunc.extra_decls.append((var.name, var.type))
        return [*hoisted, GoRangeLoop(key_var, value_var, collection, body, tags=loop.tags, codegen=self._codegen)]

    @staticmethod
    def _is_end_check(cond, key_ptr, negated: bool) -> bool:
        """``it.key != nil`` (negated) or ``it.key == nil``."""
        if not isinstance(cond, GoBinaryOp):
            return False
        want = "CmpNE" if negated else "CmpEQ"
        if cond.op != want:
            return False
        for a, b in ((cond.lhs, cond.rhs), (cond.rhs, cond.lhs)):
            x = a
            while isinstance(x, GoTypeCast):
                x = x.expr
            if key_ptr(x) and isinstance(b, GoConstant) and b.value == 0:
                return True
        return False


class ChannelRangeRecovery(GoStructuredCodeWalker):
    """
    ``for { S; v, ok = <-ch; if !ok { break }; R }`` becomes ``S; for v = range ch { R; S }``: the statements ahead
    of the receive also run on the final, failed receive, so they move before the loop and to the end of the body.
    """

    def __init__(self, codegen, cfunc: GoFunction):
        self._codegen = codegen
        self._cfunc = cfunc
        self._dropped: set = set()

    def run(self):
        root = self._cfunc.statements
        if not isinstance(root, GoStatements):
            root = GoStatements([root], addr=getattr(root, "addr", None), codegen=self._codegen)
        self._cfunc.statements = self.handle(root)
        if self._dropped:
            counter = _UseCounter()
            counter.handle(self._cfunc.statements)
            self._cfunc.extra_decls = [
                (name, ty) for name, ty in self._cfunc.extra_decls if counter.counts[("f", name)] > 0
            ]

    def handle_GoStatements(self, obj):
        out = []
        for stmt in obj.statements:
            stmt = self.handle(stmt)
            if isinstance(stmt, GoWhileLoop):
                replaced = self._try_range(stmt)
                if replaced is not None:
                    out.extend(replaced)
                    continue
            out.append(stmt)
        obj.statements = out
        return obj

    def _try_range(self, loop: GoWhileLoop):
        if not _go_is_true_const(loop.condition):
            return None
        stmts = _go_stmt_list(loop.body)
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, GoAssignment) and _go_var_named(stmt.lhs) and _go_pure(stmt.rhs):
                continue
            if (
                isinstance(stmt, GoMultiAssignment)
                and len(stmt.lhs) == 2
                and isinstance(stmt.rhs, GoFunctionCall)
                and call_tag(stmt.rhs, "go_render") == "recv"
                and len(stmt.rhs.args) == 1
                and i + 1 < len(stmts)
            ):
                value, ok = stmt.lhs
                check = stmts[i + 1]
                if not (
                    isinstance(check, GoIfElse) and len(check.condition_and_nodes) == 1 and check.else_node is None
                ):
                    return None
                cond, node = check.condition_and_nodes[0]
                if not (self._is_not_ok(cond, ok) and _go_break_only(node)):
                    return None
                leading = stmts[:i]
                # the leading copies run before every receive: once ahead of the loop and after each body
                repeated = [copy.copy(st) for st in leading] if leading else []
                body = GoStatements(stmts[i + 2 :] + repeated, codegen=self._codegen)
                self._dropped.add(_UseCounter.key(ok))
                return [
                    *leading,
                    GoRangeLoop(value, None, stmt.rhs.args[0], body, tags=loop.tags, codegen=self._codegen),
                ]
            return None
        return None

    @staticmethod
    def _is_not_ok(cond, ok) -> bool:
        if isinstance(cond, GoUnaryOp) and cond.op == "Not" and _go_var_named(cond.operand):
            return _UseCounter.key(cond.operand) == _UseCounter.key(ok)
        if isinstance(cond, GoBinaryOp) and cond.op == "CmpEQ":
            for a, b in ((cond.lhs, cond.rhs), (cond.rhs, cond.lhs)):
                if _go_var_named(a) and _UseCounter.key(a) == _UseCounter.key(ok) and isinstance(b, GoConstant):
                    return b.value == 0
        return False


class _VarSubstituter(GoStructuredCodeWalker):
    """Replaces every occurrence of a variable (by key) with an expression."""

    def __init__(self, key, replacement):
        self._key = key
        self._replacement = replacement

    def handle_GoVariable(self, obj):
        return self._replacement if _UseCounter.key(obj) == self._key else obj

    def handle_GoFakeVariable(self, obj):
        return self._replacement if _UseCounter.key(obj) == self._key else obj


class _StmtRemover(GoStructuredCodeWalker):
    """Removes the given statement objects wherever they sit (statement lists, and loop headers unless lists_only)."""

    def __init__(self, doomed, lists_only: bool = False):
        self._doomed = {id(st) for st in doomed}
        self._lists_only = lists_only

    def handle_GoStatements(self, obj):
        obj.statements = [self.handle(st) for st in obj.statements if id(st) not in self._doomed]
        return obj

    def handle_GoForLoop(self, obj):
        if not self._lists_only:
            if obj.initializer is not None and id(obj.initializer) in self._doomed:
                obj.initializer = None
            if obj.iterator is not None and id(obj.iterator) in self._doomed:
                obj.iterator = None
        return super().handle_GoForLoop(obj)


class _Scan:
    """Assignments and reads of locals across a function, with the scope each statement lives in."""

    def __init__(self, cfunc):
        self.assigns: dict = defaultdict(list)  # key -> [stmt]
        self.reads: Counter = Counter()  # key -> reads (assignment targets excluded)
        self.addressed: set = set()  # keys whose address is taken
        self.scope_of: dict = {}  # id(stmt) -> (scope id, ordinal)
        self.scopes: dict = {}  # scope id -> flattened statement list
        self._next = 0
        self._visit_scope(cfunc.statements)

    @staticmethod
    def key(var):
        return _UseCounter.key(var)

    @staticmethod
    def is_local(var) -> bool:
        if isinstance(var, GoFakeVariable):
            return var.name != "_"
        if isinstance(var, GoVariable):
            v = var.variable
            return not (isinstance(v, SimMemoryVariable) and not isinstance(v, SimStackVariable))
        return False

    @staticmethod
    def targets(stmt) -> list:
        if isinstance(stmt, GoAssignment):
            return [stmt.lhs] if isinstance(stmt.lhs, (GoVariable, GoFakeVariable)) else []
        if isinstance(stmt, GoMultiAssignment):
            return [t for t in stmt.lhs if isinstance(t, (GoVariable, GoFakeVariable))]
        if isinstance(stmt, GoRangeLoop):
            return [v for v in (stmt.index, stmt.value) if isinstance(v, (GoVariable, GoFakeVariable))]
        return []

    def _visit_scope(self, node):
        scope = self._next
        self._next += 1
        stmts = _go_stmt_list(node)
        self.scopes[scope] = stmts
        for ordinal, stmt in enumerate(stmts):
            self.scope_of[id(stmt)] = (scope, ordinal)
            self._visit_stmt(stmt)

    def _visit_stmt(self, stmt):
        for t in self.targets(stmt):
            if self.is_local(t):
                self.assigns[self.key(t)].append(stmt)
        if isinstance(stmt, GoAssignment):
            if not isinstance(stmt.lhs, (GoVariable, GoFakeVariable)):
                self._visit_expr(stmt.lhs)
            self._visit_expr(stmt.rhs)
        elif isinstance(stmt, GoMultiAssignment):
            for t in stmt.lhs:
                if not isinstance(t, (GoVariable, GoFakeVariable)):
                    self._visit_expr(t)
            self._visit_expr(stmt.rhs)
        elif isinstance(stmt, GoIfElse):
            for cond, node in stmt.condition_and_nodes:
                self._visit_expr(cond)
                self._visit_scope(node)
            if stmt.else_node is not None:
                self._visit_scope(stmt.else_node)
        elif isinstance(stmt, (GoWhileLoop, GoDoWhileLoop)):
            self._visit_expr(stmt.condition)
            self._visit_scope(stmt.body)
        elif isinstance(stmt, GoForLoop):
            for part in (stmt.initializer, stmt.iterator):
                if part is not None:
                    self.scope_of[id(part)] = self.scope_of[id(stmt)]
                    self._visit_stmt(part)
            if stmt.condition is not None:
                self._visit_expr(stmt.condition)
            self._visit_scope(stmt.body)
        elif isinstance(stmt, GoRangeLoop):
            self._visit_expr(stmt.collection)
            self._visit_scope(stmt.body)
        elif isinstance(stmt, GoTypeSwitch):
            self._visit_expr(stmt.value)
            for _, body in stmt.cases:
                self._visit_scope(body)
            if stmt.default is not None:
                self._visit_scope(stmt.default)
        elif isinstance(stmt, GoStatements):
            self._visit_scope(stmt)
        else:
            self._visit_expr(stmt)

    def _visit_expr(self, node):
        if isinstance(node, (GoVariable, GoFakeVariable)):
            self.reads[self.key(node)] += 1
            return
        if (
            isinstance(node, GoUnaryOp)
            and node.op == "Reference"
            and isinstance(node.operand, (GoVariable, GoFakeVariable))
        ):
            self.addressed.add(self.key(node.operand))
        if isinstance(node, GoStatements):
            self._visit_scope(node)
            return
        for name in _go_node_attr_names(node):
            child = getattr(node, name, None)
            if isinstance(child, GoConstruct):
                self._visit_expr(child)
            elif isinstance(child, (list, tuple)):
                for item in child:
                    if isinstance(item, GoConstruct):
                        self._visit_expr(item)
                    elif isinstance(item, tuple):
                        for x in item:
                            if isinstance(x, GoConstruct):
                                self._visit_expr(x)
            elif isinstance(child, dict):
                for x in child.values():
                    if isinstance(x, GoConstruct):
                        self._visit_expr(x)


def _go_reads_in(node, key) -> int:
    counter = _UseCounter()
    counter.handle(node)
    return counter.counts[key]


def _go_assigns_in(node, key) -> bool:
    """Whether any statement inside ``node`` assigns the variable."""
    for stmt in _go_stmt_list(node) if isinstance(node, GoStatements) else [node]:
        if any(_UseCounter.key(t) == key for t in _Scan.targets(stmt)):
            return True
        if isinstance(stmt, GoIfElse):
            if any(_go_assigns_in(n, key) for _, n in stmt.condition_and_nodes) or (
                stmt.else_node is not None and _go_assigns_in(stmt.else_node, key)
            ):
                return True
        elif isinstance(stmt, (GoWhileLoop, GoDoWhileLoop, GoRangeLoop)):
            if _go_assigns_in(stmt.body, key):
                return True
        elif isinstance(stmt, GoForLoop):
            if any(part is not None and _go_assigns_in(part, key) for part in (stmt.initializer, stmt.iterator)):
                return True
            if _go_assigns_in(stmt.body, key):
                return True
        elif isinstance(stmt, GoTypeSwitch):
            if any(_go_assigns_in(b, key) for _, b in stmt.cases) or (
                stmt.default is not None and _go_assigns_in(stmt.default, key)
            ):
                return True
        elif isinstance(stmt, GoStatements) and _go_assigns_in(stmt, key):
            return True
    return False


def _go_pure(expr) -> bool:
    """Side-effect-free expressions: no calls."""
    if isinstance(expr, (GoFunctionCall, GoMethodCall)):
        return False
    for name in _go_node_attr_names(expr):
        child = getattr(expr, name, None)
        if isinstance(child, GoConstruct) and not _go_pure(child):
            return False
        if isinstance(child, (list, tuple)) and any(isinstance(x, GoConstruct) and not _go_pure(x) for x in child):
            return False
    return True


class _SplitValueCollapser(GoStructuredCodeWalker):
    """
    ``T{a, r}`` assembling a two-word value from a variable holding a call's whole result and a dangling register
    is the variable itself.
    """

    def __init__(self, scan: _Scan):
        self._scan = scan
        self.retyped: dict = {}  # variable key -> the call's result type

    def handle_GoStructLiteral(self, obj):
        obj = super().handle_GoStructLiteral(obj)
        fields = list(obj.fields.values())
        if len(fields) != 2 or obj.type is None or not _go_var_named(fields[0]) or not _go_var_named(fields[1]):
            return obj
        first, second = fields
        if self._scan.assigns.get(_UseCounter.key(second)):
            return obj
        defs = self._scan.assigns.get(_UseCounter.key(first), [])
        if len(defs) != 1 or not isinstance(defs[0], GoAssignment):
            return obj
        rhs = defs[0].rhs
        if not isinstance(rhs, (GoFunctionCall, GoMethodCall)):
            return obj
        result = unpack_typeref(rhs.type)
        if result is None or getattr(result, "size", None) != obj.type.size:
            return obj
        with contextlib.suppress(Exception):
            if go_type_str(result) != go_type_str(obj.type):
                return obj
        self.retyped[_UseCounter.key(first)] = result
        return first


class _Retyper(GoStructuredCodeWalker):
    """Gives every node of a variable the type its defining call returns."""

    def __init__(self, types: dict):
        self._types = types

    def handle_GoVariable(self, obj):
        ty = self._types.get(_UseCounter.key(obj))
        if ty is not None:
            obj.variable_type = ty
        return obj


def _go_call_position_ok(stmt, key) -> bool:
    """
    Whether the read of ``key`` in ``stmt`` comes before every call the statement makes, in evaluation order
    (left to right), so a call folded into that read still runs first. Nested blocks are not entered: a read
    inside one is treated as unsafe.
    """
    state = {"seen_call": False, "ok": None}

    def visit(node):
        if state["ok"] is not None:
            return
        if isinstance(node, (GoVariable, GoFakeVariable)):
            if _UseCounter.key(node) == key:
                state["ok"] = not state["seen_call"]
            return
        if isinstance(node, GoStatements):
            state["ok"] = False
            return
        is_call = isinstance(node, (GoFunctionCall, GoMethodCall))
        if isinstance(node, GoMethodCall):
            visit(node.receiver)
            for a in node.args:
                visit(a)
        elif isinstance(node, GoFunctionCall):
            if not isinstance(node.callee_target, str):
                visit(node.callee_target)
            for a in node.args:
                visit(a)
        elif isinstance(node, GoAssignment):
            visit(node.rhs)
            if not isinstance(node.lhs, (GoVariable, GoFakeVariable)):
                visit(node.lhs)
        elif isinstance(node, GoMultiAssignment):
            visit(node.rhs)
        elif isinstance(node, GoIfElse):
            for cond, _ in node.condition_and_nodes[:1]:
                visit(cond)
            if state["ok"] is None:
                state["ok"] = False
        elif isinstance(node, (GoWhileLoop, GoForLoop, GoRangeLoop, GoDoWhileLoop, GoTypeSwitch, GoSelect)):
            state["ok"] = False
        else:
            for name in _go_node_attr_names(node):
                child = getattr(node, name, None)
                if isinstance(child, GoConstruct):
                    visit(child)
                elif isinstance(child, (list, tuple)):
                    for item in child:
                        if isinstance(item, GoConstruct):
                            visit(item)
                elif isinstance(child, dict):
                    for item in child.values():
                        if isinstance(item, GoConstruct):
                            visit(item)
        if is_call and state["ok"] is None:
            state["seen_call"] = True

    visit(stmt)
    return bool(state["ok"])


class CopyCleanup:
    """
    Remove the register shuffling that phi elimination and spilling leave in structured code:

    - a value spilled before a loop and reloaded inside it (``x = y`` … ``y = x``) never changes, so the spill and the
      reloads go and ``x`` reads as ``y``;
    - ``x = y`` whose every read follows in the same block, with ``y`` unchanged in between, is folded into the reads;
    - single-assignment locals nobody reads are dropped.
    A loop whose iterator statement went away takes the body's final update of a condition variable as its iterator.
    """

    MAX_ROUNDS = 8

    def __init__(self, codegen, cfunc: GoFunction):
        self._codegen = codegen
        self._cfunc = cfunc

    def run(self):
        root = self._cfunc.statements
        if not isinstance(root, GoStatements):
            root = GoStatements([root], addr=getattr(root, "addr", None), codegen=self._codegen)
            self._cfunc.statements = root
        for _ in range(self.MAX_ROUNDS):
            scan = _Scan(self._cfunc)
            if not (self._reload_pairs(scan) or self._mirrors(scan) or self._propagate(scan) or self._dead(scan)):
                break
        collapser = _SplitValueCollapser(_Scan(self._cfunc))
        self._cfunc.statements = collapser.handle(self._cfunc.statements)
        if collapser.retyped:
            self._cfunc.statements = _Retyper(collapser.retyped).handle(self._cfunc.statements)
        self._fuse_split_stores(_Scan(self._cfunc))
        for _ in range(self.MAX_ROUNDS):
            if not self._fold_calls(_Scan(self._cfunc)):
                break
        self._recover_iterators(self._cfunc.statements)
        self._drop_self_assignments()

    def _drop_self_assignments(self):
        """``x = x`` left behind by copy folding says nothing."""
        dead = []

        class _Find(GoStructuredCodeWalker):
            def handle_GoAssignment(inner, obj):
                if (
                    not obj.declares
                    and isinstance(obj.lhs, GoVariable)
                    and isinstance(obj.rhs, GoVariable)
                    and _go_var_named(obj.lhs)
                    and _UseCounter.key(obj.lhs) == _UseCounter.key(obj.rhs)
                ):
                    dead.append(obj)
                return obj

        _Find().handle(self._cfunc.statements)
        if dead:
            self._cfunc.statements = _StmtRemover(dead).handle(self._cfunc.statements)

    def _params(self):
        return {_UseCounter.key(a) for a in self._cfunc.arg_list}

    def _remove(self, stmts):
        self._cfunc.statements = _StmtRemover(stmts).handle(self._cfunc.statements)

    def _substitute(self, key, replacement):
        self._cfunc.statements = _VarSubstituter(key, replacement).handle(self._cfunc.statements)

    # -- rule 1: spill/reload pairs
    def _reload_pairs(self, scan: _Scan) -> bool:
        params = self._params()
        for key, stmts in list(scan.assigns.items()):
            if len(stmts) != 1 or key in scan.addressed:
                continue
            spill = stmts[0]
            if not (isinstance(spill, GoAssignment) and _Scan.is_local(spill.lhs)):
                continue
            rhs = spill.rhs
            if not _go_pure(rhs):
                continue
            # the original: the variable copied, or the variable defined from the same expression (a spilled twin)
            if isinstance(rhs, (GoVariable, GoFakeVariable)):
                if _UseCounter.key(rhs) == key:
                    continue
                candidates = [rhs]
            else:
                candidates = self._twins(scan, key, rhs)
            for origin in candidates:
                ykey = _UseCounter.key(origin)
                if ykey in scan.addressed:
                    continue
                reloads = []
                others = []
                for st in scan.assigns.get(ykey, []):
                    if (
                        isinstance(st, GoAssignment)
                        and isinstance(st.rhs, (GoVariable, GoFakeVariable))
                        and _UseCounter.key(st.rhs) == key
                    ):
                        reloads.append(st)
                    else:
                        others.append(st)
                if not reloads:
                    continue
                if ykey in params:
                    if others:
                        continue
                elif isinstance(rhs, (GoVariable, GoFakeVariable)):
                    # a local original: exactly one definition, before the spill in the same block
                    if len(others) != 1 or not _Scan.is_local(origin):
                        continue
                    d = scan.scope_of.get(id(others[0]))
                    c = scan.scope_of.get(id(spill))
                    if d is None or c is None or d[0] != c[0] or d[1] >= c[1]:
                        continue
                elif len(others) != 1:
                    continue
                self._remove([spill, *reloads])
                self._substitute(key, origin)
                return True
        return False

    def _twins(self, scan: _Scan, key, expr) -> list:
        """
        Locals defined once from the very expression ``x`` is defined from, when that expression only reads variables
        nothing assigns (``v7 := len(s)`` next to ``for i := len(s); ...``).
        """
        reads = _UseCounter()
        reads.handle(expr)
        if any(scan.assigns.get(k) for k in reads.counts):
            return []
        text = _go_text(expr)
        twins = []
        for other, stmts in scan.assigns.items():
            if other == key:
                continue
            defs = [
                st
                for st in stmts
                if isinstance(st, GoAssignment) and not (isinstance(st.rhs, (GoVariable, GoFakeVariable)))
            ]
            if len(defs) == 1 and _go_text(defs[0].rhs) == text and _Scan.is_local(defs[0].lhs):
                twins.append(defs[0].lhs)
        return twins

    # -- rule 1b: mirrors
    def _mirrors(self, scan: _Scan) -> bool:
        """
        ``x`` whose assignments are all ``x = y`` and which is re-copied right after every assignment to ``y`` equals
        ``y`` everywhere: the copies go and ``x`` reads as ``y``.
        """
        params = self._params()
        for key, stmts in list(scan.assigns.items()):
            if key in scan.addressed or key in params or len(stmts) < 2:
                continue
            if not all(
                isinstance(st, GoAssignment)
                and _Scan.is_local(st.lhs)
                and isinstance(st.rhs, (GoVariable, GoFakeVariable))
                and _UseCounter.key(st.rhs) != key
                for st in stmts
            ):
                continue
            ykeys = {_UseCounter.key(st.rhs) for st in stmts}
            if len(ykeys) != 1:
                continue
            ykey = next(iter(ykeys))
            if ykey in scan.addressed:
                continue
            copies = {id(st) for st in stmts}
            # every assignment to y is immediately followed, in its block, by a copy into x
            synced = True
            for st in scan.assigns.get(ykey, []):
                loc = scan.scope_of.get(id(st))
                if loc is None:
                    synced = False
                    break
                block = scan.scopes[loc[0]]
                nxt = block[loc[1] + 1] if loc[1] + 1 < len(block) else None
                if nxt is None or id(nxt) not in copies:
                    synced = False
                    break
            if not synced:
                continue
            # x is never read before its first copy (the copy precedes every read in the enclosing block order)
            first = min((scan.scope_of[id(st)] for st in stmts if id(st) in scan.scope_of), default=None)
            if first is None:
                continue
            self._remove(stmts)
            self._substitute(key, stmts[0].rhs)
            return True
        return False

    # -- rule 2: forward copy propagation inside a block
    def _propagate(self, scan: _Scan) -> bool:
        for stmts in scan.scopes.values():
            for j, cp in enumerate(stmts):
                if not (isinstance(cp, GoAssignment) and _Scan.is_local(cp.lhs)):
                    continue
                key = _UseCounter.key(cp.lhs)
                if len(scan.assigns.get(key, [])) != 1 or key in scan.addressed:
                    continue
                rhs = cp.rhs
                total = scan.reads[key]
                if total == 0:
                    continue
                if isinstance(rhs, (GoVariable, GoFakeVariable)):
                    if _UseCounter.key(rhs) == key:
                        continue
                    ykeys = [_UseCounter.key(rhs)]
                else:
                    # a pure expression is folded into a single read only
                    if total != 1 or not _go_pure(rhs):
                        continue
                    reads = _UseCounter()
                    reads.handle(rhs)
                    ykeys = list(reads.counts)
                    if key in ykeys:
                        continue
                found = 0
                targets = []
                ok = True
                for st in stmts[j + 1 :]:
                    n = _go_reads_in(st, key)
                    assigns_y = any(_go_assigns_in(st, yk) for yk in ykeys)
                    if n:
                        # reading x while assigning y in one statement is fine only for a plain assignment
                        if assigns_y and not isinstance(st, (GoAssignment, GoMultiAssignment)):
                            ok = False
                            break
                        found += n
                        targets.append(st)
                        if found == total:
                            break
                    if assigns_y:
                        ok = False
                        break
                if not ok or found != total:
                    continue
                for st in targets:
                    _VarSubstituter(key, rhs).handle(st)
                self._remove([cp])
                return True
        return False

    # -- rule 3: dead single-assignment locals
    def _dead(self, scan: _Scan) -> bool:
        doomed = []
        # a stack slot next to an address-taken object may be read through that pointer (an array or struct the
        # recovery split into several variables), so stack stores only go when no stack object escapes
        stack_escapes = any(k[0] == "v" and isinstance(k[1], SimStackVariable) for k in scan.addressed)
        for key, stmts in scan.assigns.items():
            if scan.reads[key] or key in scan.addressed:
                continue
            if stack_escapes and key[0] == "v" and isinstance(key[1], SimStackVariable):
                continue
            if all(isinstance(st, GoAssignment) and _go_pure(st.rhs) for st in stmts):
                doomed.extend(stmts)
        if not doomed:
            return False
        self._remove(doomed)
        return True

    # -- rule 4b: a two-word call result stored word by word (the second word is a dangling register)
    def _fuse_split_stores(self, scan: _Scan) -> None:
        ws = self._codegen.project.arch.bytes
        params = self._params()

        def word_store(stmt):
            if isinstance(stmt, GoAssignment) and isinstance(stmt.lhs, GoVariableField):
                off = stmt.lhs.field.offset
                if off in (0, ws) and _go_var_named(stmt.lhs.variable) and _go_var_named(stmt.rhs):
                    return _UseCounter.key(stmt.lhs.variable), off, stmt.rhs
            return None

        def whole_call_result(var):
            key = _UseCounter.key(var)
            defs = scan.assigns.get(key, [])
            if len(defs) != 1 or not isinstance(defs[0], GoAssignment):
                return None
            rhs = defs[0].rhs
            ty = unpack_typeref(rhs.type) if isinstance(rhs, (GoFunctionCall, GoMethodCall)) else None
            return ty if ty is not None and getattr(ty, "size", None) == 2 * self._codegen.project.arch.bits else None

        def dangling(var):
            key = _UseCounter.key(var)
            return key not in params and not scan.assigns.get(key) and key[0] == "v"

        for stmts in list(scan.scopes.values()):
            i = 0
            while i + 1 < len(stmts):
                a, b = word_store(stmts[i]), word_store(stmts[i + 1])
                if a and b and a[0] == b[0] and {a[1], b[1]} == {0, ws}:
                    first = a if a[1] == 0 else b
                    second = b if first is a else a
                    if whole_call_result(first[2]) is not None and dangling(second[2]):
                        base = stmts[i].lhs.variable
                        target = base
                        if isinstance(unpack_typeref(base.type), SimTypePointer):
                            target = GoUnaryOp("Dereference", base, codegen=self._codegen)
                        fused = GoAssignment(target, first[2], tags=stmts[i].tags, codegen=self._codegen)
                        self._cfunc.statements = _StmtRemover([stmts[i + 1]]).handle(self._cfunc.statements)
                        self._cfunc.statements = _VarSubstituter(("stmt", id(stmts[i])), fused).handle(
                            self._cfunc.statements
                        )
                        # replace the first store in its list
                        self._replace_stmt(stmts[i], fused)
                        stmts = _go_stmt_list(GoStatements(stmts, codegen=self._codegen))
                        i += 1
                        continue
                i += 1

    def _replace_stmt(self, old, new):
        class _Replacer(GoStructuredCodeWalker):
            def handle_GoStatements(inner, obj):
                obj.statements = [new if st is old else inner.handle(st) for st in obj.statements]
                return obj

        self._cfunc.statements = _Replacer().handle(self._cfunc.statements)

    # -- rule 5: a call result read once, by the next statement, ahead of that statement's other calls
    def _fold_calls(self, scan: _Scan) -> bool:
        for stmts in scan.scopes.values():
            for j in range(len(stmts) - 1):
                cp = stmts[j]
                if not (isinstance(cp, GoAssignment) and _Scan.is_local(cp.lhs)):
                    continue
                key = _UseCounter.key(cp.lhs)
                if len(scan.assigns.get(key, [])) != 1 or key in scan.addressed or scan.reads[key] != 1:
                    continue
                call = cp.rhs
                if not isinstance(call, (GoFunctionCall, GoMethodCall)):
                    continue
                nxt = stmts[j + 1]
                if _go_reads_in(nxt, key) != 1 or not _go_call_position_ok(nxt, key):
                    continue
                # the value's declared type must be what the call returns, or the fold changes the meaning
                if isinstance(cp.lhs, GoVariable):
                    var_ty = unpack_typeref(cp.lhs.type)
                    call_ty = unpack_typeref(call.type)
                    if (
                        var_ty is not None
                        and call_ty is not None
                        and getattr(var_ty, "size", None) != getattr(call_ty, "size", None)
                    ):
                        continue
                _VarSubstituter(key, call).handle(nxt)
                self._remove([cp])
                return True
        return False

    # -- loop iterators
    def _recover_iterators(self, node):
        for stmt in _go_stmt_list(node) if isinstance(node, GoStatements) else [node]:
            if isinstance(stmt, GoIfElse):
                for _, n in stmt.condition_and_nodes:
                    self._recover_iterators(n)
                if stmt.else_node is not None:
                    self._recover_iterators(stmt.else_node)
            elif isinstance(stmt, (GoWhileLoop, GoDoWhileLoop, GoRangeLoop)):
                self._recover_iterators(stmt.body)
            elif isinstance(stmt, GoTypeSwitch):
                for _, b in stmt.cases:
                    self._recover_iterators(b)
                if stmt.default is not None:
                    self._recover_iterators(stmt.default)
            elif isinstance(stmt, GoForLoop):
                self._recover_iterators(stmt.body)
                if stmt.iterator is None and stmt.condition is not None:
                    body = _go_stmt_list(stmt.body)
                    if (
                        body
                        and isinstance(body[-1], GoAssignment)
                        and isinstance(body[-1].lhs, (GoVariable, GoFakeVariable))
                    ):
                        key = _UseCounter.key(body[-1].lhs)
                        if _go_reads_in(stmt.condition, key) and not self._has_continue(stmt.body):
                            stmt.iterator = body[-1]
                            stmt.body = _StmtRemover([body[-1]], lists_only=True).handle(stmt.body)

    def _has_continue(self, node) -> bool:
        for stmt in _go_stmt_list(node) if isinstance(node, GoStatements) else [node]:
            if isinstance(stmt, GoContinue):
                return True
            if isinstance(stmt, GoIfElse):
                if any(self._has_continue(n) for _, n in stmt.condition_and_nodes) or (
                    stmt.else_node is not None and self._has_continue(stmt.else_node)
                ):
                    return True
            elif isinstance(stmt, GoTypeSwitch) and (
                any(self._has_continue(b) for _, b in stmt.cases)
                or (stmt.default is not None and self._has_continue(stmt.default))
            ):
                return True
            # continues inside nested loops belong to those loops
        return False


class ShortDeclarations:
    """
    Turn the first assignment of a local into ``x := e`` when it sits in the innermost block enclosing every use of
    ``x`` (Go's scoping for short declarations), and drop the ``var`` line. Loop initializers and range loops
    declare their variables the same way.
    """

    def __init__(self, codegen, cfunc: GoFunction):
        self._codegen = codegen
        self._cfunc = cfunc
        self._refs: dict = defaultdict(list)  # key -> [path]; path = ((scope, ordinal), ...)
        self._stmt_at: dict = {}
        self._next_scope = 0
        self._excluded = {_UseCounter.key(arg) for arg in cfunc.arg_list}

    @staticmethod
    def _key(var):
        return _UseCounter.key(var)

    def _is_local(self, var) -> bool:
        if isinstance(var, GoFakeVariable):
            return var.name != "_"
        if isinstance(var, GoVariable):
            v = var.variable
            return not (isinstance(v, SimMemoryVariable) and not isinstance(v, SimStackVariable))
        return False

    # -- collection
    def run(self):
        root = self._cfunc.statements
        if not isinstance(root, GoStatements):
            root = GoStatements([root], addr=getattr(root, "addr", None), codegen=self._codegen)
            self._cfunc.statements = root
        self._visit_scope(root, ())
        self._decide()

    def _visit_scope(self, node, path):
        scope = self._next_scope
        self._next_scope += 1
        for ordinal, stmt in enumerate(_go_stmt_list(node)):
            p = (*path, (scope, ordinal))
            self._stmt_at[(scope, ordinal)] = stmt
            self._visit_stmt(stmt, p)

    def _visit_stmt(self, stmt, p):
        if isinstance(stmt, GoIfElse):
            for cond, node in stmt.condition_and_nodes:
                self._visit_expr(cond, p)
                self._visit_scope(node, p)
            if stmt.else_node is not None:
                self._visit_scope(stmt.else_node, p)
        elif isinstance(stmt, (GoWhileLoop, GoDoWhileLoop)):
            self._visit_expr(stmt.condition, p)
            self._visit_scope(stmt.body, p)
        elif isinstance(stmt, GoForLoop):
            for part in (stmt.initializer, stmt.condition, stmt.iterator):
                if part is not None:
                    self._visit_expr(part, p)
            self._visit_scope(stmt.body, p)
        elif isinstance(stmt, GoRangeLoop):
            for part in (stmt.index, stmt.value, stmt.collection):
                if part is not None:
                    self._visit_expr(part, p)
            self._visit_scope(stmt.body, p)
        elif isinstance(stmt, GoTypeSwitch):
            self._visit_expr(stmt.value, p)
            for _, body in stmt.cases:
                self._visit_scope(body, p)
            if stmt.default is not None:
                self._visit_scope(stmt.default, p)
        elif isinstance(stmt, GoStatements):
            self._visit_scope(stmt, p)
        else:
            self._visit_expr(stmt, p)

    def _visit_expr(self, node, p):
        if isinstance(node, (GoVariable, GoFakeVariable)):
            if self._is_local(node):
                self._refs[self._key(node)].append(p)
            return
        if isinstance(node, GoStatements):
            self._visit_scope(node, p)
            return
        for name in _go_node_attr_names(node):
            child = getattr(node, name, None)
            if isinstance(child, GoConstruct):
                self._visit_expr(child, p)
            elif isinstance(child, (list, tuple)):
                for item in child:
                    if isinstance(item, GoConstruct):
                        self._visit_expr(item, p)
                    elif isinstance(item, tuple):
                        for x in item:
                            if isinstance(x, GoConstruct):
                                self._visit_expr(x, p)
            elif isinstance(child, dict):
                for x in child.values():
                    if isinstance(x, GoConstruct):
                        self._visit_expr(x, p)

    # -- decision
    def _candidate(self, key):
        """The (scope, ordinal) of the statement that could declare ``key``, or None."""
        paths = self._refs[key]
        if not paths:
            return None
        depth = 0
        while all(len(path) > depth for path in paths) and len({path[depth][0] for path in paths}) == 1:
            depth += 1
        if depth == 0:
            return None
        first = min(path[depth - 1][1] for path in paths)
        scope = paths[0][depth - 1][0]
        return (scope, first)

    @staticmethod
    def _targets(stmt) -> list:
        """The variables a statement assigns directly."""
        if isinstance(stmt, GoAssignment):
            return [stmt.lhs]
        if isinstance(stmt, GoMultiAssignment):
            return list(stmt.lhs)
        if isinstance(stmt, GoForLoop) and isinstance(stmt.initializer, GoAssignment):
            return [stmt.initializer.lhs]
        if isinstance(stmt, GoRangeLoop):
            return [v for v in (stmt.index, stmt.value) if v is not None]
        return []

    @staticmethod
    def _sources(stmt) -> list:
        if isinstance(stmt, (GoAssignment, GoMultiAssignment)):
            return [stmt.rhs]
        if isinstance(stmt, GoForLoop) and isinstance(stmt.initializer, GoAssignment):
            return [stmt.initializer.rhs]
        if isinstance(stmt, GoRangeLoop):
            return [stmt.collection]
        return []

    def _decide(self):
        candidates = {}
        for key in self._refs:
            if key in self._excluded:
                continue
            loc = self._candidate(key)
            if loc is None:
                continue
            stmt = self._stmt_at.get(loc)
            targets = [t for t in self._targets(stmt) if self._is_local(t)]
            if not any(self._key(t) == key for t in targets):
                continue
            # the value must not read the variable being declared
            counter = _UseCounter()
            for src in self._sources(stmt):
                counter.handle(src)
            if counter.counts[key]:
                continue
            candidates[key] = loc
        # a statement declares only when every variable it assigns is fresh there
        by_stmt: dict = defaultdict(set)
        for key, loc in candidates.items():
            by_stmt[loc].add(key)
        for loc, keys in by_stmt.items():
            stmt = self._stmt_at[loc]
            targets = [t for t in self._targets(stmt) if self._is_local(t)]
            if not targets or not all(self._key(t) in keys for t in targets):
                continue
            if isinstance(stmt, (GoAssignment, GoMultiAssignment, GoRangeLoop)):
                stmt.declares = True
            elif isinstance(stmt, GoForLoop):
                stmt.initializer.declares = True
            for t in targets:
                self._cfunc.short_declared.add(t.name if isinstance(t, GoFakeVariable) else _go_var_key(t))


def _go_exits(stmts: list) -> bool:
    """Whether a statement list always leaves the enclosing flow (return, break, continue, goto)."""
    return bool(stmts) and isinstance(stmts[-1], (GoReturn, GoBreak, GoContinue, GoGoto))


class SelectRecovery(GoStructuredCodeWalker):
    """
    ``runtime.selectgo(&cases, &order, pc, nsends, nrecvs, block)`` with its case records built on the stack and the
    dispatch on the chosen index becomes ``select { case v := <-ch: ... case ch <- x: ... default: ... }``.
    """

    def __init__(self, codegen, cfunc: GoFunction):
        self._codegen = codegen
        self._cfunc = cfunc
        self._taken = {v.name for v in cfunc.unified_local_vars if v.name} | {n for n, _ in cfunc.extra_decls}
        self._dropped: set = set()

    def run(self):
        root = self._cfunc.statements
        if not isinstance(root, GoStatements):
            root = GoStatements([root], addr=getattr(root, "addr", None), codegen=self._codegen)
        self._cfunc.statements = self.handle(root)
        if self._dropped:
            counter = _UseCounter()
            counter.handle(self._cfunc.statements)
            self._cfunc.extra_decls = [
                (name, ty) for name, ty in self._cfunc.extra_decls if counter.counts[("f", name)] > 0
            ]

    def _fresh(self, base: str) -> str:
        name, n = base, 1
        while name in self._taken:
            n += 1
            name = f"{base}{n}"
        self._taken.add(name)
        return name

    def handle_GoStatements(self, obj):
        stmts = _go_stmt_list(GoStatements([self.handle(st) for st in obj.statements], codegen=self._codegen))
        out = []
        i = 0
        while i < len(stmts):
            stmt = stmts[i]
            call = self._selectgo(stmt)
            if call is not None:
                replaced = self._try_select(stmt, call, out, stmts[i + 1 :])
                if replaced is not None:
                    select, consumed = replaced
                    out.append(select)
                    i += 1 + consumed
                    continue
            out.append(stmt)
            i += 1
        obj.statements = out
        return obj

    @staticmethod
    def _selectgo(stmt):
        if not (isinstance(stmt, GoMultiAssignment) and len(stmt.lhs) == 2):
            return None
        call = stmt.rhs
        if (
            isinstance(call, GoFunctionCall)
            and call.callee_func is not None
            and normalize_go_func_name(call.callee_func.name) == "runtime.selectgo"
            and len(call.args) == 6
        ):
            return call
        return None

    @staticmethod
    def _stack_offset(expr):
        if isinstance(expr, GoVariable) and isinstance(expr.variable, SimStackVariable):
            return expr.variable.offset
        return None

    def _try_select(self, stmt, call, preceding: list, following: list):
        chosen, ok = stmt.lhs
        cases_var = _go_referenced_var(call.args[0])
        order_var = _go_referenced_var(call.args[1])
        if cases_var is None or not isinstance(cases_var.variable, SimStackVariable):
            return None
        if not all(isinstance(a, GoConstant) for a in call.args[3:6]):
            return None
        nsends, nrecvs, block = (a.value for a in call.args[3:6])
        n = nsends + nrecvs
        if not 0 < n <= 32:
            return None
        ws = self._codegen.project.arch.bytes
        base = cases_var.variable.offset
        record = 2 * ws

        # the case records: channel at base + record*k, element pointer at base + record*k + ws
        channels: dict = {}
        slots: dict = {}
        doomed = []
        order_offset = (
            order_var.variable.offset
            if order_var is not None and isinstance(order_var.variable, SimStackVariable)
            else None
        )
        for st in preceding:
            if not (isinstance(st, GoAssignment) and isinstance(st.lhs, GoVariable)):
                continue
            off = self._stack_offset(st.lhs)
            if off is None:
                continue
            if order_offset is not None and order_offset <= off < order_offset + 2 * n:
                doomed.append(st)
                continue
            if not base <= off < base + record * n:
                continue
            rhs = st.rhs
            while isinstance(rhs, GoTypeCast):
                rhs = rhs.expr
            k, rem = divmod(off - base, record)
            if isinstance(rhs, GoConstant) and rhs.value == 0:
                doomed.append(st)  # zeroing of the array
                continue
            if rem == 0:
                channels[k] = rhs
                doomed.append(st)
            elif rem == ws:
                slot = _go_referenced_var(rhs)
                if slot is None:
                    return None
                slots[k] = slot
                doomed.append(st)
        if any(k not in channels for k in range(n)):
            return None

        # the dispatch on the chosen index
        rest = list(following)
        aliases = {_UseCounter.key(chosen)}
        copies = []
        while rest and isinstance(rest[0], GoAssignment) and _go_var_named(rest[0].lhs) and _go_var_named(rest[0].rhs):
            if _UseCounter.key(rest[0].rhs) in aliases:
                aliases.add(_UseCounter.key(rest[0].lhs))
                copies.append(rest[0])
                rest = rest[1:]
            else:
                break
        if not rest or not isinstance(rest[0], GoIfElse):
            return None
        dispatch = rest[0]
        bodies: dict = {}
        consumed = len(copies) + 1
        remaining = set(range(-1 if not block else 0, n))
        for cond, node in dispatch.condition_and_nodes:
            k, equal = self._index_test(cond, aliases)
            if k is None:
                return None
            if equal:
                bodies[k] = _go_stmt_list(node)
                remaining.discard(k)
            else:
                # "chosen != k": the branch covers every other case
                others = remaining - {k}
                if len(others) != 1:
                    return None
                other = next(iter(others))
                bodies[other] = _go_stmt_list(node)
                remaining.discard(other)
        if dispatch.else_node is not None:
            if len(remaining) != 1:
                return None
            bodies[next(iter(remaining))] = _go_stmt_list(dispatch.else_node)
            remaining.clear()
        elif len(remaining) == 1:
            # the last case falls through to the statements after the dispatch, which must all leave the flow
            tail = rest[1:]
            if not all(_go_exits(_go_stmt_list(b)) for b in bodies.values()):
                return None
            bodies[next(iter(remaining))] = tail
            consumed += len(tail)
            remaining.clear()
        if remaining:
            return None

        # the cases (each is its own scope: the bound names may repeat)
        cases = []
        ok_key = _UseCounter.key(ok)
        taken0 = set(self._taken)
        introduced = set()
        for k in sorted(bodies):
            self._taken = set(taken0)
            body = GoStatements(bodies[k], codegen=self._codegen)
            if k == -1:
                cases.append((GoSelectCase("default"), body))
                continue
            chan = channels[k]
            slot = slots.get(k)
            if k < nsends:
                value = None
                if slot is not None:
                    store = next(
                        (st for st in reversed(preceding) if isinstance(st, GoAssignment) and _go_is_var(st.lhs, slot)),
                        None,
                    )
                    if store is None:
                        return None
                    value = store.rhs
                    doomed.append(store)
                cases.append((GoSelectCase("send", chan, value), body))
                continue
            value = None
            ok_var = None
            if slot is not None and _go_reads_in(body, _UseCounter.key(slot)):
                chan_type = unpack_typeref(chan.type)
                elem = chan_type.elem_type if isinstance(chan_type, GoSimTypeChan) else None
                if elem is None:
                    elem = unpack_typeref(slot.type)
                value = GoFakeVariable(
                    self._fresh("v"), elem.with_arch(self._codegen.project.arch), codegen=self._codegen
                )
                body = _VarSubstituter(_UseCounter.key(slot), value).handle(body)
                self._dropped.add(_UseCounter.key(slot))
            if _go_reads_in(body, ok_key):
                ok_var = GoFakeVariable(self._fresh("ok"), ok.type, codegen=self._codegen)
                body = _VarSubstituter(ok_key, ok_var).handle(body)
            cases.append((GoSelectCase("recv", chan, value, ok_var), body))
            introduced |= self._taken - taken0
        self._taken = taken0 | introduced

        for st in doomed:
            if st in preceding:
                preceding.remove(st)
        self._dropped.add(_UseCounter.key(chosen))
        self._dropped.add(ok_key)
        return GoSelect(cases, tags=stmt.tags, codegen=self._codegen), consumed

    @staticmethod
    def _index_test(cond, aliases):
        if not (isinstance(cond, GoBinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return None, None
        for a, b in ((cond.lhs, cond.rhs), (cond.rhs, cond.lhs)):
            if _go_var_named(a) and _UseCounter.key(a) in aliases and isinstance(b, GoConstant):
                value = b.value
                if isinstance(value, int) and value >= 2**63:
                    value -= 2**64
                return value, cond.op == "CmpEQ"
        return None, None


class _DeadCopyRemover(GoStructuredCodeWalker):
    """Drops ``a = b`` statements of variables that no longer have any reads."""

    def __init__(self, keys, cfunc):
        counter = _UseCounter()
        counter.handle(cfunc.statements)
        self._counts = counter.counts
        self._keys = keys

    def handle_GoStatements(self, obj):
        out = []
        for stmt in obj.statements:
            stmt = self.handle(stmt)
            if (
                isinstance(stmt, GoAssignment)
                and _go_var_named(stmt.lhs)
                and _UseCounter.key(stmt.lhs) in self._keys
                and self._counts[_UseCounter.key(stmt.lhs)] <= 1
                and (_go_var_named(stmt.rhs) or isinstance(stmt.rhs, GoVariableField))
            ):
                continue
            out.append(stmt)
        obj.statements = out
        return obj


class MakeTypecastsImplicit(GoStructuredCodeWalker):
    @classmethod
    def collapse(cls, dst_ty: SimType, child: GoExpression) -> GoExpression:
        result = child
        if isinstance(child, GoTypeCast):
            intermediate_ty = child.dst_type
            start_ty = child.src_type

            # step 1: collapse pointer-integer casts of the same size
            if qualifies_for_simple_cast(intermediate_ty, dst_ty) and qualifies_for_simple_cast(start_ty, dst_ty):
                result = child.expr
            # step 2: collapse integer conversions which are redundant
            if (
                isinstance(dst_ty, (SimTypeChar, SimTypeInt, SimTypeNum))
                and isinstance(intermediate_ty, (SimTypeChar, SimTypeInt, SimTypeNum))
                and isinstance(start_ty, (SimTypeChar, SimTypeInt, SimTypeNum))
            ):
                assert dst_ty.size and start_ty.size and intermediate_ty.size
                if dst_ty.size <= start_ty.size and dst_ty.size <= intermediate_ty.size:
                    # this is a down- or neutral-cast with an intermediate step that doesn't matter
                    result = child.expr
                elif dst_ty.size >= intermediate_ty.size >= start_ty.size and intermediate_ty.signed == start_ty.signed:
                    # this is an up- or neutral-cast which is monotonically ascending
                    # we can leave out the dst_ty.signed check
                    result = child.expr
                # more cases go here...

        if result is not child:
            # TODO this is not the best since it prohibits things like the BinaryOp optimizer from working incrementally
            return cls.collapse(dst_ty, result)
        return result

    def handle_GoAssignment(self, obj):
        obj.rhs = self.collapse(obj.lhs.type, obj.rhs)
        return super().handle_GoAssignment(obj)

    def handle_GoFunctionCall(self, obj: GoFunctionCall):
        prototype_args = [] if obj.prototype is None else obj.prototype.args
        for i, (c_arg, arg_ty) in enumerate(zip(obj.args, prototype_args)):
            obj.args[i] = self.collapse(arg_ty, c_arg)
        return super().handle_GoFunctionCall(obj)

    def handle_GoReturn(self, obj: GoReturn):
        returnty = obj.codegen._func.prototype.returnty
        result_types = returnty.elems if isinstance(returnty, GoSimTypeTuple) else [returnty]
        if len(result_types) == len(obj.retvals):
            obj.retvals = [self.collapse(ty, retval) for ty, retval in zip(result_types, obj.retvals)]
        return super().handle_GoReturn(obj)

    def handle_GoBinaryOp(self, obj: GoBinaryOp):
        obj = super().handle_GoBinaryOp(obj)
        while True:
            new_lhs = self.collapse(obj.common_type, obj.lhs)
            assert obj.rhs.type is not None and new_lhs.type is not None
            if (
                new_lhs is not obj.lhs
                and GoBinaryOp.compute_common_type(obj.op, new_lhs.type, obj.rhs.type) == obj.common_type
            ):
                obj.lhs = new_lhs
            else:
                new_rhs = self.collapse(obj.common_type, obj.rhs)
                assert new_rhs.type is not None and obj.lhs.type is not None
                if (
                    new_rhs is not obj.rhs
                    and GoBinaryOp.compute_common_type(obj.op, obj.lhs.type, new_rhs.type) == obj.common_type
                ):
                    obj.rhs = new_rhs
                else:
                    break
        return obj

    def handle_GoTypeCast(self, obj: GoTypeCast):
        # note that the expression that this method returns may no longer be a GoTypeCast
        obj = super().handle_GoTypeCast(obj)
        inner = self.collapse(obj.dst_type, obj.expr)
        if inner.type is None:
            obj.expr = inner
            return obj
        if inner is not obj.expr:
            obj.src_type = inner.type
            obj.expr = inner
        if obj.src_type == obj.dst_type or qualifies_for_implicit_cast(obj.src_type, obj.dst_type):
            return obj.expr
        return obj


class FieldReferenceCleanup(GoStructuredCodeWalker):
    def handle_GoTypeCast(self, obj):
        if isinstance(obj.dst_type, SimTypePointer) and not isinstance(obj.dst_type.pts_to, SimTypeBottom):
            new_obj = obj.codegen._access_reference(obj.expr, obj.dst_type.pts_to)
            if not isinstance(new_obj, GoTypeCast):
                return self.handle(new_obj)
        return super().handle_GoTypeCast(obj)


class PointerArithmeticFixer(GoStructuredCodeWalker):
    """
    Before calling this fixer class, pointer arithmetics are purely integer-based and ignoring the pointer type.

    For example, in the following case:

    struct A* a_ptr;  // assume struct A is 24 bytes in size
    a_ptr = a_ptr + 24;

    It means adding 24 to the address of a_ptr, without considering the size of struct A. This fixer class will make
    pointer arithmetics aware of the pointer type. In this case, the fixer class will convert the code to
    a_ptr = a_ptr + 1.
    """

    def handle_GoAssignment(self, obj: GoAssignment):
        if "type" in obj.tags and "dst" in obj.tags["type"] and "src" in obj.tags["type"]:
            # HACK: do not attempt to fix pointer arithmetic if dst and src types are explicitly given
            # FIXME: Properly propagate dst and src types to lhs and rhs
            return obj
        return super().handle_GoAssignment(obj)

    def handle_GoBinaryOp(self, obj: GoBinaryOp):  # type: ignore
        obj: GoBinaryOp = super().handle_GoBinaryOp(obj)
        if (
            obj.op in ("Add", "Sub")
            and isinstance(obj.type, SimTypePointer)
            and not isinstance(obj.type.pts_to, SimTypeBottom)
            and not _go_off_stride_step(obj)
        ):
            out = obj.codegen._access_reference(obj, obj.type.pts_to)
            if (
                isinstance(out, GoUnaryOp)
                and out.op == "Reference"
                and isinstance(out.operand, GoIndexedVariable)
                and isinstance(out.operand.index, GoConstant)
            ):
                # rewrite &a[1] to a + 1
                const = out.operand.index
                if isinstance(const.value, int) and const.value < 0:
                    op = "Sub"
                    const = GoConstant(
                        -const.value,
                        const.type,
                        reference_values=const.reference_values,
                        tags=const.tags,
                        codegen=const.codegen,
                    )
                else:
                    op = "Add"
                return GoBinaryOp(op, out.operand.variable, const, tags=out.operand.tags, codegen=out.codegen)
            return out
        return obj


# StructuredCodeGenerator = GoStructuredCodeGenerator
register_analysis(GoStructuredCodeGenerator, "GoStructuredCodeGenerator")
