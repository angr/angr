# pylint:disable=missing-class-docstring,too-many-boolean-expressions,unused-argument,no-self-use,protected-access
"""
Go-flavored structured code generator. A fork of the C backend (c.py) that renders Go syntax.
"""

from __future__ import annotations

import contextlib
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
from angr.go.sim_type import (
    GoSimStruct,
    GoSimType,
    GoSimTypeInt,
    GoSimTypeInterface,
    GoSimTypePointer,
    GoSimTypeSlice,
    GoSimTypeString,
    GoSimTypeTuple,
)
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from angr.knowledge_plugins.functions import Function
from angr.sim_type import (
    SimCppClass,
    SimStruct,
    SimType,
    SimTypeArray,
    SimTypeBitfield,
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
    if not isinstance(data_type, (SimTypeInt, SimTypeChar, SimTypeNum, SimTypeReg)) or isinstance(data_type, GoSimType):
        return isinstance(data_type, GoSimTypeInt)
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
        "functy",
        "name",
        "omit_header",
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

    def variable_list_repr_chunks(self, indent=0):
        indent_str = self.indent_str(indent)

        for variable in self.sort_local_vars(self.unified_local_vars):
            cvar_and_vartypes = self.unified_local_vars[variable]

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

        if self.unified_local_vars:
            yield "\n", None

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
        yield self.name, self
        # argument list
        paren = GoClosingObject("(")
        brace = GoClosingObject("{")
        yield "(", paren
        for i, (arg_type, cvariable) in enumerate(zip(self.functy.args, self.arg_list)):
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
        yield from self.statements.c_repr_chunks(indent=indent + self.codegen.indent_delta)
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
        yield "while ", None
        paren = GoClosingObject("(")
        brace = GoClosingObject("{")
        yield "(", paren
        if self.condition is None:
            yield "true", self
        else:
            yield from self.condition.c_repr_chunks()
        yield ")", paren
        if self.codegen.braces_on_own_lines:
            yield "\n", None
            yield indent_str, None
        else:
            yield " ", None
        if self.body is None:
            yield ";", None
            yield "\n", None
        else:
            yield "{", brace
            yield "\n", None
            yield from self.body.c_repr_chunks(indent=indent + self.codegen.indent_delta)
            yield indent_str, None
            yield "}", brace
            yield "\n", None


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
        paren = GoClosingObject("(")

        yield indent_str, None
        yield "do", self
        if self.codegen.braces_on_own_lines:
            yield "\n", None
            yield indent_str, None
        else:
            yield " ", None
        if self.body is not None:
            yield "{", brace
            yield "\n", None
            yield from self.body.c_repr_chunks(indent=indent + self.codegen.indent_delta)
            yield indent_str, None
            yield "}", brace
        else:
            yield "{", brace
            yield " ", None
            yield "}", brace
        yield " ", None
        yield "while ", self
        yield "(", paren
        if self.condition is None:
            yield "true", self
        else:
            yield from self.condition.c_repr_chunks()
        yield ")", paren
        yield ";\n", self


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

        yield indent_str, None
        yield "for ", self
        yield "(", paren
        if self.initializer is not None:
            yield from self.initializer.c_repr_chunks(indent=0, asexpr=True)
        yield "; ", None
        if self.condition is not None:
            yield from self.condition.c_repr_chunks(indent=0)
        yield "; ", None
        if self.iterator is not None:
            yield from self.iterator.c_repr_chunks(indent=0, asexpr=True)
        yield ")", paren

        if self.body is not None:
            if self.codegen.braces_on_own_lines:
                yield "\n", None
                yield indent_str, None
            else:
                yield " ", None

            yield "{", brace
            yield "\n", None
            yield from self.body.c_repr_chunks(indent=indent + self.codegen.indent_delta)
            yield indent_str, None
            yield "}", brace
        else:
            yield ";", None
        yield "\n", None


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
        paren = GoClosingObject("(")
        brace = GoClosingObject("{")

        first_node = True
        first_node_is_single_stmt_if = False
        for condition, node in self.condition_and_nodes:
            # omit braces in the event that you want c-style if-statements that have only a single statement
            # and have no else scope or an else with also a single statement
            omit_braces = (
                self.cstyle_ifs
                and first_node
                and len(self.condition_and_nodes) == 1
                # no else-if tree can exist
                and self._is_single_stmt_node(node)
                # no else, else is also single-stmt, or else will not exist after pass
                and (self.else_node is None or self._is_single_stmt_node(self.else_node) or self.simplify_else_scope)
            )

            if first_node:
                first_node = False
                first_node_is_single_stmt_if = omit_braces
                yield indent_str, None
            else:
                if self.codegen.braces_on_own_lines:
                    yield "\n", None
                    yield indent_str, None
                else:
                    yield " ", None
                yield "else ", self

            yield "if ", self
            yield "(", paren
            yield from condition.c_repr_chunks()
            yield ")", paren
            if omit_braces:
                yield "\n", None
            else:
                if self.codegen.braces_on_own_lines:
                    yield "\n", None
                    yield indent_str, None
                else:
                    yield " ", None

                yield "{", brace
                yield "\n", None

            if node is not None:
                yield from node.c_repr_chunks(indent=self.codegen.indent_delta + indent)

            if not omit_braces:
                yield indent_str, None
                yield "}", brace

        single_stmt_else = first_node_is_single_stmt_if and len(self.condition_and_nodes) == 1
        if self.else_node is not None:
            brace = GoClosingObject("{")
            if self.simplify_else_scope:
                if not single_stmt_else:
                    yield "\n", None
                yield from self.else_node.c_repr_chunks(indent=indent)
            else:
                if single_stmt_else:
                    yield indent_str, None
                elif self.codegen.braces_on_own_lines:
                    yield "\n", None
                    yield indent_str, None
                else:
                    yield " ", None

                yield "else", self
                if self.codegen.braces_on_own_lines or single_stmt_else:
                    yield "\n", None
                    yield indent_str, None
                else:
                    yield " ", None

                if single_stmt_else:
                    yield from self.else_node.c_repr_chunks(indent=self.codegen.indent_delta)
                else:
                    yield "{", brace
                    yield "\n", None
                    yield from self.else_node.c_repr_chunks(indent=indent + self.codegen.indent_delta)
                    yield indent_str, None
                    yield "}", brace

        if not first_node_is_single_stmt_if and not self.simplify_else_scope:
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

        yield indent_str, None
        yield "if ", self
        yield "(", paren
        yield from self.condition.c_repr_chunks()
        yield ")", paren
        if self.codegen.braces_on_own_lines or self.cstyle_ifs:
            yield "\n", None
            yield indent_str, None
        else:
            yield " ", None
        if self.cstyle_ifs:
            yield self.indent_str(indent=self.codegen.indent_delta), self
            yield "break;\n", self
        else:
            yield "{", brace
            yield "\n", None
            yield self.indent_str(indent=indent + self.codegen.indent_delta), self
            yield "break;\n", self
            yield indent_str, None
            yield "}", brace
        if not self.cstyle_ifs:
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
        yield "break;\n", self


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
        yield "continue;\n", self


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

        yield indent_str, None
        yield "switch ", self
        yield "(", paren
        yield from self.switch.c_repr_chunks()
        yield ")", paren
        if self.codegen.braces_on_own_lines:
            yield "\n", None
            yield indent_str, None
        else:
            yield " ", None
        yield "{", brace
        yield "\n", None

        # cases
        for id_or_ids, case in self.cases:
            yield indent_str, None
            if isinstance(id_or_ids, int):
                yield f"case {id_or_ids}", self
                yield ":\n", None
            else:
                for i, case_id in enumerate(id_or_ids):
                    yield f"case {case_id}", self
                    yield ":", None
                    if i != len(id_or_ids) - 1:
                        yield " ", None
                yield "\n", None
            yield from case.c_repr_chunks(indent=indent + self.codegen.indent_delta)

        if self.default is not None:
            yield indent_str, None
            yield "default:\n", self
            yield from self.default.c_repr_chunks(indent=indent + self.codegen.indent_delta)

        yield indent_str, None
        yield "}", brace
        yield "\n", None


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
        yield indent_str, None
        yield "switch ", self
        yield "(", paren
        yield "/* incomplete */", None
        yield ")", paren
        if self.codegen.braces_on_own_lines:
            yield "\n", None
            yield indent_str, None
        else:
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

    __slots__ = ("lhs", "rhs")

    def __init__(self, lhs, rhs, **kwargs):
        super().__init__(**kwargs)

        self.lhs = lhs
        self.rhs = rhs

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
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
            and isinstance(self.lhs, GoVariable)
            and isinstance(self.rhs, GoBinaryOp)
            and self.rhs.op in compound_assignment_ops
            and self.lhs.unified_variable is not None
        ):
            if isinstance(self.rhs.lhs, GoVariable) and self.lhs.unified_variable == self.rhs.lhs.unified_variable:
                compound_expr_rhs = self.rhs.rhs
            elif (
                self.rhs.op in commutative_ops
                and isinstance(self.rhs.rhs, GoVariable)
                and self.lhs.unified_variable == self.rhs.rhs.unified_variable
            ):
                compound_expr_rhs = self.rhs.lhs

        if compound_expr_rhs is not None:
            # a = a + x  =>  a += x
            # a = x + a  =>  a += x
            yield f" {compound_assignment_ops[self.rhs.op]}= ", self
            yield from GoExpression._try_c_repr_chunks(compound_expr_rhs)
        else:
            yield " = ", self
            yield from GoExpression._try_c_repr_chunks(self.rhs)
        if not asexpr:
            yield ";\n", self


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
            yield ";", None
            if not self.returning:
                yield " /* do not return */", None
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
        return SimTypeFunction([arg.type for arg in self.args], returnty).with_arch(self.codegen.project.arch)

    @property
    def prototype_returnty(self) -> SimType:
        """
        Returns returnty and avoids creating the SimTypeFunction instance if the function prototype is not available.
        Instead of self.prototype.returnty, you should use self.prototype_returnty for better performance.
        """
        if self.callee_func is not None and self.callee_func.prototype is not None:
            return self.prototype.returnty  # type: ignore
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

        for i, arg in enumerate(self.args):
            if i:
                yield ", ", None
            yield from GoExpression._try_c_repr_chunks(arg)

        yield ")", paren

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
            yield "return;\n", self
        else:
            yield indent_str, None
            yield "return ", self
            for i, retval in enumerate(self.retvals):
                if i:
                    yield ", ", None
                yield from retval.c_repr_chunks()
            yield ";\n", self


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
            yield "/* ", None
        yield "goto ", self
        if lbl is None:
            if isinstance(self.target, int):
                yield f"LABEL_{self.target:#x}", None
            else:
                yield "*((void *)(", None
                yield from self.target.c_repr_chunks()
                yield "))", None
        else:
            yield lbl.name, lbl
        yield ";", self
        if self.codegen.comment_gotos:
            yield " */", None
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
        if not isinstance(self.variable, (GoVariable, GoVariableField)):
            yield "(", None
        yield from self.variable.c_repr_chunks()
        if not isinstance(self.variable, (GoVariable, GoVariableField)):
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
        yield from self.variable.c_repr_chunks()
        if self.var_is_ptr:
            yield "->", self
        else:
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
        paren = GoClosingObject("(")
        yield "~", self
        yield "(", paren
        yield from GoExpression._try_c_repr_chunks(self.operand)
        yield ")", paren

    def _c_repr_chunks_neg(self):
        paren = GoClosingObject("(")
        yield "-", self
        yield "(", paren
        yield from GoExpression._try_c_repr_chunks(self.operand)
        yield ")", paren

    def _c_repr_chunks_reference(self):
        # C array-to-pointer decay: an array-typed lvalue already decays to a pointer to its first
        # element, so "&array" is redundant.
        operand_type = self.operand.type if self.operand is not None else None
        if operand_type is not None and isinstance(unpack_typeref(operand_type), SimTypeArray):
            yield from GoExpression._try_c_repr_chunks(self.operand)
            return
        yield "&", self
        yield from GoExpression._try_c_repr_chunks(self.operand)

    def _c_repr_chunks_dereference(self):
        paren = GoClosingObject("(")
        yield "*", self
        yield "(", paren
        yield from GoExpression._try_c_repr_chunks(self.operand)
        yield ")", paren

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
        precedence_list = [
            # lowest precedence
            ["Concat"],
            ["LogicalOr"],
            ["LogicalXor"],
            ["LogicalAnd"],
            ["Or"],
            ["Xor"],
            ["And"],
            ["CmpEQ", "CmpNE"],
            ["CmpLE", "CmpLT", "CmpGT", "CmpGE"],
            ["Shl", "Shr", "Sar"],
            ["Add", "Sub"],
            ["Mul", "Div"],
            ["SBorrow", "SCarry", "Carry"],
            # highest precedence
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
            yield "(", paren
            yield go_type_str(signed_ty), signed_ty
            yield ")", paren
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
        yield from self._c_repr_chunks(" ^ ")

    def _c_repr_chunks_cmple(self):
        yield from self._c_repr_chunks(" <= ")

    def _c_repr_chunks_cmplt(self):
        yield from self._c_repr_chunks(" < ")

    def _c_repr_chunks_cmpgt(self):
        yield from self._c_repr_chunks(" > ")

    def _c_repr_chunks_cmpge(self):
        yield from self._c_repr_chunks(" >= ")

    def _c_repr_chunks_cmpeq(self):
        if self._cstyle_null_cmp and self._has_const_null_rhs():
            yield from GoUnaryOp("Not", self.lhs, codegen=self.codegen).c_repr_chunks()
        else:
            yield from self._c_repr_chunks(" == ")

    def _c_repr_chunks_cmpne(self):
        if self._cstyle_null_cmp and self._has_const_null_rhs():
            yield from self._try_c_repr_chunks(self.lhs)
        else:
            yield from self._c_repr_chunks(" != ")

    def _c_repr_chunks_concat(self):
        yield from self._c_repr_chunks(" CONCAT ")

    def _c_repr_chunks_rol(self):
        yield "__ROL__", self
        paren = GoClosingObject("(")
        yield "(", paren
        yield from self._try_c_repr_chunks(self.lhs)
        yield ", ", None
        yield from self._try_c_repr_chunks(self.rhs)
        yield ")", paren

    def _c_repr_chunks_ror(self):
        yield "__ROR__", self
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

        src_type = src_type or expr.type
        assert src_type is not None
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
        if self.codegen.show_casts:
            yield "(", paren
            yield go_type_str(self.dst_type), self.dst_type
            yield ")", paren

        if isinstance(self.expr, GoBinaryOp):
            wrapping_paren = True
            yield "(", paren
        else:
            wrapping_paren = False
        yield from GoExpression._try_c_repr_chunks(self.expr)
        if wrapping_paren:
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

        if isinstance(self.value, int) and self.value == 0 and isinstance(self.type, SimTypePointer):
            # print NULL instead
            yield "NULL", self

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

        if self.fmt_hex:
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
        yield "(", paren
        yield from self.cond.c_repr_chunks()
        yield " ? ", self
        yield from self.iftrue.c_repr_chunks()
        yield " : ", self
        yield from self.iffalse.c_repr_chunks()
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
                expr = GoTypeCast(
                    expr.type, SimTypePointer(SimTypeChar()).with_arch(self.project.arch), expr, codegen=self
                )
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
            for c, t in o_terms:
                op = "Add"
                if c == -1 and result is not None:
                    op = "Sub"
                    piece = (
                        t
                        if not isinstance(t.type, SimTypePointer)
                        else GoTypeCast(t.type, SimTypePointer(SimTypeChar()), t, codegen=self)
                    )
                elif c == 1:
                    piece = (
                        t
                        if not isinstance(t.type, SimTypePointer)
                        else GoTypeCast(t.type, SimTypePointer(SimTypeChar()), t, codegen=self)
                    )
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
            return bail_out()

        i = 0
        kernel = None
        while i < len(terms):
            c, t = terms[i]
            if isinstance(unpack_typeref(t.type), (SimTypePointer, SimTypeArray)):
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
        while terms:
            assert kernel.type is not None
            kernel_type = unpack_typeref(unpack_pointer_and_array(kernel.type))
            assert kernel_type

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

        if (
            expr.bits
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

    def _handle_Expr_Load(self, expr: Expr.Load, **kwargs):
        if expr.size == UNDETERMINED_SIZE:
            # the size is undetermined; we force it to 1
            expr_size = 1
            expr_bits = 8
        else:
            expr_size = expr.size
            expr_bits = expr.bits

        if expr_size > 100 and isinstance(expr.addr, Expr.Const):
            return self._handle_Expr_Const(expr.addr, type_=SimTypePointer(SimTypeChar()).with_arch(self.project.arch))

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
        assert inner.type is not None
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
