# pylint:disable=missing-class-docstring,too-many-boolean-expressions,unused-argument,no-self-use,protected-access
from __future__ import annotations

import logging
import re
import struct
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any, cast

from angr.ailment import Block, Expr, Stmt, Tmp
from angr.ailment.block_walker import AILBlockViewer, _dispatch_key
from angr.ailment.constant import UNDETERMINED_SIZE
from angr.ailment.expression import BinaryOp, StackBaseOffset
from angr.analyses.analysis import Analysis, register_analysis
from angr.analyses.decompiler.converted_pointers import (
    ConvertedPointerBindingMap,
    ConvertedPointerBindings,
    converted_pointer_binding_map,
)
from angr.analyses.decompiler.far_calls import FarCallBindingMap, FarCallBindings, far_call_binding_map
from angr.analyses.decompiler.near_calls import INDIRECT_NEAR_CALL_TARGET_REGISTERS
from angr.analyses.decompiler.notes.deobfuscated_strings import DeobfuscatedStringsNote
from angr.analyses.decompiler.region_identifier import MultiNode
from angr.analyses.decompiler.register_state import RegisterStateBindings, register_state_binding_map
from angr.analyses.decompiler.segmented_memory import (
    SegmentedMemoryBindings,
    segmented_memory_binding_map,
    segmented_stack_variable,
)
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
from angr.calling_conventions import SimComboArg, SimStackArg
from angr.errors import UnsupportedNodeTypeError
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from angr.knowledge_plugins.functions import Function
from angr.serializable import Serializable
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
    SimTypeFloat80,
    SimTypeFunction,
    SimTypeInt,
    SimTypeInt128,
    SimTypeInt256,
    SimTypeInt512,
    SimTypeLength,
    SimTypeLong,
    SimTypeLongLong,
    SimTypeNum,
    SimTypePointer,
    SimTypeReg,
    SimTypeShort,
    SimTypeWideChar,
    TypeRef,
)
from angr.sim_variable import (
    SimMemoryVariable,
    SimRegisterVariable,
    SimStackVariable,
    SimTemporaryVariable,
    SimVariable,
)
from angr.utils.bits import u2s
from angr.utils.constants import should_use_hex
from angr.utils.library import get_cpp_function_name
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
    UnsupportedConstruct,
    UnsupportedConstructLocation,
)

if TYPE_CHECKING:
    import archinfo

    import angr
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal


l = logging.getLogger(name=__name__)


type RenderResult = tuple[str, PositionMapping, PositionMapping, InstructionMapping, dict[Any, set[Any]]]


INDENT_DELTA = 4


_C_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_EXACT_STORAGE_ACCESS_TAG = "_exact_storage_access"
_EXACT_STORAGE_OFFSET_TAG = "_exact_storage_offset"
_NATIVE_STACK_ABSOLUTE_OFFSET_TAG = "_native_stack_absolute_offset"
_NATIVE_STACK_FRAME_ALIGNMENT_TAG = "_native_stack_frame_alignment"
_CONVERTED_POINTER_ARGUMENTS_TAG = "_converted_pointer_arguments"
_AMBIENT_REGISTER_STATE_SEED_TAG = "ambient_register_state_seed"
_INITIAL_REGISTER_STATE_SEED_TAG = "initial_register_state_seed"
_REQUIRED_CAST_TAG = "_force_explicit_cast"
_VOID_CALL_RESULT_TAG = "_void_call_result_consumed"
_UNSUPPORTED_DIAGNOSTIC_KIND_TAG = "_unsupported_diagnostic_kind"
_UNSUPPORTED_DIAGNOSTIC_OPERATION_TAG = "_unsupported_diagnostic_operation"
_NATIVE_STACK_POINTER_NEAR_CALL_KIND = "guest_near_pointer_boundary"
_NATIVE_STACK_POINTER_NEAR_CALL_OPERATION = "native-stack-pointer-to-16-bit-guest-near-pointer"
_NATIVE_STACK_POINTER_FAR_CALL_KIND = "native_stack_pointer_far_call_boundary"
_NATIVE_STACK_POINTER_FAR_CALL_OPERATION = "native-stack-pointer-to-16:16-guest-far-pointer"
_CONVERTED_POINTER_FAILURE_KIND = "converted_pointer_binding_failure"
_X86_PCODE_SWI_TARGET = "__pcode_swi"
_X86_PCODE_SWI_ARGUMENT_COUNT = 16
_C_KEYWORDS = {
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
}


class _NativeStackPointerGuestNearCallError(UnsupportedNodeTypeError):
    pass


class _StructuredCodegenDiagnosticError(UnsupportedNodeTypeError):
    def __init__(self, message: str, kind: str, operation: str):
        super().__init__(message)
        self.kind = kind
        self.operation = operation


class _SegmentedAddressFinder(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.found = False

    def _handle_SegmentedAddress(self, expr_idx, expr, stmt_idx, stmt, block):
        self.found = True


def _contains_segmented_address(expr: Expr.Expression) -> bool:
    if isinstance(expr, Expr.SegmentedAddress):
        return True
    finder = _SegmentedAddressFinder()
    finder.walk_expression(expr)
    return finder.found


def c_identifier(name: str) -> str:
    """Return a deterministic C identifier for an ABI symbol name."""

    if _C_IDENTIFIER_RE.fullmatch(name) and name not in _C_KEYWORDS:
        return name
    encoded = "".join(
        character if (character == "_" or (character.isascii() and character.isalnum())) else f"_x{ord(character):x}_"
        for character in name
    )
    if not encoded or encoded[0].isdigit():
        encoded = "_" + encoded
    if encoded in _C_KEYWORDS:
        encoded = "_" + encoded
    return encoded


def c_variable_identifier(variable: SimVariable) -> str:
    """Return the same valid identifier for every declaration and use of a SimVariable."""

    if variable.name:
        raw_name = variable.name
    elif isinstance(variable, SimTemporaryVariable):
        raw_name = f"tmp_{variable.tmp_id}"
    else:
        raw_name = str(variable)
    return c_identifier(raw_name)


def qualifies_for_simple_cast(ty1, ty2):
    # converting ty1 to ty2 - can this happen precisely?
    # used to decide whether to add explicit typecasts instead of doing *(int*)&v1
    return (
        ty1.size == ty2.size
        and isinstance(ty1, (SimTypeInt, SimTypeChar, SimTypeNum, SimTypePointer))
        and isinstance(ty2, (SimTypeInt, SimTypeChar, SimTypeNum, SimTypePointer))
    )


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


def extract_terms(expr: CExpression) -> tuple[int, list[tuple[int, CExpression]]]:
    # Look through representation-preserving casts while recovering address terms. Width-changing casts can truncate
    # or extend the machine address and must remain part of the expression even if their operand has a pointer type.
    if isinstance(expr, CTypeCast) and expr.src_type.size == expr.dst_type.size:
        expr = MakeTypecastsImplicit.collapse(expr.dst_type, expr.expr)
    if (
        isinstance(expr, CTypeCast)
        and isinstance(expr.dst_type, SimTypeInt)
        and isinstance(expr.src_type, SimTypeInt)
        and expr.dst_type.size == expr.src_type.size
        and expr.dst_type.signed != expr.src_type.signed
    ):
        # (unsigned int)(a + 60)  ==>  a + 60, assuming a + 60 is an int
        expr = expr.expr

    if isinstance(expr, CConstant) and isinstance(expr.value, int):
        return expr.value, []
    # elif isinstance(expr, CUnaryOp) and expr.op == 'Minus'
    if isinstance(expr, CBinaryOp) and expr.op == "Add":
        c1, t1 = extract_terms(expr.lhs)
        c2, t2 = extract_terms(expr.rhs)
        return c1 + c2, t1 + t2
    if isinstance(expr, CBinaryOp) and expr.op == "Sub":
        c1, t1 = extract_terms(expr.lhs)
        c2, t2 = extract_terms(expr.rhs)
        return c1 - c2, t1 + [(-c, t) for c, t in t2]
    if isinstance(expr, CBinaryOp) and expr.op == "Mul":
        if isinstance(expr.lhs, CConstant) and isinstance(expr.lhs.value, int):
            c, t = extract_terms(expr.rhs)
            return c * expr.lhs.value, [(c1 * expr.lhs.value, t1) for c1, t1 in t]
        if isinstance(expr.rhs, CConstant) and isinstance(expr.rhs.value, int):
            c, t = extract_terms(expr.lhs)
            return c * expr.rhs.value, [(c1 * expr.rhs.value, t1) for c1, t1 in t]
        return 0, [(1, expr)]
    if isinstance(expr, CBinaryOp) and expr.op == "Shl":
        if isinstance(expr.rhs, CConstant) and isinstance(expr.rhs.value, int):
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
    # special logic for C++ classes
    if isinstance(t0, SimCppClass) and isinstance(t1, SimCppClass):  # noqa: SIM102
        # TODO: Use the information (class names, etc.) in types_stl
        if {t1.name, t0.name} == {
            "std::string",
            "class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>",
        }:
            return True
    return t0 == t1


def _is_void_type(type_: SimType | None) -> bool:
    type_ = unpack_typeref(type_) if type_ is not None else None
    return isinstance(type_, SimTypeBottom) and type_.label == "void"


def _coerce_scalar_expression(
    expression: CExpression,
    expected_type: SimType | None,
    codegen: CStructuredCodeGenerator,
    *,
    force_numeric: bool = False,
) -> CExpression:
    """Represent a recovered scalar conversion explicitly at a C type boundary.

    AIL expressions retain fixed-width machine values even when independently
    recovered C types disagree. C does not permit implicit integer/pointer or
    incompatible-pointer conversions at assignments, returns, and call
    boundaries, so preserve the machine-level conversion with a required cast.
    Aggregate conversions remain unresolved because C has no aggregate cast.

    A consumed result from a call recovered as ``void`` is a stronger conflict:
    casting a void expression is itself invalid C. Retain both pieces of
    evidence by giving that call an explicit call-site return ABI while tagging
    the conflict for unsupported-construct reporting.
    """

    # Reaching a scalar type boundary proves that a direct call expression's result is consumed. This assignment is
    # intentionally structural: deserialized codegen nodes and AST rewrites may bypass CFunctionCall's original AIL
    # construction context, while the enclosing assignment/return/argument still preserves the use unambiguously.
    if isinstance(expression, CFunctionCall):
        expression.result_used = True

    if expected_type is None or expression.type is None:
        return expression

    actual = unpack_typeref(expression.type).with_arch(codegen.project.arch)
    expected = unpack_typeref(expected_type).with_arch(codegen.project.arch)
    if type_equals(actual, expected):
        return expression
    if isinstance(actual, (SimStruct, SimTypeArray, SimTypeFixedSizeArray)) or isinstance(
        expected,
        (SimStruct, SimTypeArray, SimTypeFixedSizeArray, SimTypeFunction, SimTypeBottom),
    ):
        return expression
    if (
        not force_numeric
        and isinstance(actual, (SimTypeChar, SimTypeInt, SimTypeNum))
        and isinstance(expected, (SimTypeChar, SimTypeInt, SimTypeNum))
    ):
        return expression

    if _is_void_type(actual):
        if not isinstance(expression, CFunctionCall):
            return expression
        if not expression.override_callsite_return_type(expected):
            return expression
        expression.tags[_VOID_CALL_RESULT_TAG] = True
        return expression

    tags = {**expression.tags, _REQUIRED_CAST_TAG: True}
    return CTypeCast(actual, expected, expression, tags=tags, codegen=codegen)


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


def type_to_c_repr_chunks(
    ty: SimType, name=None, name_type=None, full=False, indent_str="", indent_delta: int = INDENT_DELTA
):
    """
    Helper generator function to turn a SimType into generated tuples of (C-string, AST node).

    :param indent_delta:    Number of space characters used to indent each struct field one level deeper.
    """
    if isinstance(ty, SimStruct):
        if full:
            # struct def preamble
            yield indent_str, None
            if isinstance(ty, SimCppClass):
                yield "class ", None
            else:
                yield "typedef struct ", None
            yield ty.name, ty
            yield " {\n", None

            # each of the fields
            # fields should be indented
            new_indent_str = (" " * indent_delta) + indent_str
            for k, v in ty.fields.items():
                yield new_indent_str, None
                yield from type_to_c_repr_chunks(v, name=k, name_type=CStructFieldNameDef(k), full=False, indent_str="")
                yield ";\n", None

            # struct def postamble
            yield "} ", None
            yield ty.name, ty
            yield ";\n\n", None

        else:
            assert name
            assert name_type
            yield indent_str, None
            yield ty.name, ty
            yield " ", None
            if name:
                yield name, name_type
    elif isinstance(ty, SimType):
        assert name
        assert name_type
        raw_type_str = ty.c_repr(name=name)
        assert name in raw_type_str

        type_pre, type_post = raw_type_str.rsplit(name, 1)

        if type_pre.endswith(" "):
            type_pre_spaces = " " * (len(type_pre) - len(type_pre.rstrip(" ")))
            type_pre = type_pre.rstrip(" ")
        else:
            type_pre_spaces = ""

        yield indent_str, None
        yield type_pre, ty
        if type_pre_spaces:
            yield type_pre_spaces, None
        yield name, name_type
        yield type_post, CArrayTypeLength(type_post)
    # This case was used when generating externs, apparently there can be cases where the name is not known
    elif ty is None:
        assert name
        assert name_type
        yield "<missing-type> ", None
        yield name, name_type
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


class CConstruct:
    """
    Represents a program construct in C.
    Acts as the base class for all other representation constructions.
    """

    __slots__ = ("codegen", "ident", "idx", "tags")

    def __init__(self, codegen, tags=None):
        # a CConstruct cannot exist without its owning codegen: ``idx`` (the per-codegen unique node identity) and
        # ``ident`` (a per-class-name display label; NOT unique) are both allocated from it
        assert codegen is not None
        self.tags = tags or {}
        self.codegen: CStructuredCodeGenerator = codegen
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
                if isinstance(obj, (CStatement, CExpression)):
                    # only add statements/expressions that can be address tracked into map_pos_to_addr
                    if hasattr(obj, "tags") and obj.tags is not None and "ins_addr" in obj.tags:
                        if isinstance(obj, CVariable) and obj not in used_vars:
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
                                CVariable,
                                CConstant,
                                CStructField,
                                CIndexedVariable,
                                CVariableField,
                                CBinaryOp,
                                CUnaryOp,
                                CAssignment,
                                CFunctionCall,
                                CLabel,
                            ),
                        )
                        and pos_to_node is not None
                    ):
                        pos_to_node.add_mapping(pos, len(s), obj)

                # add (), {}, [], and [20] to mapping for highlighting as well as the full functions name
                elif isinstance(obj, (CClosingObject, CFunction, CArrayTypeLength, CStructFieldNameDef)):
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

                if isinstance(obj, CExpression):
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
        # by the CFunction class, which will then call each statement within it and construct
        # the chunks that get printed in qccode_edit in angr-management.
        return "".join(mapper(self.c_repr_chunks(indent)))

    def c_repr_chunks(self, indent=0, asexpr=False):
        raise NotImplementedError

    @staticmethod
    def indent_str(indent=0):
        return " " * indent


class CFunction(CConstruct):  # pylint:disable=abstract-method
    """
    Represents a function in C.
    """

    __slots__ = (
        "addr",
        "arg_list",
        "canonical_local_vars",
        "demangled_name",
        "exact_local_storage_accesses",
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
        arg_list: list[CVariable],
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
        self.canonical_local_vars: dict[SimVariable, SimVariable] = {}
        self.exact_local_storage_accesses: dict[SimVariable, tuple[CVariable, ...]] = {}
        self.unified_local_vars: dict[SimVariable, set[tuple[CVariable, SimType]]] = {}
        self.show_demangled_name = show_demangled_name
        self.omit_header = omit_header

        self.refresh()

    def refresh(self):
        self.unified_local_vars = self.get_unified_local_vars()
        # SimVariable equality deliberately ignores some provenance fields (for example, a stack variable's
        # region). Preserve the exact key chosen for each declaration so equal CVariable nodes cannot render a
        # different identifier from the declaration that represents them.
        self.canonical_local_vars = {variable: variable for variable in self.unified_local_vars}
        self.exact_local_storage_accesses = self._collect_exact_local_storage_accesses()

    def _collect_exact_local_storage_accesses(self) -> dict[SimVariable, tuple[CVariable, ...]]:
        """Collect every exact-width value view backed by a rendered local declaration."""

        accesses: dict[SimVariable, list[CVariable]] = defaultdict(list)
        visited: set[int] = set()

        def visit(value) -> None:
            if isinstance(value, CVariable):
                if value.tags.get(_EXACT_STORAGE_ACCESS_TAG, False):
                    accesses[self.resolved_variable(value)].append(value)
                return

            if isinstance(value, CConstruct):
                if id(value) in visited:
                    return
                visited.add(id(value))
                for cls in type(value).__mro__:
                    slots = cls.__dict__.get("__slots__", ())
                    if isinstance(slots, str):
                        slots = (slots,)
                    for slot in slots:
                        if slot in {"codegen", "ident", "idx", "tags"}:
                            continue
                        visit(getattr(value, slot, None))
            elif isinstance(value, dict):
                for item in value.values():
                    visit(item)
            elif isinstance(value, (list, tuple, set, frozenset)):
                for item in value:
                    visit(item)

        visit(self.statements)
        return {variable: tuple(variable_accesses) for variable, variable_accesses in accesses.items()}

    @staticmethod
    def captured_variable(variable: CVariable) -> SimVariable:
        """Return the unified identity captured when this C AST node was built."""

        return variable.unified_variable or variable.variable

    def resolved_variable(self, variable: CVariable) -> SimVariable:
        """Return the exact variable identity used by this function's rendered declaration."""

        captured_variable = self.captured_variable(variable)
        canonical_local_vars = getattr(self, "canonical_local_vars", {})
        return canonical_local_vars.get(captured_variable, captured_variable)

    def argument_name(self, variable: CVariable) -> str | None:
        """Return the rendered parameter name for a variable unified with a function argument."""

        variable_key = self.captured_variable(variable)
        argument_names = self.functy.arg_names or ()
        for index, argument in enumerate(self.arg_list):
            argument_key = self.captured_variable(argument)
            if variable_key != argument_key:
                continue
            if index < len(argument_names) and argument_names[index]:
                return c_identifier(argument_names[index])
            return c_variable_identifier(argument_key)
        return None

    @staticmethod
    def _sorted_local_variable_types(cvar_and_vartypes: set[tuple[CVariable, SimType]]) -> list[SimType]:
        vartypes = [vartype for _cvar, vartype in cvar_and_vartypes]
        count = Counter(vartypes)
        return sorted(
            count,
            key=lambda vartype: (
                isinstance(vartype, (SimTypeChar, SimTypeInt, SimTypeFloat)),
                count[vartype],
                repr(vartype),
            ),
        )

    def _storage_safe_declaration_type(self, variable: SimVariable, declaration_type: SimType) -> SimType:
        """Ensure an emitted local declaration owns all bytes accessed through its exact AIL value views."""

        declaration_size = _safe_type_size(unpack_typeref(declaration_type))
        required_size = 0
        widest_zero_offset_access: SimType | None = None
        for access in self.exact_local_storage_accesses.get(variable, ()):
            offset = access.tags.get(_EXACT_STORAGE_OFFSET_TAG, 0)
            access_type = unpack_typeref(access.variable_type)
            access_size = _safe_type_size(access_type)
            if type(offset) is not int or offset < 0 or access_size <= 0:
                continue
            end = offset * self.codegen.project.arch.byte_width + access_size
            if end > required_size:
                required_size = end
                widest_zero_offset_access = access_type if offset == 0 and end == access_size else None
            elif end == required_size and offset == 0 and end == access_size:
                widest_zero_offset_access = access_type

        if required_size <= 0 or declaration_size >= required_size:
            return declaration_type
        if widest_zero_offset_access is not None:
            return widest_zero_offset_access.with_arch(self.codegen.project.arch)

        byte_width = self.codegen.project.arch.byte_width
        byte_count = (required_size + byte_width - 1) // byte_width
        byte_type = SimTypeChar(signed=False).with_arch(self.codegen.project.arch)
        return SimTypeArray(byte_type, byte_count).with_arch(self.codegen.project.arch)

    def _selected_local_variable_type(
        self, variable: SimVariable, cvar_and_vartypes: set[tuple[CVariable, SimType]]
    ) -> SimType:
        recovered_type = self._sorted_local_variable_types(cvar_and_vartypes)[0]
        return self._storage_safe_declaration_type(variable, recovered_type)

    def declaration_type(self, variable: CVariable) -> SimType | None:
        """Return the type of the declaration whose identifier ``variable`` renders."""

        variable_key = self.captured_variable(variable)
        for index, argument in enumerate(self.arg_list):
            if variable_key == self.captured_variable(argument) and index < len(self.functy.args):
                return self.functy.args[index]

        declaration = self.unified_local_vars.get(self.resolved_variable(variable))
        if declaration:
            resolved_variable = self.resolved_variable(variable)
            return self._selected_local_variable_type(resolved_variable, declaration)
        return variable.variable_type

    def get_unified_local_vars(self) -> dict[SimVariable, set[tuple[CVariable, SimType]]]:
        unified_to_var_and_types: dict[SimVariable, set[tuple[CVariable, SimType]]] = defaultdict(set)

        arg_set: set[SimVariable] = set()
        for arg in self.arg_list:
            # TODO: Handle CIndexedVariable
            if isinstance(arg, CVariable):
                arg_set.add(self.captured_variable(arg))

        # output each variable and its type
        for var, cvar in self.variables_in_use.items():
            if isinstance(var, SimMemoryVariable) and not isinstance(var, SimStackVariable):
                # Skip all global variables
                continue

            key = self.captured_variable(cvar)
            if key in arg_set:
                continue

            var_type = self.variable_manager.get_variable_type(var)  # FIXME

            # `_handle_VirtualVariable` overrides p-code wide bit-vector carriers to an exact uint64_t/uint80_t.
            # Keep the declaration consistent with those uses instead of reinstating Typehoon's narrow integer guess
            # here.
            if (
                isinstance(cvar.type, SimTypeNum)
                and cvar.type.size in {64, 80}
                and var.size * self.codegen.project.arch.byte_width == cvar.type.size
            ):
                var_type = cvar.type
            elif cvar.tags.get(_NATIVE_STACK_FRAME_ALIGNMENT_TAG) and isinstance(
                unpack_typeref(cvar.variable_type), (SimTypeArray, SimTypeFixedSizeArray)
            ):
                var_type = cvar.variable_type

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

            name = c_variable_identifier(variable)

            # sort by the following:
            #   * if it's a a non-basic type
            #   * the number of occurrences
            #   * the repr of the type itself
            # TODO: The type selection should actually happen during variable unification
            vartypes = self._sorted_local_variable_types(cvar_and_vartypes)
            declaration_type = self._selected_local_variable_type(variable, cvar_and_vartypes)
            vartypes = [declaration_type, *(var_type for var_type in vartypes if var_type != declaration_type)]
            initial_register_state_seeds = {
                seed
                for cvar, _ in cvar_and_vartypes
                if isinstance((seed := cvar.tags.get(_INITIAL_REGISTER_STATE_SEED_TAG)), str)
            }
            storage_alignments = {
                alignment
                for cvar, _ in cvar_and_vartypes
                if type(alignment := cvar.tags.get(_NATIVE_STACK_FRAME_ALIGNMENT_TAG)) is int and alignment > 0
            }

            for i, var_type in enumerate(vartypes):
                if i == 0:
                    if storage_alignments:
                        # A converted-pointer frame is byte-addressed so every recovered field can retain its exact
                        # offset and aliasing. Give the frame a conservative host alignment without imposing that
                        # alignment on unrelated recovered locals.
                        yield f"_Alignas({max(storage_alignments)}) ", None
                    yield from type_to_c_repr_chunks(var_type, name=name, name_type=cvariable)
                    if len(initial_register_state_seeds) == 1:
                        yield " = ", None
                        yield next(iter(initial_register_state_seeds)), None
                    yield ";  // ", None
                    yield variable.loc_repr(self.codegen.project.arch), None
                # multiple types
                else:
                    if i == 1:
                        yield ", Other Possible Types: ", None
                    else:
                        yield ", ", None
                    if isinstance(var_type, SimType):
                        yield var_type.c_repr(), var_type
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
                    for field in ty.fields.values():
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

            for ty in sorted(local_types, key=_local_type_sort_key):
                # drop unreferenced structs
                if isinstance(ty, SimStruct) and ty.name in referenced_struct_names:
                    yield from type_to_c_repr_chunks(
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
                if ty.name in defined_struct_names:
                    continue
                defined_struct_names.add(ty.name)
                yield from type_to_c_repr_chunks(
                    ty, full=True, indent_str=indent_str, indent_delta=self.codegen.indent_delta
                )

            # Emit extern declarations (ordered by variable address so renames do not reshuffle them)
            for v in sorted(self.codegen.cexterns, key=cextern_sort_key):
                if v.variable not in self.variables_in_use:
                    continue
                varname = v.c_repr() if v.type is None else c_variable_identifier(v.variable)
                yield "extern ", None
                if v.type is None:
                    yield "<unknown-type>", None
                else:
                    yield from type_to_c_repr_chunks(v.type, name=varname, name_type=v, full=False)
                yield ";\n", None
            yield "\n", None

        yield indent_str, None

        # header comments (if they exist)
        assert self.codegen.cfunc is not None and self.codegen.cfunc.addr is not None
        header_comments = self.codegen.kb.comments.get(self.codegen.cfunc.addr, [])
        if header_comments:
            header_cmt = self._line_wrap_comment("".join(header_comments))
            yield header_cmt, None

        if self.codegen._func.is_plt:
            yield "// attributes: PLT stub\n", None

        # return type
        assert self.functy.returnty is not None
        yield self.functy.returnty.c_repr(name="").strip(" "), self.functy.returnty
        yield " ", None
        # function name
        if self.demangled_name and self.demangled_name != self.name and self.show_demangled_name:
            normalized_name = get_cpp_function_name(self.demangled_name)
        else:
            normalized_name = c_identifier(self.name)
        yield normalized_name, self
        # argument list
        paren = CClosingObject("(")
        brace = CClosingObject("{")
        yield "(", paren
        if not self.functy.args and self.codegen.cstyle_void_param:
            yield "void", None
        for i, arg_type in enumerate(self.functy.args):
            if i:
                yield ", ", None

            cvariable = self.arg_list[i] if i < len(self.arg_list) else None
            if i < len(self.functy.arg_names) and self.functy.arg_names[i]:
                argument_name = c_identifier(self.functy.arg_names[i])
            elif cvariable is not None:
                variable = cvariable.unified_variable or cvariable.variable
                argument_name = c_variable_identifier(variable)
            else:
                argument_name = f"a{i}"
            yield from type_to_c_repr_chunks(
                arg_type,
                name=argument_name,
                name_type=cvariable if cvariable is not None else arg_type,
                full=False,
            )

        yield ")", paren
        # function body
        if self.codegen.braces_on_own_lines:
            yield "\n", None
            yield indent_str, None
        else:
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
                case SimRegisterVariable():
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


class CStatement(CConstruct):  # pylint:disable=abstract-method
    """
    Represents a statement in C.
    """

    def __init__(self, tags=None, *, codegen):
        super().__init__(codegen=codegen, tags=tags)


class CExpression(CConstruct):
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


class CStatements(CStatement):
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
        for index, stmt in enumerate(self.statements):
            yield from stmt.c_repr_chunks(indent=indent, asexpr=asexpr)
            if asexpr and index + 1 < len(self.statements):
                yield ", ", None


class CAILBlock(CStatement):
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


class CLoop(CStatement):  # pylint:disable=abstract-method
    """
    Represents a loop in C.
    """

    __slots__ = ()


class CWhileLoop(CLoop):
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
        paren = CClosingObject("(")
        brace = CClosingObject("{")
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


class CDoWhileLoop(CLoop):
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
        brace = CClosingObject("{")
        paren = CClosingObject("(")

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


class CForLoop(CStatement):
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
        brace = CClosingObject("{")
        paren = CClosingObject("(")

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


class CIfElse(CStatement):
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
        condition_and_nodes: list[tuple[CExpression, CStatement | None]],
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
        return (isinstance(node, CStatements) and len(node.statements) == 1) or isinstance(
            node, (CBreak, CContinue, CReturn, CGoto)
        )

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        paren = CClosingObject("(")
        brace = CClosingObject("{")

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
            brace = CClosingObject("{")
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


class CIfBreak(CStatement):
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
        paren = CClosingObject("(")
        brace = CClosingObject("{")

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


class CBreak(CStatement):
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


class CContinue(CStatement):
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


class CSwitchCase(CStatement):
    """
    Represents a switch-case statement in C.
    """

    __slots__ = ("cases", "default", "switch")

    def __init__(self, switch, cases, default, **kwargs):
        super().__init__(**kwargs)

        self.switch = switch
        self.cases: list[tuple[int | tuple[int], CStatements]] = cases
        self.default = default

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        paren = CClosingObject("(")
        brace = CClosingObject("{")

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


class CIncompleteSwitchCase(CStatement):
    """
    Represents an incomplete switch-case construct; this only appear in the decompilation output when switch-case
    structuring fails (for whatever reason).
    """

    __slots__ = ("cases", "head")

    def __init__(self, head, cases, **kwargs):
        super().__init__(**kwargs)

        self.head = head
        self.cases: list[tuple[int, CStatements]] = cases

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        paren = CClosingObject("(")
        brace = CClosingObject("{")

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


class CAssignment(CStatement):
    """
    a = b
    """

    __slots__ = ("lhs", "rhs")

    @staticmethod
    def _valid_lvalue(lhs: CExpression, codegen) -> CExpression:
        if isinstance(lhs, CTypeCast):
            # ISO C casts are rvalues. AIL can nevertheless describe a write through a typed view of an underlying
            # storage location, especially after a narrow stack access is unified with a wider declaration. Preserve
            # that bit-level write as ``*(T *)&storage`` instead of emitting the invalid ``(T)storage = value``.
            return CUnaryOp(
                "Dereference",
                CUnaryOp("Reference", lhs, codegen=codegen),
                codegen=codegen,
            )
        return lhs

    def __init__(self, lhs, rhs, **kwargs):
        super().__init__(**kwargs)

        self.lhs = self._valid_lvalue(lhs, self.codegen)
        self.rhs = _coerce_scalar_expression(rhs, self.lhs.type, self.codegen)

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        # Cleanup walkers and cache deserialization can change the effective type of either child after construction.
        # Re-establish the assignment boundary immediately before rendering so the AST type and emitted C stay in
        # agreement. The coercion is idempotent because an existing cast already reports the destination type.
        self.lhs = self._valid_lvalue(self.lhs, self.codegen)
        self.rhs = _coerce_scalar_expression(self.rhs, self.lhs.type, self.codegen)

        yield indent_str, None
        yield from CExpression._try_c_repr_chunks(self.lhs)

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
            and isinstance(self.lhs, CVariable)
            and isinstance(self.rhs, CBinaryOp)
            and self.rhs.op in compound_assignment_ops
            and self.lhs.unified_variable is not None
        ):
            if isinstance(self.rhs.lhs, CVariable) and self.lhs.unified_variable == self.rhs.lhs.unified_variable:
                compound_expr_rhs = self.rhs.rhs
            elif (
                self.rhs.op in commutative_ops
                and isinstance(self.rhs.rhs, CVariable)
                and self.lhs.unified_variable == self.rhs.rhs.unified_variable
            ):
                compound_expr_rhs = self.rhs.lhs

        if compound_expr_rhs is not None:
            # a = a + x  =>  a += x
            # a = x + a  =>  a += x
            yield f" {compound_assignment_ops[self.rhs.op]}= ", self
            yield from CExpression._try_c_repr_chunks(compound_expr_rhs)
        else:
            yield " = ", self
            yield from CExpression._try_c_repr_chunks(self.rhs)
        if not asexpr:
            yield ";\n", self


class CExpressionStatement(CStatement):
    """
    Wraps a CExpression so it can be used as a standalone statement.

    expr;
    """

    __slots__ = ("expr", "returning")

    def __init__(self, expr: CExpression, returning: bool | None = True, **kwargs):
        super().__init__(**kwargs)
        self.expr = expr
        # Function.returning is tri-state: None means that analysis has not proved either outcome.  At a call
        # statement, however, only an explicit False justifies suppressing the fall-through path (and rendering the
        # corresponding diagnostic).  Keep CExpressionStatement's persisted state boolean so unknown callees remain
        # cacheable and conservatively behave as returning calls.
        self.returning = returning is not False

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield from self.expr.c_repr_chunks(indent=0)
        if not asexpr:
            yield ";", None
            if self.returning is False:
                yield " /* do not return */", None
            yield "\n", None


class CFunctionCall(CExpression):
    """
    func(arg0, arg1)

    :ivar Function callee_func:  The function getting called.
    """

    __slots__ = (
        "args",
        "callee_func",
        "callee_target",
        "callsite_prototype",
        "result_used",
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
        callsite_prototype: SimTypeFunction | None = None,
        result_used: bool = False,
        tags=None,
        *,
        codegen,
        **kwargs,
    ):
        super().__init__(tags=tags, codegen=codegen, **kwargs)

        if not isinstance(callee_target, (int, str, CExpression)):
            raise UnsupportedNodeTypeError(
                f"Call target {type(callee_target).__name__} was not converted to a C expression"
            )
        self.callee_target = callee_target
        self.callee_func: Function | None = callee_func
        self.args = args if args is not None else []
        # VariableMap commonly obtains this object directly from Function.prototype. Keep the edge-local ABI as an
        # independent snapshot: later calling-convention recovery is allowed to refine the function-wide prototype in
        # place, but must not retroactively rewrite an already constructed call site (or its serialized cache entry).
        self.callsite_prototype = self._snapshot_callsite_prototype(callsite_prototype)
        self.result_used = result_used
        self.show_demangled_name = show_demangled_name
        self.show_disambiguated_name = show_disambiguated_name

    def _snapshot_callsite_prototype(self, prototype: SimTypeFunction | None) -> SimTypeFunction | None:
        if prototype is None:
            return None
        # SimTypeFunction.copy() creates a detached outer object. Binding that copy to the target architecture then
        # recursively detaches its argument and return types as well, even when the input was already arch-bound.
        return cast(SimTypeFunction, prototype.copy().with_arch(self.codegen.project.arch))

    def override_callsite_return_type(self, return_type: SimType) -> bool:
        """Give this call edge a scalar return ABI without mutating the callee's function-wide prototype."""

        prototype = self.prototype
        if prototype is None:
            return False
        callsite_prototype = prototype.copy()
        callsite_prototype.returnty = return_type
        self.callsite_prototype = self._snapshot_callsite_prototype(callsite_prototype)
        return True

    @property
    def current_callee_func(self) -> Function | None:
        """Return the function currently registered for this direct call target.

        Decompiler analyses may replace a ``Function`` object in the knowledge base while an earlier structured-code
        tree is retained for regeneration.  The call-site prototype is an intentional edge-local snapshot, but the
        declaration it is compared against must come from the current program-wide function identity rather than a
        detached object captured when this node was constructed.
        """

        callee_func = self.callee_func
        if callee_func is None or self.codegen is None:
            return callee_func
        kb = getattr(self.codegen, "kb", None)
        functions = getattr(kb, "functions", None)
        function = getattr(functions, "function", None)
        if function is None:
            return callee_func
        try:
            current_callee = function(addr=callee_func.addr)
        except KeyError:
            current_callee = None
        return current_callee if current_callee is not None else callee_func

    @property
    def current_callee_prototype_is_void(self) -> bool:
        callee_func = self.current_callee_func
        if callee_func is None or callee_func.prototype is None:
            return False
        return callee_func.prototype.returnty is None or _is_void_type(callee_func.prototype.returnty)

    @property
    def prettify_thiscall(self) -> bool:
        if self.codegen is None:
            return False
        return self.codegen.prettify_thiscall

    @property
    def prototype(self) -> SimTypeFunction | None:
        if self.callsite_prototype is not None:
            return self.callsite_prototype
        callee_func = self.current_callee_func
        if callee_func is not None and callee_func.prototype is not None:
            proto = callee_func.prototype
            if callee_func.prototype_libname is not None:
                # we need to deref the prototype in case it uses SimTypeRef internally
                proto = cast(SimTypeFunction, dereference_simtype_by_lib(proto, callee_func.prototype_libname))
            return proto
        returnty = SimTypeInt(signed=False)
        return SimTypeFunction([arg.type for arg in self.args], returnty).with_arch(self.codegen.project.arch)

    @property
    def prototype_returnty(self) -> SimType:
        """
        Returns returnty and avoids creating the SimTypeFunction instance if the function prototype is not available.
        Instead of self.prototype.returnty, you should use self.prototype_returnty for better performance.
        """
        prototype = self.prototype
        if prototype is not None and prototype.returnty is not None:
            return prototype.returnty
        if prototype is not None and prototype.returnty is None:
            return SimTypeBottom(label="void").with_arch(self.codegen.project.arch)
        return SimTypeInt(signed=False).with_arch(self.codegen.project.arch)

    @property
    def type(self):
        return self.prototype_returnty

    def _is_target_ambiguous(self, func_name: str) -> bool:
        """
        Check for call target name ambiguity.
        """
        caller, callee = self.codegen._func, self.current_callee_func

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
        callee_func = self.current_callee_func
        if callee_func is not None:
            if (
                callee_func.demangled_name
                and callee_func.demangled_name != callee_func.name
                and self.show_demangled_name
            ):
                func_name = get_cpp_function_name(callee_func.demangled_name)
            else:
                func_name = c_identifier(callee_func.get_declaration_name())
            if (
                self.prettify_thiscall
                and self.args
                and self._is_func_likely_method(func_name, callee_func.is_rust_function())
            ):
                func_name = callee_func.short_name
                yield from self._c_repr_chunks_thiscall(func_name)
                return
            if self.show_disambiguated_name and self._is_target_ambiguous(func_name):
                func_name = callee_func.get_unambiguous_name(display_name=func_name)

            callee_prototype = callee_func.prototype
            if callee_prototype is not None and callee_func.prototype_libname is not None:
                callee_prototype = cast(
                    SimTypeFunction,
                    dereference_simtype_by_lib(callee_prototype, callee_func.prototype_libname),
                )
            if (
                self.callsite_prototype is not None
                and callee_prototype is not None
                and not type_equals(self.callsite_prototype, callee_prototype)
            ):
                # The declaration describes the callee globally, while the call-site prototype describes the ABI
                # observed at this edge. Calling through the explicit function-pointer type keeps independently
                # recovered signatures representable C and makes the disagreement visible in the output.
                function_pointer_type = SimTypePointer(self.callsite_prototype).with_arch(self.codegen.project.arch)
                yield "((", None
                yield function_pointer_type.c_repr(name=None), function_pointer_type
                yield ")", None
                yield func_name, self
                yield ")", None
            else:
                yield func_name, self
        elif isinstance(self.callee_target, str):
            yield self.callee_target, self
        elif isinstance(self.callee_target, CDirtyExpression):
            # The call target is an opaque intrinsic/syscall placeholder (e.g. __debugbreak,
            # syscall). Render just its name; the parentheses + args are emitted below. This
            # also guarantees the internal "[D] ..." marker never reaches the output.
            name = self.callee_target.intrinsic_name()
            yield (name if name is not None else "/* unsupported call */"), self
        else:
            chunks = list(CExpression._try_c_repr_chunks(self.callee_target))
            target_type = unpack_typeref(getattr(self.callee_target, "type", None))
            target_is_function_pointer = isinstance(target_type, SimTypePointer) and isinstance(
                unpack_typeref(target_type.pts_to), SimTypeFunction
            )
            if target_is_function_pointer:
                if isinstance(self.callee_target, (CUnaryOp, CBinaryOp)):
                    yield "(", None
                yield from chunks
                if isinstance(self.callee_target, (CUnaryOp, CBinaryOp)):
                    yield ")", None
            else:
                # AIL represents a raw CALLIND target as an integer expression. Calling that expression directly
                # produces invalid C (``integer_expression()``). Preserve the call-site ABI by making the
                # implementation-defined integer-to-function-pointer conversion explicit.
                prototype = self.prototype
                assert prototype is not None
                function_pointer_type = SimTypePointer(prototype).with_arch(self.codegen.project.arch)
                yield "((", None
                yield function_pointer_type.c_repr(name=None), function_pointer_type
                yield ")(", None
                yield from chunks
                yield "))", None

        paren = CClosingObject("(")
        yield "(", paren

        for i, arg in enumerate(self.args):
            if i:
                yield ", ", None
            yield from CExpression._try_c_repr_chunks(arg)

        yield ")", paren

    def _c_repr_chunks_thiscall(self, func_name: str):
        # The first argument is the `this` pointer
        assert self.args
        this_ref = self.args[0]
        if isinstance(this_ref, CUnaryOp) and this_ref.op == "Reference":
            yield from CExpression._try_c_repr_chunks(this_ref.operand)
        else:
            yield from CExpression._try_c_repr_chunks(this_ref)

        if func_name != "<ctor>":
            yield ".", None
            yield func_name, self

        # the remaining arguments
        paren = CClosingObject("(")
        yield "(", paren

        for i, arg in enumerate(self.args):
            if i == 0:
                continue
            if i > 1:
                yield ", ", None
            yield from CExpression._try_c_repr_chunks(arg)

        yield ")", paren


class CReturn(CStatement):
    __slots__ = ("retval",)

    def __init__(self, retval, **kwargs):
        super().__init__(**kwargs)

        return_type = self.codegen._func.prototype.returnty if self.codegen._func.prototype is not None else None
        if return_type is not None and self.codegen._func.prototype_libname is not None:
            return_type = dereference_simtype_by_lib(return_type, self.codegen._func.prototype_libname)
        self.retval = _coerce_scalar_expression(retval, return_type, self.codegen) if retval is not None else None

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        if not self.retval:
            yield indent_str, None
            yield "return;\n", self
        else:
            yield indent_str, None
            yield "return ", self
            yield from self.retval.c_repr_chunks()
            yield ";\n", self


class CGoto(CStatement):
    __slots__ = (
        "target",
        "target_idx",
    )

    def __init__(self, target, target_idx, **kwargs):
        super().__init__(**kwargs)

        if isinstance(target, CConstant) and isinstance(target.value, int):
            # unpack target
            target = target.value

        self.target: int | CExpression = target
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
                yield from self.target.c_repr_chunks()
        else:
            yield lbl.name, lbl
        yield ";", self
        if self.codegen.comment_gotos:
            yield " */", None
        yield "\n", None


class CUnsupportedStatement(CStatement):
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
        # AIL is not C. In particular, stringifying an unsupported expression can emit
        # internal node representations that look like source but cannot compile. Keep
        # the original statement on this node for structured diagnostics/serialization,
        # but make the textual fallback inert and deterministic.
        yield "/* unsupported AIL statement; see structured diagnostics */", self
        yield "\n", None


class CDirtyStatement(CExpression):
    __slots__ = ("dirty",)

    def __init__(self, dirty: CDirtyExpression, **kwargs):
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


class CLabel(CStatement):
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


class CStructField(CExpression):
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


class CFakeVariable(CExpression):
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


class CVariable(CExpression):
    """
    CVariable represents access to a variable with the specified type (`variable_type`).

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
        # A VirtualVariable denotes a value access of an exact AIL width. Its
        # backing declaration can be widened, narrowed, or changed to an array
        # when later decompilations refine the unified variable. Keep the type
        # of this particular access stable; c_repr_chunks() supplies the typed
        # lvalue view required by the final declaration.
        if self.tags.get(_EXACT_STORAGE_ACCESS_TAG, False) and self.variable_type is not None:
            return self.variable_type
        if self.codegen is not None and self.codegen.cfunc is not None:
            return self.codegen.cfunc.declaration_type(self)
        return self.variable_type

    @property
    def name(self):
        if self.codegen is not None and self.codegen.cfunc is not None:
            argument_name = self.codegen.cfunc.argument_name(self)
            if argument_name is not None:
                return argument_name
            v = self.codegen.cfunc.resolved_variable(self)
        else:
            v = self.variable if self.unified_variable is None else self.unified_variable
        return c_variable_identifier(v)

    def c_repr_chunks(self, indent=0, asexpr=False):
        access_type = self.variable_type if self.tags.get(_EXACT_STORAGE_ACCESS_TAG, False) else None
        offset = self.tags.get(_EXACT_STORAGE_OFFSET_TAG, 0)
        declaration_type = (
            self.codegen.cfunc.declaration_type(self)
            if access_type is not None and self.codegen is not None and self.codegen.cfunc is not None
            else None
        )
        if (
            access_type is not None
            and declaration_type is not None
            and type(offset) is int
            and (offset != 0 or not type_equals(access_type, declaration_type))
        ):
            # Render the exact AIL value through the final declaration's
            # storage. In particular, never allow a recovered byte array to
            # decay to a pointer where the AIL expression is a word value.
            # The result remains an lvalue, so the same representation is valid
            # on either side of an assignment.
            paren = CClosingObject("(")
            access_pointer_type = SimTypePointer(access_type).with_arch(self.codegen.project.arch)
            declaration_type = unpack_typeref(declaration_type)
            declaration_is_array = isinstance(declaration_type, (SimTypeArray, SimTypeFixedSizeArray))

            yield "*", self
            yield "(", paren
            yield "(", paren
            yield access_pointer_type.c_repr(name=None), access_pointer_type
            yield ")", paren
            if offset == 0:
                if not declaration_is_array:
                    yield "&", self
                yield self.name, self
            else:
                array_element_type = declaration_type.elem_type if declaration_is_array else None
                if array_element_type is not None and array_element_type.size == self.codegen.project.arch.byte_width:
                    yield "&", self
                    yield self.name, self
                    yield f"[{offset}]", self
                else:
                    yield "(", paren
                    yield "(char *)", None
                    if not declaration_is_array:
                        yield "&", self
                    yield self.name, self
                    yield f" + {offset}", self
                    yield ")", paren
            yield ")", paren
        else:
            yield self.name, self
        if self.codegen.display_vvar_ids:
            yield f"<vvar_{self.vvar_id}>", self


class CIndexedVariable(CExpression):
    """
    Represent a variable (an array) that is indexed.
    """

    def __init__(self, variable: CExpression, index: CExpression, variable_type=None, **kwargs):
        super().__init__(**kwargs)
        self.variable = variable
        self.index: CExpression = index
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

        bracket = CClosingObject("[")
        if not isinstance(self.variable, (CVariable, CVariableField)):
            yield "(", None
        yield from self.variable.c_repr_chunks()
        if not isinstance(self.variable, (CVariable, CVariableField)):
            yield ")", None
        yield "[", bracket
        yield from CExpression._try_c_repr_chunks(self.index)
        yield "]", bracket


class CVariableField(CExpression):
    """
    Represent a field of a variable.
    """

    def __init__(self, variable: CExpression, field: CStructField, var_is_ptr: bool = False, **kwargs):
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


class CUnaryOp(CExpression):
    """
    Unary operations.
    """

    __slots__ = (
        "op",
        "operand",
    )

    _OPERATION_HANDLERS = {
        "Not": "_c_repr_chunks_not",
        "Neg": "_c_repr_chunks_neg",
        "BitwiseNeg": "_c_repr_chunks_bitwiseneg",
        "Reference": "_c_repr_chunks_reference",
        "Dereference": "_c_repr_chunks_dereference",
        "Clz": "_c_repr_chunks_clz",
        "PopCount": "_c_repr_chunks_popcount",
        "Abs": "_c_repr_chunks_abs",
        "Sqrt": "_c_repr_chunks_sqrt",
        "IsNaN": "_c_repr_chunks_isnan",
        "Ceil": "_c_repr_chunks_ceil",
        "Floor": "_c_repr_chunks_floor",
        "Round": "_c_repr_chunks_round",
    }

    def __init__(self, op, operand: CExpression, **kwargs):
        super().__init__(**kwargs)

        self.op = op
        self.operand = operand

        if operand.type is not None:
            var_type = unpack_typeref(operand.type)
            if op == "IsNaN":
                self._type = SimTypeChar(signed=False).with_arch(self.codegen.project.arch)
            elif op == "Reference":
                self._type = SimTypePointer(var_type).with_arch(self.codegen.project.arch)
            elif op == "Dereference":
                if isinstance(var_type, SimTypePointer):
                    self._type = unpack_typeref(var_type.pts_to)
                elif isinstance(var_type, (SimTypeArray, SimTypeFixedSizeArray)):
                    self._type = unpack_typeref(var_type.elem_type)

    @property
    def type(self):
        operand_type = self.operand.type if self.operand is not None and hasattr(self.operand, "type") else None
        if operand_type is not None:
            operand_type = unpack_typeref(operand_type)
            if self.op == "Reference":
                return SimTypePointer(operand_type).with_arch(self.codegen.project.arch)
            if self.op == "Dereference":
                if isinstance(operand_type, SimTypePointer):
                    return unpack_typeref(operand_type.pts_to)
                if isinstance(operand_type, (SimTypeArray, SimTypeFixedSizeArray)):
                    return unpack_typeref(operand_type.elem_type)
        if self._type is None:
            self._type = operand_type
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return

        handler_name = self._OPERATION_HANDLERS.get(self.op)
        if handler_name is not None:
            yield from getattr(self, handler_name)()
        else:
            yield f"UnaryOp {self.op}", self

    #
    # Handlers
    #

    def _c_repr_chunks_not(self):
        paren = CClosingObject("(")
        yield "!", self
        yield "(", paren
        yield from CExpression._try_c_repr_chunks(self.operand)
        yield ")", paren

    def _c_repr_chunks_bitwiseneg(self):
        paren = CClosingObject("(")
        yield "~", self
        yield "(", paren
        yield from CExpression._try_c_repr_chunks(self.operand)
        yield ")", paren

    def _c_repr_chunks_neg(self):
        paren = CClosingObject("(")
        yield "-", self
        yield "(", paren
        yield from CExpression._try_c_repr_chunks(self.operand)
        yield ")", paren

    def _c_repr_chunks_reference(self):
        if isinstance(self.operand, CTypeCast):
            # A cast expression is not an lvalue, so ``&(T)value`` is invalid C. AIL uses this shape to take a
            # typed view of an underlying storage location; take that location's address first and cast the pointer.
            paren = CClosingObject("(")
            pointer_type = SimTypePointer(self.operand.dst_type).with_arch(self.codegen.project.arch)
            yield "(", paren
            yield pointer_type.c_repr(name=None), pointer_type
            yield ")", paren
            yield "&", self
            yield from CExpression._try_c_repr_chunks(self.operand.expr)
            return

        # C array-to-pointer decay: an array-typed lvalue already decays to a pointer to its first
        # element, so "&array" is redundant.
        operand_type = self.operand.type if self.operand is not None else None
        if operand_type is not None and isinstance(unpack_typeref(operand_type), SimTypeArray):
            yield from CExpression._try_c_repr_chunks(self.operand)
            return
        yield "&", self
        yield from CExpression._try_c_repr_chunks(self.operand)

    def _c_repr_chunks_dereference(self):
        paren = CClosingObject("(")
        yield "*", self
        yield "(", paren
        yield from CExpression._try_c_repr_chunks(self.operand)
        yield ")", paren

    def _c_repr_chunks_clz(self):
        paren = CClosingObject("(")
        yield "Clz", self
        yield "(", paren
        yield from CExpression._try_c_repr_chunks(self.operand)
        yield ")", paren

    def _c_repr_chunks_popcount(self):
        operand_bits = getattr(getattr(self.operand, "type", None), "size", None)
        if operand_bits is not None and operand_bits <= 8:
            cast_type = "unsigned char"
            intrinsic = "__builtin_popcount"
        elif operand_bits is not None and operand_bits <= 16:
            cast_type = "unsigned short"
            intrinsic = "__builtin_popcount"
        elif operand_bits is not None and operand_bits <= 32:
            cast_type = "unsigned int"
            intrinsic = "__builtin_popcount"
        else:
            cast_type = "unsigned long long"
            intrinsic = "__builtin_popcountll"

        paren = CClosingObject("(")
        cast_paren = CClosingObject("(")
        yield intrinsic, self
        yield "(", paren
        yield f"({cast_type})", cast_paren
        yield "(", cast_paren
        yield from CExpression._try_c_repr_chunks(self.operand)
        yield ")", cast_paren
        yield ")", paren

    def _c_repr_chunks_math_call(self, base_name: str):
        operand_type = unpack_typeref(self.operand.type) if self.operand.type is not None else None
        if isinstance(operand_type, SimTypeFloat80):
            function_name = f"{base_name}l"
        elif isinstance(operand_type, SimTypeDouble):
            function_name = base_name
        elif isinstance(operand_type, SimTypeFloat):
            function_name = f"{base_name}f"
        else:
            function_name = base_name
        paren = CClosingObject("(")
        yield function_name, self
        yield "(", paren
        yield from CExpression._try_c_repr_chunks(self.operand)
        yield ")", paren

    def _c_repr_chunks_abs(self):
        yield from self._c_repr_chunks_math_call("fabs")

    def _c_repr_chunks_sqrt(self):
        yield from self._c_repr_chunks_math_call("sqrt")

    def _c_repr_chunks_isnan(self):
        paren = CClosingObject("(")
        yield "isnan", self
        yield "(", paren
        yield from CExpression._try_c_repr_chunks(self.operand)
        yield ")", paren

    def _c_repr_chunks_ceil(self):
        yield from self._c_repr_chunks_math_call("ceil")

    def _c_repr_chunks_floor(self):
        yield from self._c_repr_chunks_math_call("floor")

    def _c_repr_chunks_round(self):
        yield from self._c_repr_chunks_math_call("round")


class CBinaryOp(CExpression):
    """
    Binary operations.
    """

    __slots__ = ("_cstyle_null_cmp", "common_type", "lhs", "op", "rhs")

    _OPERATION_HANDLERS = {
        "Add": "_c_repr_chunks_add",
        "Sub": "_c_repr_chunks_sub",
        "Mul": "_c_repr_chunks_mul",
        "Mull": "_c_repr_chunks_mull",
        "Div": "_c_repr_chunks_div",
        "Mod": "_c_repr_chunks_mod",
        "And": "_c_repr_chunks_and",
        "Xor": "_c_repr_chunks_xor",
        "Or": "_c_repr_chunks_or",
        "Shr": "_c_repr_chunks_shr",
        "Shl": "_c_repr_chunks_shl",
        "Sar": "_c_repr_chunks_sar",
        "LogicalAnd": "_c_repr_chunks_logicaland",
        "LogicalOr": "_c_repr_chunks_logicalor",
        "LogicalXor": "_c_repr_chunks_logicalxor",
        "CmpLE": "_c_repr_chunks_cmple",
        "CmpLEs": "_c_repr_chunks_cmple",
        "CmpLT": "_c_repr_chunks_cmplt",
        "CmpLTs": "_c_repr_chunks_cmplt",
        "CmpGT": "_c_repr_chunks_cmpgt",
        "CmpGTs": "_c_repr_chunks_cmpgt",
        "CmpGE": "_c_repr_chunks_cmpge",
        "CmpGEs": "_c_repr_chunks_cmpge",
        "CmpEQ": "_c_repr_chunks_cmpeq",
        "CmpNE": "_c_repr_chunks_cmpne",
        "Concat": "_c_repr_chunks_concat",
        "Rol": "_c_repr_chunks_rol",
        "Ror": "_c_repr_chunks_ror",
    }

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

        handler_name = self._OPERATION_HANDLERS.get(self.op)
        if handler_name is not None:
            yield from getattr(self, handler_name)()
        else:
            yield from self._c_repr_chunks_opfirst(self.op)

    def _has_const_null_rhs(self) -> bool:
        return isinstance(self.rhs, CConstant) and self.rhs.value == 0

    #
    # Handlers
    #

    def _c_repr_chunks(self, op):
        skip_op_and_rhs = False
        if self._cstyle_null_cmp and self._has_const_null_rhs():
            if self.op == "CmpEQ":
                skip_op_and_rhs = True
                yield "!", None
            elif self.op == "CmpNE":
                skip_op_and_rhs = True
        # lhs
        if isinstance(self.lhs, CBinaryOp) and self.op_precedence > self.lhs.op_precedence:
            paren = CClosingObject("(")
            yield "(", paren
            yield from self._try_c_repr_chunks(self.lhs)
            yield ")", paren
        else:
            yield from self._try_c_repr_chunks(self.lhs)

        if not skip_op_and_rhs:
            # operator
            yield op, self
            # rhs
            if isinstance(self.rhs, CBinaryOp) and self.op_precedence > self.rhs.op_precedence - (
                1 if self.op in ["Sub", "Div"] else 0
            ):
                paren = CClosingObject("(")
                yield "(", paren
                yield from self._try_c_repr_chunks(self.rhs)
                yield ")", paren
            else:
                yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_opfirst(self, op):
        yield op, self
        paren = CClosingObject("(")
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
            paren = CClosingObject("(")
            yield "(", paren
            yield f"{signed_ty.c_repr(name=None)}", signed_ty
            yield ")", paren
            yield "(", paren
            yield from self._try_c_repr_chunks(self.lhs)
            yield ")", paren
            yield " >> ", self
            if isinstance(self.rhs, CBinaryOp) and self.op_precedence > self.rhs.op_precedence:
                paren2 = CClosingObject("(")
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
        yield from self._c_repr_chunks(" == ")

    def _c_repr_chunks_cmpne(self):
        yield from self._c_repr_chunks(" != ")

    def _c_repr_chunks_concat(self):
        yield from self._c_repr_chunks(" CONCAT ")

    def _c_repr_chunks_rol(self):
        yield "__ROL__", self
        paren = CClosingObject("(")
        yield "(", paren
        yield from self._try_c_repr_chunks(self.lhs)
        yield ", ", None
        yield from self._try_c_repr_chunks(self.rhs)
        yield ")", paren

    def _c_repr_chunks_ror(self):
        yield "__ROR__", self
        paren = CClosingObject("(")
        yield "(", paren
        yield from self._try_c_repr_chunks(self.lhs)
        yield ", ", None
        yield from self._try_c_repr_chunks(self.rhs)
        yield ")", paren


class CTypeCast(CExpression):
    __slots__ = (
        "dst_type",
        "expr",
        "src_type",
    )

    def __init__(self, src_type: SimType | None, dst_type: SimType, expr: CExpression, **kwargs):
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
        paren = CClosingObject("(")
        if self.codegen.show_casts:
            yield "(", paren
            yield f"{self.dst_type.c_repr(name=None)}", self.dst_type
            yield ")", paren

        if isinstance(self.expr, CBinaryOp):
            wrapping_paren = True
            yield "(", paren
        else:
            wrapping_paren = False
        yield from CExpression._try_c_repr_chunks(self.expr)
        if wrapping_paren:
            yield ")", paren


class CConstant(CExpression):
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
        def _memory_data_is_readonly(v: MemoryData) -> bool:
            return is_in_readonly_segment(self.codegen.project, v.addr) or is_in_readonly_section(
                self.codegen.project, v.addr
            )

        def _default_output(v) -> str | None:
            if (
                isinstance(v, MemoryData)
                and v.sort == MemoryDataSort.String
                and v.content is not None
                and _memory_data_is_readonly(v)
            ):
                return CConstant.str_to_c_str(v.content.decode("utf-8"), maxlen=self.codegen.max_str_len)
            if isinstance(v, Function):
                if v.demangled_name and v.demangled_name != v.name:
                    return get_cpp_function_name(v.demangled_name)
                return c_identifier(v.get_declaration_name())
            if isinstance(v, str):
                return CConstant.str_to_c_str(v, maxlen=self.codegen.max_str_len)
            if isinstance(v, bytes):
                return CConstant.str_to_c_str(v.replace(b"\x00", b"").decode("utf-8"), maxlen=self.codegen.max_str_len)
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
                        if not _memory_data_is_readonly(refval):
                            refval = None
                        else:
                            v = refval.content.decode("utf-8") if refval.content else f"<unknown@{refval.addr:#x}>"
                    elif isinstance(refval, bytes):
                        v = refval.decode("latin1")
                    else:
                        # it must be a string
                        v = refval
                        assert isinstance(v, str)
                    if refval is not None:
                        yield CConstant.str_to_c_str(v, maxlen=self.codegen.max_str_len), self
                        return

                if isinstance(self._type, SimTypePointer) and isinstance(self._type.pts_to, SimTypeWideChar):
                    refval = self.reference_values[self._type]
                    if isinstance(refval, MemoryData):
                        if not _memory_data_is_readonly(refval):
                            refval = None
                        else:
                            v = decode_utf16_string(refval.content) if refval.content else f"<unknown@{refval.addr:#x}>"
                    elif isinstance(refval, bytes):
                        v = decode_utf16_string(refval) if refval else "<unknown_bytes>"
                    else:
                        assert False, f"Unexpected reference value type {type(refval)} for wide char pointer"
                    if refval is not None:
                        yield CConstant.str_to_c_str(v, prefix="L", maxlen=self.codegen.max_str_len), self
                        return

                if isinstance(self.reference_values[self._type], int):
                    yield self.fmt_int(self.reference_values[self._type]), self
                    return
                o = _default_output(self.reference_values[self.type])
                if o is not None:
                    yield o, self
                    return

            # default priority: string references -> variables -> other reference values
            for v in self.reference_values.values():
                o = _default_output(v)
                if o is not None:
                    yield o, self
                    return

        if isinstance(self.value, int) and self.value == 0 and isinstance(self.type, SimTypePointer):
            # print NULL instead
            yield "NULL", self

        elif isinstance(self._type, SimTypePointer) and isinstance(self.value, int):
            # A nonzero integer is not an implicit C null-pointer constant.
            # Keep the recovered machine address valid at every use site,
            # including assignments and prototype-checked call arguments.
            paren = CClosingObject("(")
            yield "(", paren
            yield self._type.c_repr(name=None), self._type
            yield ")", paren
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


class CRegister(CExpression):
    __slots__ = ("reg",)

    def __init__(self, reg, **kwargs):
        super().__init__(**kwargs)

        self.reg = reg

    @property
    def type(self):
        return self._type or SimTypeInt().with_arch(self.codegen.project.arch)

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield str(self.reg), None


class CITE(CExpression):
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
        paren = CClosingObject("(")
        yield "(", paren
        yield from self.cond.c_repr_chunks()
        yield " ? ", self
        yield from self.iftrue.c_repr_chunks()
        yield " : ", self
        yield from self.iffalse.c_repr_chunks()
        yield ")", paren


class CMultiStatementExpression(CExpression):
    """
    (stmt0, stmt1, stmt2, expr)
    """

    __slots__ = (
        "expr",
        "stmts",
    )

    def __init__(self, stmts: CStatements, expr: CExpression, **kwargs):
        super().__init__(**kwargs)
        self.stmts = stmts
        self.expr = expr

    @property
    def type(self):
        return self.expr.type

    def c_repr_chunks(self, indent=0, asexpr=False):
        paren = CClosingObject("(")
        yield "(", paren
        yield from self.stmts.c_repr_chunks(indent=0, asexpr=True)
        if self.stmts.statements:
            yield ", ", None
        yield from self.expr.c_repr_chunks()
        yield ")", paren


class CVEXCCallExpression(CExpression):
    """
    ccall_name(arg0, arg1, ...)
    """

    __slots__ = (
        "callee",
        "operands",
    )

    def __init__(self, callee: str, operands: list[CExpression], **kwargs):
        super().__init__(**kwargs)
        self.callee = callee
        self.operands = operands

    @property
    def type(self):
        return SimTypeInt().with_arch(self.codegen.project.arch)

    def c_repr_chunks(self, indent=0, asexpr=False):
        paren = CClosingObject("(")
        yield f"{self.callee}", self
        yield "(", paren
        for idx, operand in enumerate(self.operands):
            if idx != 0:
                yield ", ", None
            yield from operand.c_repr_chunks()
        yield ")", paren


class CReinterpret(CExpression):
    """A width-preserving bit reinterpretation rendered through the PBR compatibility ABI."""

    __slots__ = ("expr", "from_bits", "from_type", "to_bits", "to_type")

    def __init__(self, from_bits, from_type, to_bits, to_type, expr, dst_type, **kwargs):
        super().__init__(**kwargs)
        self.from_bits = from_bits
        self.from_type = from_type
        self.to_bits = to_bits
        self.to_type = to_type
        self.expr = expr
        self._type = dst_type

    @property
    def type(self):
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.from_bits != self.to_bits or {self.from_type, self.to_type} != {"I", "F"}:
            yield "/* unsupported reinterpret */", self
            return
        direction = "from_bits" if self.from_type == "I" else "to_bits"
        paren = CClosingObject("(")
        yield f"pbr_f{self.to_bits}_{direction}", self
        yield "(", paren
        yield from CExpression._try_c_repr_chunks(self.expr)
        yield ")", paren


class CDirtyExpression(CExpression):
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


class CClosingObject:
    """
    A class to represent all objects that can be closed by it's correspodning character.
    Examples: (), {}, []
    """

    __slots__ = ("opening_symbol",)

    def __init__(self, opening_symbol):
        self.opening_symbol = opening_symbol


class CArrayTypeLength:
    """
    A class to represent the type information of fixed-size array lengths.
    Examples: In "char foo[20]", this would be the "[20]".
    """

    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text


class CStructFieldNameDef:
    """A class to represent the name of a defined field in a struct.
    Needed because it's not a CVariable or a CStructField (because
    CStructField is the access of a CStructField).
    Example: In "struct foo { int bar; }, this would be "bar".
    """

    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name


class CStructuredCodeGenerator(BaseStructuredCodeGenerator, Analysis, Serializable):
    def __init__(
        self,
        func,
        sequence,
        indent=0,
        cfg=None,
        func_args: list[SimVariable] | None = None,
        binop_depth_cutoff: int = 16,
        show_casts=True,
        braces_on_own_lines=True,
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
        register_state_bindings: RegisterStateBindings = (),
        segmented_memory_bindings: SegmentedMemoryBindings = (),
        far_call_bindings: FarCallBindings = (),
        converted_pointer_bindings: ConvertedPointerBindings = (),
        stack_pointer_tracker=None,
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
            Expr.SegmentedAddress: self._handle_Expr_SegmentedAddress,
            Expr.VEXCCallExpression: self._handle_Expr_VEXCCallExpression,
            Expr.DirtyExpression: self._handle_Expr_Dirty,
            Expr.ITE: self._handle_Expr_ITE,
            Expr.Call: self._handle_Expr_Call,
            Expr.Reinterpret: self._handle_Reinterpret,
            Expr.MultiStatementExpression: self._handle_MultiStatementExpression,
            Expr.VirtualVariable: self._handle_VirtualVariable,
        }

        self._func = func
        self._func_args = func_args
        self._cfg = cfg
        self._sequence = sequence
        self._variable_map: VariableMap = variable_map if variable_map is not None else VariableMap()
        self._register_state_bindings = register_state_binding_map(register_state_bindings)
        self._segmented_memory_bindings = segmented_memory_binding_map(segmented_memory_bindings)
        self._far_call_bindings: FarCallBindingMap = far_call_binding_map(far_call_bindings)
        self._converted_pointer_bindings: ConvertedPointerBindingMap = converted_pointer_binding_map(
            converted_pointer_bindings
        )
        self._stack_pointer_tracker = stack_pointer_tracker
        self.binop_depth_cutoff = binop_depth_cutoff

        self._variables_in_use: dict | None = None
        self._inlined_strings: set[SimMemoryVariable] = set()
        self._function_pointers: set[SimMemoryVariable] = set()
        self.ailexpr2cnode: dict[tuple[Expr.Expression, bool], CExpression] | None = None
        self.cnode2ailexpr: dict[CExpression, Expr.Expression] | None = None
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
        self.map_addr_to_label: dict[tuple[int, int | None], CLabel] = {}
        self.cfunc: CFunction | None = None
        self.cexterns: set[CVariable] | None = None
        self.display_notes = display_notes
        self.max_str_len = max_str_len
        self.prettify_thiscall = prettify_thiscall
        self.cstyle_void_param = cstyle_void_param
        # Number of space characters per indentation level in the emitted pseudocode.
        self.indent_delta = indent_size

        self._analyze()

    @property
    def unsupported_constructs(self) -> tuple[UnsupportedConstruct, ...]:
        """
        Unsupported AIL constructs that survived into this structured C result.

        Records are aggregated by construct kind and operation, sorted deterministically, and include the best source
        coordinates retained by AIL. The property is derived from the C AST, so it is also available on deserialized
        code-generation results.
        """
        if self.cfunc is None:
            return ()
        collector = _UnsupportedConstructCollector()
        collector.handle(self.cfunc)
        return collector.result

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
        # Storage objects proven to carry addresses of native C stack objects.
        # This is deliberately data-flow evidence, not a type-based guess: a
        # pointer-shaped 16-bit value may still be an ordinary guest offset.
        self._native_stack_pointer_carriers: set[SimStackVariable] = set()
        self._native_stack_pointer_provenance: dict[SimStackVariable, int] = {}
        self._selector_carriers: dict[SimStackVariable, tuple[int, int]] = {}
        self._native_stack_frames: dict[tuple[int, int], SimStackVariable] = {}
        self._all_cvariables: list[CVariable] = []

        # Structuring may clone a labeled block into more than one branch. C labels have function scope, so retain
        # one canonical declaration for every AIL label name and map every cloned target to that declaration.
        self._labels_by_name: dict[str, CLabel] = {}

        # memo
        self.ailexpr2cnode = {}

        arg_list = [self._variable(arg, None) for arg in self._func_args] if self._func_args else []

        self.reset_ident_counters()
        obj = self._handle(self._sequence)

        # A frame may be discovered midway through the structured sequence. Reapply the final interval mapping after
        # every occurrence has been built so later accesses and AST-cleanup copies use the same aliasing identity.
        for cvar in self._all_cvariables:
            self._apply_native_stack_frame_to_cvariable(cvar)

        self.cnode2ailexpr = {v: k[0] for k, v in self.ailexpr2cnode.items()}

        self.cfunc = CFunction(
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

    def render_text(self, cfunc: CFunction) -> RenderResult:
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
            if isinstance(node.obj, CConstant):
                ast_to_pos[node.obj.value].add(elem)
            elif isinstance(node.obj, CVariable):
                if node.obj.unified_variable is not None:
                    ast_to_pos[node.obj.unified_variable].add(elem)
                else:
                    ast_to_pos[node.obj.variable].add(elem)
            elif isinstance(node.obj, SimType):
                ast_to_pos[node.obj].add(elem)
            elif isinstance(node.obj, CFunctionCall):
                callee_func = node.obj.current_callee_func
                if callee_func is not None:
                    ast_to_pos[callee_func].add(elem)
                else:
                    ast_to_pos[node.obj.callee_target].add(elem)
            elif isinstance(node.obj, CStructField):
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
                if isinstance(var, CVariable):
                    # Exact VirtualVariable accesses carry their own AIL value
                    # type. The declaration is refreshed independently by
                    # CFunction.refresh(); overwriting the occurrence type here
                    # would turn array-backed scalar reads into array decay.
                    if var.tags.get(_EXACT_STORAGE_ACCESS_TAG, False):
                        continue
                    var.variable_type = self._get_variable_type(
                        var.variable,
                        is_global=isinstance(var.variable, SimMemoryVariable)
                        and not isinstance(var.variable, SimStackVariable),
                    )

        if self.cexterns is not None:
            for var in self.cexterns:
                if isinstance(var, CVariable):
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
            # Call arguments were coerced when the retained C AST was built, but whole-program type recovery may
            # change a variable's rendered declaration before final emission. Refresh the declaration view first,
            # then reapply only the conversions required by each call's exact edge/callee prototype.
            self.cfunc.refresh()
            _ReapplyCallArgumentCoercions().handle(self.cfunc)

    def reload_function_metadata(self, function: Function | None = None) -> None:
        """
        Refresh metadata for the function represented by this code generator.

        Decompilation can refine or replace a ``Function`` object after this C AST was constructed. Keep the AST and
        its recovered local-variable identities, but make subsequent renders use the current function name,
        demangled name, prototype, and function attributes.

        :param function: The current function object. If omitted, resolve it from the knowledge base by address.
        :raises ValueError: If the function is missing, has a different address, or has no prototype.
        """

        if function is None:
            function = self.kb.functions.function(addr=self._func.addr)
        if function is None:
            raise ValueError(f"Function {self._func.addr:#x} is no longer present in the knowledge base")
        if function.addr != self._func.addr:
            raise ValueError(
                f"Cannot reload function metadata for {function.addr:#x} into code generated for {self._func.addr:#x}"
            )
        if function.prototype is None:
            raise ValueError(f"Function {function.addr:#x} has no prototype")

        self._func = function
        if self.cfunc is not None:
            self.cfunc.addr = function.addr
            self.cfunc.name = function.name
            self.cfunc.demangled_name = function.demangled_name
            self.cfunc.functy = function.prototype
            self.cfunc.refresh()

    #
    # Util methods
    #

    def default_simtype_from_bits(self, n: int, signed: bool = True) -> SimType:
        candidates = {
            64: (SimTypeLongLong, SimTypeLong),
            32: (SimTypeInt, SimTypeLong),
            16: (SimTypeShort, SimTypeInt),
            8: (SimTypeChar,),
        }
        for simtype in candidates.get(n, ()):
            candidate = simtype(signed=signed).with_arch(self.project.arch)
            if candidate.size == n:
                return candidate
        return SimTypeNum(n, signed=signed).with_arch(self.project.arch)

    def float_simtype_from_bits(self, n: int) -> SimType:
        if n == 32:
            return SimTypeFloat().with_arch(self.project.arch)
        if n == 64:
            return SimTypeDouble().with_arch(self.project.arch)
        if n == 80:
            return SimTypeFloat80().with_arch(self.project.arch)
        raise UnsupportedNodeTypeError(f"Unsupported floating-point width {n}.")

    def _variable(
        self, variable: SimVariable, fallback_type_size: int | None, vvar_id: int | None = None, mark_used: bool = True
    ) -> CVariable:
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
        cvar = CVariable(variable, unified_variable=unified, variable_type=variable_type, codegen=self, vvar_id=vvar_id)
        all_cvariables = getattr(self, "_all_cvariables", None)
        if all_cvariables is not None:
            all_cvariables.append(cvar)
        self._apply_native_stack_frame_to_cvariable(cvar)
        if mark_used:
            previous = self._variables_in_use.get(variable)
            if previous is not None and _INITIAL_REGISTER_STATE_SEED_TAG in previous.tags:
                cvar.tags[_INITIAL_REGISTER_STATE_SEED_TAG] = previous.tags[_INITIAL_REGISTER_STATE_SEED_TAG]
            self._variables_in_use[variable] = cvar
        return cvar

    def _cvariable_stack_interval(self, cvar: CVariable) -> tuple[int, int] | None:
        variable = cvar.variable
        if not isinstance(variable, SimStackVariable) or variable.base != "bp" or type(variable.offset) is not int:
            return None
        absolute_start = cvar.tags.get(_NATIVE_STACK_ABSOLUTE_OFFSET_TAG)
        if type(absolute_start) is not int:
            access_offset = cvar.tags.get(_EXACT_STORAGE_OFFSET_TAG, 0)
            if type(access_offset) is not int:
                return None
            absolute_start = variable.offset + access_offset
        access_type = cvar.variable_type if cvar.tags.get(_EXACT_STORAGE_ACCESS_TAG, False) else None
        access_bits = _safe_type_size(unpack_typeref(access_type)) if access_type is not None else -1
        if access_bits > 0 and access_bits % self.project.arch.byte_width == 0:
            size = access_bits // self.project.arch.byte_width
        else:
            size = variable.size
        if type(size) is not int or size <= 0:
            return None
        return absolute_start, absolute_start + size

    def _apply_native_stack_frame_to_cvariable(self, cvar: CVariable) -> None:
        interval = self._cvariable_stack_interval(cvar)
        if interval is None:
            return
        start, end = interval
        frames = getattr(self, "_native_stack_frames", {})
        matches = [
            (frame_start, span, frame)
            for (frame_start, span), frame in frames.items()
            if frame_start <= start and end <= frame_start + span
        ]
        if len(matches) != 1:
            return
        frame_start, _span, frame = matches[0]
        cvar.unified_variable = frame
        cvar.tags = {
            **cvar.tags,
            _EXACT_STORAGE_ACCESS_TAG: True,
            _EXACT_STORAGE_OFFSET_TAG: start - frame_start,
            _NATIVE_STACK_ABSOLUTE_OFFSET_TAG: start,
        }

    def _stack_variable_intervals(self) -> list[tuple[int, int, SimStackVariable]]:
        variable_manager = self.kb.dec_variables[self._func.addr]
        candidates = list(variable_manager.get_variables("stack"))
        candidates.extend(variable_manager.get_unified_variables("stack"))
        candidates.extend(
            cvar.variable
            for cvar in getattr(self, "_all_cvariables", ())
            if isinstance(cvar.variable, SimStackVariable)
        )
        unique: dict[tuple[int, int, str, str | int | None], SimStackVariable] = {}
        for variable in candidates:
            if variable.base != "bp" or type(variable.offset) is not int or type(variable.size) is not int:
                continue
            if variable.size <= 0:
                continue
            unique[(variable.offset, variable.size, variable.ident or "", variable.region)] = variable
        return sorted(
            ((variable.offset, variable.offset + variable.size, variable) for variable in unique.values()),
            key=lambda row: (row[0], row[1], row[2].ident or ""),
        )

    def _stack_storage_evidence_intervals(self) -> list[tuple[int, int]]:
        intervals = [(start, end) for start, end, _ in self._stack_variable_intervals()]
        intervals.extend(
            interval
            for cvar in getattr(self, "_all_cvariables", ())
            if (interval := self._cvariable_stack_interval(cvar)) is not None
        )
        return sorted(set(intervals))

    def _function_argument_stack_intervals(self) -> tuple[tuple[int, int], ...]:
        intervals = []
        variable_manager = self.kb.dec_variables[self._func.addr]
        for variable in self._func_args or ():
            if not isinstance(variable, SimStackVariable):
                continue
            candidates = (variable, variable_manager.unified_variable(variable))
            for candidate in candidates:
                if (
                    isinstance(candidate, SimStackVariable)
                    and candidate.base == "bp"
                    and type(candidate.offset) is int
                    and type(candidate.size) is int
                    and candidate.size > 0
                ):
                    intervals.append((candidate.offset, candidate.offset + candidate.size))
        return tuple(sorted(set(intervals)))

    def _signed_arch_offset(self, value) -> int | None:
        if type(value) is not int:
            return None
        sign_bit = 1 << (self.project.arch.bits - 1)
        modulus = 1 << self.project.arch.bits
        return value - modulus if value & sign_bit else value

    def _proven_call_local_stack_interval(
        self,
        expr: Expr.Call,
        prototype: SimTypeFunction | None,
        target_func: Function | None,
    ) -> tuple[int, int] | None:
        """Prove the local allocation still live below BP at one call instruction.

        Stack-pointer tracking observes SP after the caller has materialized the
        outgoing arguments. Removing the exact ABI-described stack argument
        footprint yields the allocation floor before those temporary pushes;
        the tracked BP value is its exclusive ceiling. This proves allocated
        bytes without confusing adjacent outgoing argument slots with the
        address-taken object.
        """

        tracker = self._stack_pointer_tracker
        callsite = expr.tags.get("ins_addr")
        if tracker is None or prototype is None or type(callsite) is not int:
            return None
        cc = self._variable_map.calling_convention(expr)
        if cc is None and target_func is not None:
            cc = target_func.calling_convention
        if cc is None or self.project.arch.bp_offset is None:
            return None
        try:
            locations = cc.arg_locs(prototype)
        except (TypeError, ValueError, NotImplementedError):
            return None

        stack_ranges = []

        def collect(location) -> bool:
            if isinstance(location, SimStackArg):
                if type(location.stack_offset) is not int or type(location.size) is not int or location.size <= 0:
                    return False
                stack_ranges.append((location.stack_offset, location.stack_offset + location.size))
                return True
            if isinstance(location, SimComboArg):
                return all(collect(part) for part in location.locations)
            return True

        if not all(collect(location) for location in locations) or not stack_ranges:
            return None
        stack_argument_start = getattr(cc, "STACKARG_SP_DIFF", None)
        if type(stack_argument_start) is not int:
            return None
        stack_argument_end = max(end for _start, end in stack_ranges)
        if stack_argument_end < stack_argument_start:
            return None
        argument_bytes = stack_argument_end - stack_argument_start

        sp = self._signed_arch_offset(tracker.offset_before(callsite, self.project.arch.sp_offset))
        bp = self._signed_arch_offset(tracker.offset_before(callsite, self.project.arch.bp_offset))
        if sp is None or bp is None:
            return None
        allocation_floor = sp + argument_bytes
        if allocation_floor >= bp:
            return None
        return allocation_floor, bp

    def _install_native_stack_frame(
        self,
        start: int,
        span: int,
        allocated_interval: tuple[int, int] | None,
    ) -> SimStackVariable:
        end = start + span
        if start >= 0 or end > 0:
            raise _StructuredCodegenDiagnosticError(
                f"Converted native stack interval [{start}, {end}) is not wholly local stack storage",
                _CONVERTED_POINTER_FAILURE_KIND,
                "prove-local-stack-storage",
            )
        for argument_start, argument_end in self._function_argument_stack_intervals():
            if start < argument_end and argument_start < end:
                raise _StructuredCodegenDiagnosticError(
                    f"Converted native stack interval [{start}, {end}) overlaps function argument storage",
                    _CONVERTED_POINTER_FAILURE_KIND,
                    "reject-function-argument-storage",
                )
        if allocated_interval is None or not (allocated_interval[0] <= start and end <= allocated_interval[1]):
            raise _StructuredCodegenDiagnosticError(
                f"Required native stack interval [{start}, {end}) is not contained in a proven live local "
                f"allocation {allocated_interval!r}",
                _CONVERTED_POINTER_FAILURE_KIND,
                "prove-live-stack-allocation",
            )

        for frame_start, frame_span in getattr(self, "_native_stack_frames", {}):
            frame_end = frame_start + frame_span
            if (frame_start, frame_span) != (start, span) and start < frame_end and frame_start < end:
                raise _StructuredCodegenDiagnosticError(
                    "Converted native stack frames must be identical or disjoint",
                    _CONVERTED_POINTER_FAILURE_KIND,
                    "reject-overlapping-native-frames",
                )
        existing = getattr(self, "_native_stack_frames", {}).get((start, span))
        if existing is not None:
            return existing

        evidence = []
        for evidence_start, evidence_end in self._stack_storage_evidence_intervals():
            if evidence_start < end and start < evidence_end:
                if evidence_start < start or evidence_end > end:
                    raise _StructuredCodegenDiagnosticError(
                        f"Recovered stack storage [{evidence_start}, {evidence_end}) straddles converted interval "
                        f"[{start}, {end})",
                        _CONVERTED_POINTER_FAILURE_KIND,
                        "prove-stack-storage-alias-boundary",
                    )
                evidence.append((evidence_start, evidence_end))

        offset_name = f"m{-start:x}" if start < 0 else f"p{start:x}"
        frame = SimStackVariable(
            start,
            span,
            ident=f"converted_pointer_frame_{offset_name}_{span:x}",
            name=f"native_frame_{offset_name}_{span:x}",
            region=self._func.addr,
        )
        self._native_stack_frames[(start, span)] = frame
        for cvar in self._all_cvariables:
            self._apply_native_stack_frame_to_cvariable(cvar)

        byte_type = SimTypeChar(signed=False).with_arch(self.project.arch)
        frame_type = SimTypeArray(byte_type, span).with_arch(self.project.arch)
        frame_declaration = CVariable(
            frame,
            unified_variable=frame,
            variable_type=frame_type,
            tags={
                _EXACT_STORAGE_ACCESS_TAG: True,
                _EXACT_STORAGE_OFFSET_TAG: 0,
                _NATIVE_STACK_FRAME_ALIGNMENT_TAG: 16,
            },
            codegen=self,
        )
        self._all_cvariables.append(frame_declaration)
        self._variables_in_use[frame] = frame_declaration
        return frame

    def _get_variable_reference(self, cvar: CVariable) -> CExpression:
        """
        Return a reference to a CVariable instance with special handling of arrays and array pointers.

        :param cvar:    The CVariable object.
        :return:        A reference to a CVariable object.
        """

        if isinstance(cvar.type, (SimTypeArray, SimTypeFixedSizeArray)):
            return cvar
        if isinstance(cvar.type, SimTypePointer) and isinstance(
            cvar.type.pts_to, (SimTypeArray, SimTypeFixedSizeArray)
        ):
            return cvar
        return CUnaryOp("Reference", cvar, codegen=self)

    def _access_reference(self, expr: CExpression, data_type: SimType) -> CExpression:
        result = self._access(expr, data_type, True)
        if isinstance(result, CUnaryOp) and result.op == "Dereference":
            result = result.operand
        else:
            result = CUnaryOp("Reference", result, codegen=self)
        return result

    def _access_constant_offset_reference(
        self, expr: CExpression, offset: int, data_type: SimType | None
    ) -> CExpression:
        result = self._access_constant_offset(expr, offset, data_type or SimTypeBottom(), True)
        if isinstance(result, CTypeCast) and data_type is None:
            result = result.expr
        if isinstance(result, CUnaryOp) and result.op == "Dereference":
            result = result.operand
            if isinstance(result, CTypeCast) and data_type is None:
                result = result.expr
        else:
            result = CUnaryOp("Reference", result, codegen=self)
        return result

    def _access_constant_offset(
        self,
        expr: CExpression,
        offset: int,
        data_type: SimType,
        lvalue: bool,
        renegotiate_type: Callable[[SimType, SimType], SimType] = lambda old, proposed: old,
    ) -> CExpression:
        def _force_type_cast(src_type_: SimType, dst_type_: SimType, expr_: CExpression) -> CUnaryOp:
            src_type_ptr = SimTypePointer(src_type_).with_arch(self.project.arch)
            dst_type_ptr = SimTypePointer(dst_type_).with_arch(self.project.arch)
            return CUnaryOp(
                "Dereference",
                CTypeCast(
                    src_type_ptr,
                    dst_type_ptr,
                    CUnaryOp("Reference", expr_, codegen=self),
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
                raise TypeError("CStructuredCodeGenerator programming error: no type whatsoever for dereference")
            if offset:
                expr = CBinaryOp("Add", expr, CConstant(offset, SimTypeInt(), codegen=self), codegen=self)
            return CUnaryOp(
                "Dereference",
                CTypeCast(expr.type, SimTypePointer(data_type).with_arch(self.project.arch), expr, codegen=self),
                codegen=self,
            )

        base_expr = expr.operand if isinstance(expr, CUnaryOp) and expr.op == "Reference" else None

        if offset == 0:
            data_type = renegotiate_type(data_type, base_type)
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
                return CUnaryOp("Dereference", expr, codegen=self)

        stride = 1 if base_type.size is None else base_type.size // self.project.arch.byte_width or 1
        index, remainder = divmod(offset, stride)
        if index != 0:
            index = CConstant(index, SimTypeInt(), codegen=self)
            kernel = expr
            # create a CIndexedVariable indicating the index access
            if base_expr and isinstance(base_expr, CIndexedVariable):
                old_index = base_expr.index
                kernel = base_expr.variable
                if not isinstance(old_index, CConstant) or old_index.value != 0:
                    index = CBinaryOp("Add", old_index, index, codegen=self)
            result = CUnaryOp(
                "Reference", CIndexedVariable(kernel, index, variable_type=base_type, codegen=self), codegen=self
            )
            return self._access_constant_offset(result, remainder, data_type, lvalue, renegotiate_type)

        if isinstance(base_type, SimStruct) and base_type.offsets:
            # find the field that we're accessing
            field_name, field_offset = max(
                ((x, y) for x, y in base_type.offsets.items() if y <= remainder), key=lambda x: x[1]
            )
            field = CStructField(base_type, field_offset, field_name, codegen=self)
            if base_expr:
                result = CUnaryOp("Reference", CVariableField(base_expr, field, False, codegen=self), codegen=self)
            else:
                result = CUnaryOp("Reference", CVariableField(expr, field, True, codegen=self), codegen=self)
            return self._access_constant_offset(result, remainder - field_offset, data_type, lvalue, renegotiate_type)

        if isinstance(base_type, (SimTypeFixedSizeArray, SimTypeArray)):
            result = base_expr or expr  # death to C
            if isinstance(result, CIndexedVariable):
                # unpack indexed variable
                var = result.variable
                result = CUnaryOp(
                    "Reference",
                    CIndexedVariable(var, result.index, variable_type=base_type.elem_type, codegen=self),
                    codegen=self,
                )
            else:
                result = CUnaryOp(
                    "Reference",
                    CIndexedVariable(
                        result,
                        CConstant(0, SimTypeInt(), codegen=self),
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
                expr = CTypeCast(
                    expr.type, SimTypePointer(SimTypeChar()).with_arch(self.project.arch), expr, codegen=self
                )
            expr_with_offset = CBinaryOp("Add", expr, CConstant(remainder, SimTypeInt(), codegen=self), codegen=self)
            return CUnaryOp(
                "Dereference",
                CTypeCast(
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
            return CUnaryOp(
                "Dereference", CTypeCast(expr.type, SimTypePointer(data_type), expr, codegen=self), codegen=self
            )
        # otherwise, normal cast
        return CTypeCast(base_type, data_type, base_expr, codegen=self)

    def _access(
        self,
        expr: CExpression,
        data_type: SimType,
        lvalue: bool,
        renegotiate_type: Callable[[SimType, SimType], SimType] = lambda old, proposed: old,
    ) -> CExpression:
        # same rule as _access_constant_offset wrt pointer expressions
        data_type = unpack_typeref(data_type)
        # The enclosing arithmetic may have an integer type because BinaryOp rendering explicitly casts recovered
        # pointers before machine-width arithmetic. ``extract_terms`` deliberately peels those casts so a load/store
        # can still lower a byte offset to a struct field or array element. Falling back based only on ``expr.type``
        # would discard that recoverable pointer base and emit an opaque integer-address dereference.
        o_constant, o_terms = extract_terms(expr)

        def bail_out():
            if len(o_terms) == 0:
                # probably a plain integer, return as *(int_type*)expr
                return CUnaryOp(
                    "Dereference", CTypeCast(expr.type, SimTypePointer(data_type), expr, codegen=self), codegen=self
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
                        else CTypeCast(t.type, SimTypePointer(SimTypeChar()), t, codegen=self)
                    )
                elif c == 1:
                    piece = (
                        t
                        if not isinstance(t.type, SimTypePointer)
                        else CTypeCast(t.type, SimTypePointer(SimTypeChar()), t, codegen=self)
                    )
                else:
                    assert t.type is not None
                    coefficient_type = pointer_length_int_type if isinstance(t.type, SimTypePointer) else t.type
                    piece = CBinaryOp(
                        "Mul",
                        CConstant(c, coefficient_type, codegen=self),
                        (
                            t
                            if not isinstance(t.type, SimTypePointer)
                            else CTypeCast(t.type, pointer_length_int_type, t, codegen=self)
                        ),
                        codegen=self,
                    )
                result = piece if result is None else CBinaryOp(op, result, piece, codegen=self)
            if o_constant != 0:
                result = CBinaryOp("Add", CConstant(o_constant, SimTypeInt(), codegen=self), result, codegen=self)

            return CUnaryOp(
                "Dereference", CTypeCast(result.type, SimTypePointer(data_type), result, codegen=self), codegen=self
            )

        # pain.
        # step 1 is split expr into a sum of terms, each of which is a product of a constant stride and an index
        # also identify the "kernel", the root of the expression
        constant, terms = o_constant, list(o_terms)
        if constant < 0:
            constant = -constant  # TODO: This may not be correct. investigate later

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
                kernel = CUnaryOp(
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
                    index = CBinaryOp(
                        "Mul", CConstant(index_multiplier, SimTypeInt(), codegen=self), next_term, codegen=self
                    )
                else:
                    index = next_term
                if (
                    isinstance(kernel, CUnaryOp)
                    and kernel.op == "Reference"
                    and isinstance(kernel.operand, CIndexedVariable)
                ):
                    old_index = kernel.operand.index
                    kernel = kernel.operand.variable
                    if not isinstance(old_index, CConstant) or old_index.value != 0:
                        index = CBinaryOp("Add", old_index, index, codegen=self)
                kernel = CUnaryOp("Reference", CIndexedVariable(kernel, index, codegen=self), codegen=self)
                terms.pop()
                continue

            if next_stride > kernel_stride:
                l.warning("Oddly-sized array access stride. Uh oh!")
                return bail_out()

            # nothing has the ability to escape the kernel
            # go in deeper
            if isinstance(kernel_type, SimStruct):
                field_name, field_offset = max(
                    ((x, y) for x, y in kernel_type.offsets.items() if y <= constant), key=lambda x: x[1]
                )
                field_type = kernel_type.fields[field_name]
                kernel = CUnaryOp(
                    "Reference",
                    self._access_constant_offset(kernel, field_offset, field_type, True, renegotiate_type),
                    codegen=self,
                )
                constant -= field_offset
                continue

            if isinstance(kernel_type, (SimTypeArray, SimTypeFixedSizeArray)):
                inner = self._access_constant_offset(kernel, 0, kernel_type.elem_type, True, renegotiate_type)
                if isinstance(inner, CUnaryOp) and inner.op == "Dereference":
                    # unpack
                    kernel = inner.operand
                else:
                    kernel = CUnaryOp("Reference", inner, codegen=self)
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

        return lines[0] if len(lines) == 1 else CStatements(lines, codegen=self, addr=seq.addr)

    def _handle_Loop(self, loop_node, **kwargs):
        tags = {"ins_addr": loop_node.addr}

        if loop_node.sort == "while":
            return CWhileLoop(
                None if loop_node.condition is None else self._handle(loop_node.condition),
                None if loop_node.sequence_node is None else self._handle(loop_node.sequence_node, is_expr=False),
                tags=tags,
                codegen=self,
            )
        if loop_node.sort == "do-while":
            return CDoWhileLoop(
                self._handle(loop_node.condition),
                None if loop_node.sequence_node is None else self._handle(loop_node.sequence_node, is_expr=False),
                tags=tags,
                codegen=self,
            )
        if loop_node.sort == "for":
            return CForLoop(
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

        return CIfElse(
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

        return CIfElse(
            condition_and_nodes,
            else_node=else_node,
            tags=tags,
            cstyle_ifs=self.cstyle_ifs,
            codegen=self,
        )

    def _handle_ConditionalBreak(self, node, **kwargs):
        tags = {"ins_addr": node.addr}

        return CIfBreak(self._handle(node.condition), cstyle_ifs=self.cstyle_ifs, tags=tags, codegen=self)

    def _handle_Break(self, node, **kwargs):
        tags = {"ins_addr": node.addr}

        return CBreak(tags=tags, codegen=self)

    def _handle_MultiNode(self, node, **kwargs):
        lines = []

        for n in node.nodes:
            r = self._handle(n, is_expr=False)
            lines.append(r)

        return lines[0] if len(lines) == 1 else CStatements(lines, codegen=self, addr=node.addr)

    def _handle_SwitchCase(self, node, **kwargs):
        """

        :param SwitchCaseNode node:
        :return:
        """

        switch_expr = self._handle(node.switch_expr)
        # AIL switch selectors are fixed-width machine values. Type recovery
        # may label the same carrier as a pointer because of uses elsewhere in
        # the function, but C only accepts integer switch expressions. Preserve
        # the selector's exact AIL width with an explicit numeric conversion at
        # this boundary instead of emitting invalid C or inheriting C pointer
        # semantics.
        switch_type = self.default_simtype_from_bits(node.switch_expr.bits, signed=False)
        switch_expr = _coerce_scalar_expression(switch_expr, switch_type, self, force_numeric=True)
        cases = [(idx, self._handle(case, is_expr=False)) for idx, case in node.cases.items()]
        default = self._handle(node.default_node, is_expr=False) if node.default_node is not None else None
        tags = {"ins_addr": node.addr}
        return CSwitchCase(switch_expr, cases, default=default, tags=tags, codegen=self)

    def _handle_IncompleteSwitchCase(self, node: IncompleteSwitchCaseNode, **kwargs):
        head = self._handle(node.head, is_expr=False)
        cases = [(case.addr, self._handle(case, is_expr=False)) for case in node.cases]
        tags = {"ins_addr": node.addr}
        return CIncompleteSwitchCase(head, cases, tags=tags, codegen=self)

    def _handle_Continue(self, node, **kwargs):
        tags = {"ins_addr": node.addr}

        return CContinue(tags=tags, codegen=self)

    def _handle_AILBlock(self, node, **kwargs):
        """

        :param Block node:
        :return:
        """

        # return CStatements([ CAILBlock(node) ])
        cstmts = []
        for stmt in node.statements:
            try:
                cstmt = self._handle(stmt, is_expr=False)
            except UnsupportedNodeTypeError as error:
                l.warning(
                    "Unsupported AIL statement or expression %s.",
                    getattr(stmt, "kind", None) or type(stmt).__name__,
                    exc_info=True,
                )
                diagnostic_tags = None
                if isinstance(error, _NativeStackPointerGuestNearCallError):
                    diagnostic_tags = {
                        **stmt.tags,
                        _UNSUPPORTED_DIAGNOSTIC_KIND_TAG: _NATIVE_STACK_POINTER_NEAR_CALL_KIND,
                        _UNSUPPORTED_DIAGNOSTIC_OPERATION_TAG: _NATIVE_STACK_POINTER_NEAR_CALL_OPERATION,
                    }
                elif isinstance(error, _StructuredCodegenDiagnosticError):
                    diagnostic_tags = {
                        **stmt.tags,
                        _UNSUPPORTED_DIAGNOSTIC_KIND_TAG: error.kind,
                        _UNSUPPORTED_DIAGNOSTIC_OPERATION_TAG: error.operation,
                    }
                cstmt = CUnsupportedStatement(stmt, tags=diagnostic_tags, codegen=self)
            if isinstance(cstmt, CStatements):
                # Statement lowering may expand one AIL statement into an ordered C sequence (for example, a local
                # SSA definition and its ambient-register write-through). Keep that sequence at this block level so
                # enclosing if/else rendering sees its real statement count and retains required braces.
                cstmts.extend(cstmt.statements)
            else:
                cstmts.append(cstmt)

        return CStatements(cstmts, codegen=self, addr=node.addr)

    #
    # AIL statement handlers
    #

    @staticmethod
    def _c_lvalue_is_stack_object(expr: CExpression) -> bool:
        if isinstance(expr, CVariable):
            return isinstance(expr.variable, SimStackVariable) or isinstance(expr.unified_variable, SimStackVariable)
        if isinstance(expr, (CIndexedVariable, CVariableField)):
            return CStructuredCodeGenerator._c_lvalue_is_stack_object(expr.variable)
        return False

    @staticmethod
    def _c_expression_has_pointer_semantics(expr: CExpression) -> bool:
        expr_type = unpack_typeref(expr.type) if expr.type is not None else None
        if isinstance(expr_type, (SimTypePointer, SimTypeArray, SimTypeFixedSizeArray)):
            return True
        if isinstance(expr, CUnaryOp):
            return expr.op == "Reference" or CStructuredCodeGenerator._c_expression_has_pointer_semantics(expr.operand)
        if isinstance(expr, CBinaryOp):
            return CStructuredCodeGenerator._c_expression_has_pointer_semantics(
                expr.lhs
            ) or CStructuredCodeGenerator._c_expression_has_pointer_semantics(expr.rhs)
        if isinstance(expr, CTypeCast):
            return CStructuredCodeGenerator._c_expression_has_pointer_semantics(expr.expr)
        return False

    @staticmethod
    def _c_expression_is_proven_stack_address(expr: CExpression) -> bool:
        if isinstance(expr, CUnaryOp) and expr.op == "Reference":
            return CStructuredCodeGenerator._c_lvalue_is_stack_object(expr.operand)
        if isinstance(expr, CTypeCast):
            dst_type = unpack_typeref(expr.dst_type)
            return isinstance(
                dst_type, SimTypePointer
            ) and CStructuredCodeGenerator._c_expression_is_proven_stack_address(expr.expr)
        if isinstance(expr, CBinaryOp) and expr.op in {"Add", "Sub"}:
            lhs_is_stack = CStructuredCodeGenerator._c_expression_is_proven_stack_address(expr.lhs)
            rhs_is_stack = CStructuredCodeGenerator._c_expression_is_proven_stack_address(expr.rhs)
            lhs_has_pointer = CStructuredCodeGenerator._c_expression_has_pointer_semantics(expr.lhs)
            rhs_has_pointer = CStructuredCodeGenerator._c_expression_has_pointer_semantics(expr.rhs)
            return (lhs_is_stack and not rhs_has_pointer) or (expr.op == "Add" and rhs_is_stack and not lhs_has_pointer)
        return False

    @staticmethod
    def _c_stack_storage_identity(expr: CExpression) -> SimStackVariable | None:
        if not isinstance(expr, CVariable):
            return None
        if isinstance(expr.unified_variable, SimStackVariable):
            return expr.unified_variable
        return expr.variable if isinstance(expr.variable, SimStackVariable) else None

    @staticmethod
    def _c_integer_constant(expr: CExpression) -> int | None:
        if isinstance(expr, CConstant) and type(expr.value) is int:
            return expr.value
        if isinstance(expr, CTypeCast):
            return CStructuredCodeGenerator._c_integer_constant(expr.expr)
        return None

    def _c_stack_lvalue_offset(self, expr: CExpression) -> int | None:
        """Return the exact BP-relative byte offset of a recovered stack lvalue."""

        if isinstance(expr, CVariable) and isinstance(expr.variable, SimStackVariable):
            if type(expr.variable.offset) is not int or expr.variable.base != "bp":
                return None
            access_offset = expr.tags.get(_EXACT_STORAGE_OFFSET_TAG, 0)
            if type(access_offset) is not int:
                return None
            return expr.variable.offset + access_offset
        if isinstance(expr, CIndexedVariable):
            base_offset = self._c_stack_lvalue_offset(expr.variable)
            index = self._c_integer_constant(expr.index)
            element_bits = _safe_type_size(unpack_typeref(expr.type))
            if base_offset is None or index is None or element_bits <= 0:
                return None
            byte_width = self.project.arch.byte_width
            if element_bits % byte_width != 0:
                return None
            return base_offset + index * (element_bits // byte_width)
        if isinstance(expr, CVariableField) and not expr.var_is_ptr:
            base_offset = self._c_stack_lvalue_offset(expr.variable)
            return None if base_offset is None else base_offset + expr.field.offset
        return None

    def _c_native_stack_pointer_offset(self, expr: CExpression) -> int | None:
        """Recover a native stack address without treating pointer-shaped guest integers as evidence."""

        if isinstance(expr, CUnaryOp) and expr.op == "Reference":
            return self._c_stack_lvalue_offset(expr.operand)
        if isinstance(expr, CVariable):
            storage = self._c_stack_storage_identity(expr)
            if storage is not None:
                return getattr(self, "_native_stack_pointer_provenance", {}).get(storage)
            expr_type = unpack_typeref(expr.type) if expr.type is not None else None
            if isinstance(expr_type, (SimTypeArray, SimTypeFixedSizeArray)):
                return self._c_stack_lvalue_offset(expr)
        if isinstance(expr, CTypeCast):
            return self._c_native_stack_pointer_offset(expr.expr)
        if isinstance(expr, CBinaryOp) and expr.op in {"Add", "Sub"}:
            lhs_offset = self._c_native_stack_pointer_offset(expr.lhs)
            rhs_offset = self._c_native_stack_pointer_offset(expr.rhs)
            lhs_constant = self._c_integer_constant(expr.lhs)
            rhs_constant = self._c_integer_constant(expr.rhs)
            if lhs_offset is not None and rhs_constant is not None:
                return lhs_offset + (rhs_constant if expr.op == "Add" else -rhs_constant)
            if expr.op == "Add" and rhs_offset is not None and lhs_constant is not None:
                return rhs_offset + lhs_constant
        return None

    def _c_selector_provenance(self, expr: CExpression) -> tuple[int, int] | None:
        if isinstance(expr, CRegister):
            matches = [storage for storage, lvalue in self._register_state_bindings.items() if lvalue == expr.reg]
            return matches[0] if len(matches) == 1 else None
        if isinstance(expr, CVariable):
            storage = self._c_stack_storage_identity(expr)
            if storage is not None:
                return getattr(self, "_selector_carriers", {}).get(storage)
            seed = expr.tags.get(_INITIAL_REGISTER_STATE_SEED_TAG)
            if isinstance(seed, str):
                matches = [storage for storage, lvalue in self._register_state_bindings.items() if lvalue == seed]
                return matches[0] if len(matches) == 1 else None
        if isinstance(expr, CTypeCast):
            return self._c_selector_provenance(expr.expr)
        return None

    def _c_expression_has_native_stack_pointer_identity(self, expr: CExpression) -> bool:
        if self._c_expression_is_proven_stack_address(expr):
            return True
        storage = self._c_stack_storage_identity(expr)
        if storage is not None:
            return storage in getattr(self, "_native_stack_pointer_carriers", set())
        if isinstance(expr, CTypeCast):
            # A narrowing cast does not turn a native C object address into a
            # guest offset. Retain the identity so a later ABI boundary can
            # reject the truncation instead of treating it as evidence.
            return self._c_expression_has_native_stack_pointer_identity(expr.expr)
        if isinstance(expr, CBinaryOp) and expr.op in {"Add", "Sub"}:
            lhs_is_stack_pointer = self._c_expression_has_native_stack_pointer_identity(expr.lhs)
            rhs_is_stack_pointer = self._c_expression_has_native_stack_pointer_identity(expr.rhs)
            lhs_has_pointer = self._c_expression_has_pointer_semantics(expr.lhs)
            rhs_has_pointer = self._c_expression_has_pointer_semantics(expr.rhs)
            return (lhs_is_stack_pointer and not rhs_has_pointer) or (
                expr.op == "Add" and rhs_is_stack_pointer and not lhs_has_pointer
            )
        return False

    def _remember_native_stack_pointer_assignment(self, destination: CExpression, source: CExpression) -> None:
        storage = self._c_stack_storage_identity(destination)
        if storage is None:
            return
        carriers = getattr(self, "_native_stack_pointer_carriers", None)
        if carriers is None:
            carriers = self._native_stack_pointer_carriers = set()
        if self._c_expression_has_native_stack_pointer_identity(source):
            carriers.add(storage)
        else:
            carriers.discard(storage)
        proven_offset = self._c_native_stack_pointer_offset(source)
        provenance = getattr(self, "_native_stack_pointer_provenance", None)
        if provenance is None:
            provenance = self._native_stack_pointer_provenance = {}
        if proven_offset is None:
            provenance.pop(storage, None)
        else:
            provenance[storage] = proven_offset

        selector = self._c_selector_provenance(source)
        selector_carriers = getattr(self, "_selector_carriers", None)
        if selector_carriers is None:
            selector_carriers = self._selector_carriers = {}
        if selector is None:
            selector_carriers.pop(storage, None)
        else:
            selector_carriers[storage] = selector

    def _reject_native_stack_pointer_at_guest_near_call_boundary(
        self,
        argument: CExpression,
        expected_type: SimType | None,
        *,
        guest_near_pointer_boundary: bool,
    ) -> None:
        if not guest_near_pointer_boundary or expected_type is None:
            return
        expected = unpack_typeref(expected_type).with_arch(self.project.arch)
        if not (
            isinstance(expected, SimTypePointer)
            and expected.size == 16
            and self._c_expression_has_native_stack_pointer_identity(argument)
        ):
            return
        raise _NativeStackPointerGuestNearCallError(
            "Native C stack-object pointer identity cannot be reinterpreted or truncated at a 16-bit guest "
            "near-pointer call boundary without an explicit host-pointer service binding"
        )

    @staticmethod
    def _ail_expression_is_direct_register_value(expr: Expr.Expression) -> bool:
        if isinstance(expr, Expr.Register):
            return True
        if not isinstance(expr, Expr.VirtualVariable):
            return False
        return expr.was_reg or (
            expr.was_parameter
            and isinstance(expr.oident, tuple)
            and len(expr.oident) == 2
            and expr.oident[0] == Expr.VirtualVariableCategory.REGISTER
        )

    @staticmethod
    def _segmented_address_uses_stack_selector(address: Expr.SegmentedAddress) -> bool:
        return address.tags.get("segment_register") == "ss" or address.tags.get("segment_register_origin") == "ss"

    def _classify_segmented_memory_offset(self, address: Expr.SegmentedAddress) -> tuple[CExpression, bool]:
        offset = self._handle(address.offset)
        native_stack_address = (
            address.address_kind == "x86-protected-16:16"
            and self._segmented_address_uses_stack_selector(address)
            and self._c_expression_is_proven_stack_address(offset)
        )
        if native_stack_address:
            return offset, True
        if self._c_expression_has_pointer_semantics(offset):
            segment_register = address.tags.get("segment_register")
            direct_machine_register = isinstance(address.offset, Expr.Register) or (
                isinstance(address.offset, Expr.VirtualVariable) and address.offset.was_reg
            )
            if (
                address.address_kind == "x86-protected-16:16"
                and isinstance(segment_register, str)
                and (
                    segment_register in {"cs", "ds", "es", "fs", "gs"}
                    or (segment_register == "ss" and direct_machine_register)
                )
                and address.offset.bits == 16
                and self._ail_expression_is_direct_register_value(address.offset)
            ):
                # The AIL value is still the exact 16-bit machine register even if type recovery independently labels
                # its C storage as a pointer. Convert through the 32-bit runtime carrier before narrowing back to the
                # guest width: on the supported 32-bit hosts this avoids a pointer-to-smaller-integer conversion while
                # preserving the register bits. An ordinary SS register read is also a guest offset; explicit
                # pointer-typed SS parameters and pointer-derived expressions remain closed.
                carrier_type = self.default_simtype_from_bits(32, signed=False)
                guest_offset_type = self.default_simtype_from_bits(address.offset.bits, signed=False)
                cast_tags = {**offset.tags, _REQUIRED_CAST_TAG: True}
                carrier_offset = CTypeCast(
                    offset.type,
                    carrier_type,
                    offset,
                    tags=cast_tags,
                    codegen=self,
                )
                return (
                    CTypeCast(
                        carrier_type,
                        guest_offset_type,
                        carrier_offset,
                        tags=cast_tags,
                        codegen=self,
                    ),
                    False,
                )
            raise UnsupportedNodeTypeError(
                "Segmented-memory offset resolved to a host C pointer without proven SS stack-object provenance"
            )
        return offset, False

    def _segmented_memory_helper_call(
        self,
        address: Expr.SegmentedAddress,
        size: int,
        endness: str,
        *,
        data: CExpression | None = None,
        offset: CExpression | None = None,
        tags=None,
    ) -> CFunctionCall:
        if address.address_kind != "x86-protected-16:16" or address.selector.bits != 16 or address.offset.bits != 16:
            raise UnsupportedNodeTypeError(
                f"Unsupported segmented-address helper ABI {address.address_kind!r} "
                f"with {address.selector.bits}-bit selector and {address.offset.bits}-bit offset"
            )
        binding_key = address.address_kind, endness, size
        helpers = self._segmented_memory_bindings.get(binding_key)
        operation = "store" if data is not None else "load"
        helper = None if helpers is None else helpers[1 if data is not None else 0]
        if helper is None:
            raise UnsupportedNodeTypeError(
                f"No {operation} helper is bound for segmented address {address.address_kind!r}, "
                f"endness {endness!r}, width {size}"
            )

        selector_type = self.default_simtype_from_bits(16, signed=False)
        offset_type = self.default_simtype_from_bits(32, signed=False)
        selector = self._coerce_call_argument(self._handle(address.selector), selector_type)
        if offset is None:
            offset, native_stack_address = self._classify_segmented_memory_offset(address)
            if native_stack_address:
                raise UnsupportedNodeTypeError(
                    "Proven SS stack-object address must be lowered as a native C access, not a guest runtime offset"
                )
        offset = self._coerce_call_argument(offset, offset_type)
        args = [selector, offset]
        argument_types = [selector_type, offset_type]

        if data is None:
            return_type = self.default_simtype_from_bits(size * self.project.arch.byte_width, signed=False)
        else:
            data_type = self.default_simtype_from_bits(size * self.project.arch.byte_width, signed=False)
            args.append(self._coerce_call_argument(data, data_type))
            argument_types.append(data_type)
            return_type = None

        prototype = SimTypeFunction(
            argument_types,
            return_type,
        ).with_arch(self.project.arch)
        return CFunctionCall(
            helper,
            None,
            args,
            callsite_prototype=prototype,
            result_used=data is None,
            tags=tags,
            codegen=self,
        )

    def _segmented_stack_access(
        self,
        variable: SimStackVariable,
        size: int,
        offset: int,
        tags: dict,
    ) -> CVariable:
        """Build an exact-width lvalue view into a proven native stack object."""

        access = self._variable(variable, size)
        access.variable_type = self.default_simtype_from_bits(
            size * self.project.arch.byte_width,
            signed=False,
        )
        access.tags = {
            **tags,
            _EXACT_STORAGE_ACCESS_TAG: True,
            _EXACT_STORAGE_OFFSET_TAG: offset,
        }
        return access

    def _segmented_stack_access_needs_exact_view(
        self,
        variable: SimStackVariable,
        size: int,
        offset: int,
    ) -> bool:
        variable_manager = self.kb.dec_variables[self._func.addr]
        recovered_type = variable_manager.get_variable_type(variable)
        recovered_bits = _safe_type_size(unpack_typeref(recovered_type)) if recovered_type is not None else 0
        access_bits = size * self.project.arch.byte_width
        if offset != 0 or variable.size != size or recovered_bits not in {0, access_bits}:
            return True

        unified = variable_manager.unified_variable(variable)
        return unified is not None and any(
            candidate != variable and variable_manager.unified_variable(candidate) == unified and candidate.size != size
            for candidate in variable_manager.get_variables("stack")
        )

    def _direct_far_call_target_addr(self, expr: Expr.Call) -> int:
        if expr.tags.get("far_call_resolved_indirect", False):
            raise UnsupportedNodeTypeError(
                "A CFG-resolved indirect far call is not a direct CALLF operand; refusing guessed lowering"
            )
        if isinstance(expr.target, Expr.Const):
            if not isinstance(expr.target.value, int) or isinstance(expr.target.value, bool):
                raise UnsupportedNodeTypeError("Direct far-call targets must be integer constants")
            return expr.target.value

        target = expr.target
        if not (
            isinstance(target, Expr.SegmentedAddress)
            and target.address_kind in {"x86-protected-16:16", "x86-protected-16:32"}
            and target.selector.bits == 16
            and isinstance(target.selector, Expr.Const)
            and isinstance(target.selector.value, int)
            and not isinstance(target.selector.value, bool)
            and isinstance(target.offset, Expr.Const)
            and isinstance(target.offset.value, int)
            and not isinstance(target.offset.value, bool)
        ):
            raise UnsupportedNodeTypeError(
                "Indirect or nonconstant segmented far calls are unsupported; refusing host function-pointer lowering"
            )

        # A protected-mode immediate CALLF operand carries a loader selector,
        # not a runtime selector. Resolve it solely through the canonical CFG
        # call edge. The raw selector is deliberately neither flattened nor
        # passed to generated C.
        cfg = getattr(self._cfg, "model", self._cfg)
        ins_addr = expr.tags.get("ins_addr")
        if cfg is None or not isinstance(ins_addr, int):
            raise UnsupportedNodeTypeError("A constant segmented far call requires an exact canonical CFG call edge")
        callsite_node = cfg.get_any_node(ins_addr, anyaddr=True)
        if callsite_node is None:
            raise UnsupportedNodeTypeError("A constant segmented far call has no canonical CFG callsite node")

        callees = {
            successor.addr
            for _, successor, data in cfg.graph.out_edges([callsite_node], data=True)
            if data.get("jumpkind") == "Ijk_Call"
            and (data.get("ins_addr") is None or data.get("ins_addr") == ins_addr)
            and isinstance(successor.addr, int)
        }
        if len(callees) != 1:
            raise UnsupportedNodeTypeError(
                "A constant segmented far call does not resolve to exactly one canonical CFG target"
            )
        return next(iter(callees))

    def _resolve_far_call_binding(self, expr: Expr.Call) -> tuple[str, str, str | None, str | None] | None:
        if getattr(expr, "transfer_kind", "unknown") != "far":
            return None
        if expr.tags.get("indirect_far_call_dispatch", False):
            slot_offset_kind = expr.tags.get("indirect_far_call_slot_offset_kind")
            slot_offset = expr.tags.get("indirect_far_call_slot_offset")
            if slot_offset_kind is None and slot_offset is not None:
                # Serialized fixed-slot intrinsics created before offset-source tagging are unambiguous.
                slot_offset_kind = "constant"
            if not (
                isinstance(expr.target, str)
                and expr.args is not None
                and len(expr.args) >= 2
                and expr.bits in (None, 0)
                and expr.tags.get("indirect_far_call_binding_authoritative", False)
                and expr.tags.get("indirect_far_call_address_kind") == "x86-protected-16:16"
                and expr.args[0].bits == 16
            ):
                raise UnsupportedNodeTypeError("Malformed dynamic far-call dispatcher intrinsic")

            if slot_offset_kind == "constant":
                valid_offset = (
                    isinstance(slot_offset, int)
                    and not isinstance(slot_offset, bool)
                    and 0 <= slot_offset <= 0xFFFF
                    and isinstance(expr.args[1], Expr.Const)
                    and expr.args[1].bits == 16
                    and expr.args[1].value == slot_offset
                    and "indirect_far_call_slot_offset_register" not in expr.tags
                    and "indirect_far_call_slot_offset_register_size" not in expr.tags
                )
            elif slot_offset_kind == "register":
                slot_register_offset = expr.tags.get("indirect_far_call_slot_offset_register")
                slot_register_size = expr.tags.get("indirect_far_call_slot_offset_register_size")
                valid_offset = (
                    slot_offset is None
                    and isinstance(slot_register_offset, int)
                    and not isinstance(slot_register_offset, bool)
                    and slot_register_offset >= 0
                    and slot_register_size == 2
                    and expr.args[1].bits == 16
                )
            else:
                valid_offset = False
            if not valid_offset:
                raise UnsupportedNodeTypeError("Malformed dynamic far-call dispatcher intrinsic")

            has_site_identifier = "indirect_far_call_site_identifier" in expr.tags
            if has_site_identifier:
                site_identifier = expr.tags["indirect_far_call_site_identifier"]
                if not (
                    isinstance(site_identifier, int)
                    and not isinstance(site_identifier, bool)
                    and 0 <= site_identifier <= 0xFFFF_FFFF
                    and len(expr.args) >= 3
                    and isinstance(expr.args[2], Expr.Const)
                    and expr.args[2].bits == 32
                    and expr.args[2].value == site_identifier
                    and expr.tags.get("indirect_far_call_noreturn", False)
                ):
                    raise UnsupportedNodeTypeError("Malformed dynamic far-call dispatcher intrinsic")
            elif expr.tags.get("indirect_far_call_noreturn", False):
                raise UnsupportedNodeTypeError("Malformed dynamic far-call dispatcher intrinsic")
            return None
        target_addr = self._direct_far_call_target_addr(expr)
        binding = self._far_call_bindings.get(target_addr)
        if binding is None:
            raise UnsupportedNodeTypeError(
                f"No exact far-call binding exists for canonical direct target {target_addr:#x}; "
                "refusing host function-pointer lowering"
            )
        return binding

    def _x86_pcode_swi_prototype(self, expr: Expr.Call) -> SimTypeFunction | None:
        if expr.target != _X86_PCODE_SWI_TARGET or self.project.arch.name not in {
            "x86:LE:16:Protected Mode",
            "x86:LE:16:Real Mode",
        }:
            return None
        if expr.args is None or len(expr.args) != _X86_PCODE_SWI_ARGUMENT_COUNT:
            raise UnsupportedNodeTypeError(
                f"{_X86_PCODE_SWI_TARGET} requires a vector, eight x86-16 registers, and CF/PF/AF/ZF/SF/OF/DF"
            )
        return SimTypeFunction(
            [SimTypeShort(signed=False) for _ in range(9)] + [SimTypeChar(signed=False) for _ in range(7)],
            SimTypeShort(signed=False),
        ).with_arch(self.project.arch)

    def _coerce_guest_register_argument(self, argument: CExpression, expected_type: SimType) -> CExpression:
        """Render one runtime input as the exact low bits of a guest register."""
        expected_type = expected_type.with_arch(self.project.arch)
        expected_bits = expected_type.size
        if not isinstance(expected_bits, int) or expected_bits <= 0 or expected_bits > 64:
            raise UnsupportedNodeTypeError("Guest-register runtime arguments must be unsigned scalars up to 64 bits")
        mask = (1 << expected_bits) - 1
        if isinstance(argument, CConstant) and isinstance(argument.value, int):
            return CConstant(
                argument.value & mask,
                expected_type,
                tags=argument.tags,
                codegen=self,
            )

        actual_type = unpack_typeref(argument.type) if argument.type is not None else None
        if (
            not isinstance(actual_type, SimTypePointer)
            and isinstance(argument, CVariable)
            and argument.codegen is not None
            and argument.codegen.cfunc is not None
        ):
            declaration_type = unpack_typeref(argument.codegen.cfunc.declaration_type(argument))
            if isinstance(declaration_type, SimTypePointer):
                # Exact-width VVar accesses normally render through the declaration's storage (for example as a
                # 16-bit lvalue view of an array). At a guest-register ABI boundary, however, pointer-typed storage
                # denotes the pointer value itself. Use an unwrapped occurrence so the conversion below goes through
                # the integer carrier instead of dereferencing the pointer object's representation.
                argument = CVariable(
                    argument.variable,
                    unified_variable=argument.unified_variable,
                    variable_type=declaration_type,
                    vvar_id=argument.vvar_id,
                    tags={
                        key: value
                        for key, value in argument.tags.items()
                        if key not in {_EXACT_STORAGE_ACCESS_TAG, _EXACT_STORAGE_OFFSET_TAG}
                    },
                    codegen=self,
                )
                actual_type = declaration_type
        if isinstance(actual_type, SimTypePointer):
            # A recovered host pointer type is type evidence, not the guest runtime ABI. Convert through an integer
            # carrier wide enough for every supported host, then explicitly retain the low guest bits. This avoids
            # both an invalid implicit pointer-to-integer conversion and a size-changing direct pointer cast.
            carrier_type = SimTypeNum(64, signed=False).with_arch(self.project.arch)
            required_tags = {**argument.tags, _REQUIRED_CAST_TAG: True}
            integer_value = CTypeCast(
                actual_type,
                carrier_type,
                argument,
                tags=required_tags,
                codegen=self,
            )
            masked_value = (
                integer_value
                if expected_bits == 64
                else CBinaryOp(
                    "And",
                    integer_value,
                    CConstant(mask, carrier_type, codegen=self),
                    tags=argument.tags,
                    codegen=self,
                )
            )
            return CTypeCast(
                masked_value.type,
                expected_type,
                masked_value,
                tags=required_tags,
                codegen=self,
            )

        return self._coerce_call_argument(argument, expected_type)

    def _coerce_x86_pcode_swi_argument(self, argument: CExpression, expected_type: SimType) -> CExpression:
        """Render one software-interrupt input as the exact low 16 bits of a guest register."""

        return self._coerce_guest_register_argument(argument, expected_type)

    @staticmethod
    def _ail_16_16_carrier_parts(argument: Expr.Expression) -> tuple[Expr.Expression, Expr.Expression] | None:
        if not (
            isinstance(argument, Expr.BinaryOp)
            and argument.op == "Concat"
            and argument.bits == 32
            and len(argument.operands) == 2
            and argument.operands[0].bits == 16
            and argument.operands[1].bits == 16
        ):
            return None
        return argument.operands[0], argument.operands[1]

    def _converted_pointer_helper_call(
        self,
        frame: SimStackVariable,
        helper: str,
        span: int,
        contract: str,
        tags,
    ) -> CFunctionCall:
        byte_type = SimTypeChar(signed=False).with_arch(self.project.arch)
        frame_type = SimTypeArray(byte_type, frame.size).with_arch(self.project.arch)
        frame_value = CVariable(
            frame,
            unified_variable=frame,
            variable_type=frame_type,
            tags={_NATIVE_STACK_FRAME_ALIGNMENT_TAG: 16},
            codegen=self,
        )
        frame_byte = CIndexedVariable(
            frame_value,
            CConstant(0, self.default_simtype_from_bits(32, signed=False), codegen=self),
            variable_type=byte_type,
            codegen=self,
        )
        frame_address = CUnaryOp("Reference", frame_byte, codegen=self)
        void_pointer_type = SimTypePointer(SimTypeBottom(label="void")).with_arch(self.project.arch)
        frame_address = CTypeCast(
            frame_address.type,
            void_pointer_type,
            frame_address,
            tags={_REQUIRED_CAST_TAG: True},
            codegen=self,
        )
        span_type = self.default_simtype_from_bits(32, signed=False)
        helper_prototype = SimTypeFunction(
            [void_pointer_type, span_type],
            SimTypeNum(64, signed=False),
        ).with_arch(self.project.arch)
        return CFunctionCall(
            helper,
            None,
            [frame_address, CConstant(span, span_type, codegen=self)],
            callsite_prototype=helper_prototype,
            result_used=True,
            tags={**(tags or {}), "converted_pointer_contract": contract},
            codegen=self,
        )

    def _lower_converted_pointer_argument(
        self,
        argument: Expr.Expression,
        converted_argument: CExpression,
        binding: tuple[str, int, str, str, int, int, str, int | None, str | None] | None,
        *,
        allocated_interval: tuple[int, int] | None,
        tags,
    ) -> CExpression | None:
        """Lower a proven native 16:16 carrier, preserving clearly guest-native values unchanged."""

        parts = self._ail_16_16_carrier_parts(argument)
        if parts is None:
            if binding is None and argument.bits != 32:
                # A legacy 16-bit near-pointer prototype has its own precise boundary diagnostic in
                # `_coerce_call_argument`. This bridge is exclusively about one 32-bit 16:16 machine carrier.
                return None
            if not self._c_expression_has_native_stack_pointer_identity(converted_argument):
                return None
            if binding is None:
                raise _StructuredCodegenDiagnosticError(
                    "A proven native stack address reaches a far-call scalar without an exact converted-pointer "
                    "binding",
                    _NATIVE_STACK_POINTER_FAR_CALL_KIND,
                    _NATIVE_STACK_POINTER_FAR_CALL_OPERATION,
                )
            raise _StructuredCodegenDiagnosticError(
                "A converted-pointer argument carrying native address identity is not an exact 16:16 value",
                _CONVERTED_POINTER_FAILURE_KIND,
                "prove-exact-16:16-carrier",
            )

        selector_ail, offset_ail = parts
        selector = self._handle(selector_ail)
        offset = self._handle(offset_ail)
        native_identity = self._c_expression_has_native_stack_pointer_identity(offset)
        native_offset = self._c_native_stack_pointer_offset(offset)
        sealed_native_offset = None if binding is None else binding[7]
        if not native_identity and native_offset is None and sealed_native_offset is None:
            # The binding describes the semantic API argument, not every caller's choice of storage. A genuine guest
            # selector:offset must retain its exact 32-bit carrier and must never mint a host borrow token.
            return None
        if binding is None:
            raise _StructuredCodegenDiagnosticError(
                "A proven native stack address was truncated into the low half of an unbound 16:16 far argument",
                _NATIVE_STACK_POINTER_FAR_CALL_KIND,
                _NATIVE_STACK_POINTER_FAR_CALL_OPERATION,
            )
        if native_offset is None and sealed_native_offset is None:
            raise _StructuredCodegenDiagnosticError(
                "Native stack address identity lacks an exact recovered BP-relative origin",
                _CONVERTED_POINTER_FAILURE_KIND,
                "prove-native-stack-pointer-provenance",
            )

        (
            helper,
            span,
            address_kind,
            _selector_name,
            selector_offset,
            selector_size,
            contract,
            sealed_native_offset,
            sealed_native_evidence,
        ) = binding
        if address_kind != "x86-protected-16:16":
            raise _StructuredCodegenDiagnosticError(
                f"Unsupported converted-pointer address kind {address_kind!r}",
                _CONVERTED_POINTER_FAILURE_KIND,
                "prove-address-kind",
            )
        selector_provenance = self._c_selector_provenance(selector)
        if sealed_native_offset is None and selector_provenance != (selector_offset, selector_size):
            raise _StructuredCodegenDiagnosticError(
                "Native stack pointer carrier selector is not proven to come from the configured stack selector",
                _CONVERTED_POINTER_FAILURE_KIND,
                "prove-stack-selector",
            )

        if sealed_native_offset is not None:
            if not sealed_native_evidence:
                raise _StructuredCodegenDiagnosticError(
                    "Sealed native stack offset has no machine-evidence identity",
                    _CONVERTED_POINTER_FAILURE_KIND,
                    "prove-machine-native-stack-evidence",
                )
            if selector_provenance is not None and selector_provenance != (selector_offset, selector_size):
                raise _StructuredCodegenDiagnosticError(
                    "Recovered pointer selector contradicts the sealed machine stack-selector proof",
                    _CONVERTED_POINTER_FAILURE_KIND,
                    "prove-machine-stack-selector",
                )
            # The sealed displacement is relative to machine BP.  angr stack
            # variables and StackPointerTracker use the function-entry SP
            # coordinate, whose BP origin is the live interval's exclusive
            # upper bound.  Translate the machine fact into that coordinate;
            # this is commonly a two-byte shift for the saved 16-bit BP.
            native_offset = (
                sealed_native_offset if allocated_interval is None else sealed_native_offset + allocated_interval[1]
            )

        assert native_offset is not None
        frame = self._install_native_stack_frame(native_offset, span, allocated_interval)
        return self._converted_pointer_helper_call(frame, helper, span, contract, tags)

    def _build_call_expression(
        self, expr: Expr.Call, *, result_used: bool, tags=None
    ) -> tuple[CFunctionCall, Function | None, tuple[str, str, str | None, str | None] | None]:
        dynamic_far_dispatch = expr.tags.get("indirect_far_call_dispatch", False)
        dynamic_near_dispatch = expr.tags.get("indirect_near_call_dispatch", False)
        if dynamic_far_dispatch and dynamic_near_dispatch:
            raise UnsupportedNodeTypeError("A call cannot be both a dynamic far- and near-call dispatcher")
        runtime_prototype = None
        if dynamic_far_dispatch and result_used:
            raise UnsupportedNodeTypeError("Dynamic far-call dispatcher intrinsics are void")
        if dynamic_far_dispatch:
            runtime_prototype = self._variable_map.prototype(expr)
            runtime_arg_types = () if runtime_prototype is None else runtime_prototype.args
            if not (
                expr.tags.get("indirect_far_call_binding_authoritative", False)
                and self._variable_map.calling_convention(expr) is None
                and runtime_prototype is not None
                and isinstance(runtime_prototype.returnty, SimTypeBottom)
                and runtime_prototype.returnty.label == "void"
                and expr.args is not None
                and len(runtime_arg_types) == len(expr.args)
                and all(
                    isinstance(unpack_typeref(arg_type), (SimTypeChar, SimTypeInt, SimTypeNum))
                    and unpack_typeref(arg_type).signed is False
                    and arg_type.with_arch(self.project.arch).size == argument.bits
                    for arg_type, argument in zip(runtime_arg_types, expr.args)
                )
            ):
                raise UnsupportedNodeTypeError(
                    "Dynamic far-call dispatcher intrinsics require an exact binding-authoritative scalar void ABI"
                )
        if dynamic_near_dispatch:
            runtime_prototype = self._variable_map.prototype(expr)
            runtime_arg_types = () if runtime_prototype is None else runtime_prototype.args
            return_type = None if runtime_prototype is None else unpack_typeref(runtime_prototype.returnty)
            allowed_target_ranges = {
                self.project.arch.registers[register_name]
                for register_name in INDIRECT_NEAR_CALL_TARGET_REGISTERS
                if register_name in self.project.arch.registers
            }
            selector_offset = expr.tags.get("indirect_near_call_selector_register")
            selector_size = expr.tags.get("indirect_near_call_selector_register_size")
            target_offset = expr.tags.get("indirect_near_call_target_register")
            target_size = expr.tags.get("indirect_near_call_target_register_size")
            site_identifier = expr.tags.get("indirect_near_call_site_identifier")
            if not (
                expr.tags.get("indirect_near_call_binding_authoritative", False)
                and expr.tags.get("indirect_near_call_address_kind") == "x86-protected-16:16"
                and isinstance(expr.target, str)
                and getattr(expr, "transfer_kind", "unknown") == "near"
                and type(selector_offset) is int
                and selector_size == 2
                and (selector_offset, selector_size) == self.project.arch.registers.get("cs")
                and type(target_offset) is int
                and target_size == 2
                and (target_offset, target_size) in allowed_target_ranges
                and target_offset != selector_offset
                and type(site_identifier) is int
                and 0 <= site_identifier <= 0xFFFF_FFFF
                and self._variable_map.calling_convention(expr) is None
                and runtime_prototype is not None
                and isinstance(return_type, (SimTypeChar, SimTypeInt, SimTypeNum))
                and return_type.signed is False
                and runtime_prototype.returnty.with_arch(self.project.arch).size == 16
                and expr.bits == 16
                and expr.args is not None
                and len(expr.args) == 2
                and len(runtime_arg_types) == len(expr.args)
                and tuple(argument.bits for argument in expr.args) == (16, 32)
                and isinstance(expr.args[1], Expr.Const)
                and expr.args[1].value == site_identifier
                and all(
                    isinstance(unpack_typeref(arg_type), (SimTypeChar, SimTypeInt, SimTypeNum))
                    and unpack_typeref(arg_type).signed is False
                    and arg_type.with_arch(self.project.arch).size == argument.bits
                    for arg_type, argument in zip(runtime_arg_types, expr.args)
                )
            ):
                raise UnsupportedNodeTypeError(
                    "Dynamic near-call dispatcher intrinsics require an exact binding-authoritative unsigned "
                    "16-bit return ABI"
                )
        far_binding = self._resolve_far_call_binding(expr)
        far_target_addr = self._direct_far_call_target_addr(expr) if far_binding is not None else None
        guest_near_pointer_boundary = (
            far_binding is not None
            and far_binding[0] == "external"
            and self.project.arch.name in {"x86:LE:16:Protected Mode", "x86:LE:16:Real Mode"}
        )

        # Keep the original direct target for KB/prototype lookup even when an
        # external binding replaces the emitted callee with an exact wrapper.
        original_target = (
            CConstant(
                far_target_addr,
                self.default_simtype_from_bits(self.project.arch.bits, signed=False),
                tags=expr.target.tags,
                codegen=self,
            )
            if far_target_addr is not None
            else self._handle(expr.target, lvalue=True)
            if not isinstance(expr.target, str)
            else expr.target
        )
        if (
            isinstance(original_target, CUnaryOp)
            and original_target.op == "Reference"
            and isinstance(original_target.operand, CVariable)
            and isinstance(original_target.operand.variable, SimMemoryVariable)
            and not isinstance(original_target.operand.variable, SimStackVariable)
            and original_target.operand.variable.size == 1
        ):
            original_target = original_target.operand

        target_func = (
            self.kb.functions.function(addr=original_target.value) if isinstance(original_target, CConstant) else None
        )
        if far_binding is not None and target_func is None:
            raise UnsupportedNodeTypeError(
                f"Far-call target {far_target_addr:#x} is not a known function; refusing guessed lowering"
            )

        callsite_prototype = self._variable_map.prototype(expr)
        x86_pcode_swi_prototype = self._x86_pcode_swi_prototype(expr)
        argument_prototype = (
            x86_pcode_swi_prototype
            or runtime_prototype
            or callsite_prototype
            or (target_func.prototype if target_func is not None else None)
        )
        callsite = expr.tags.get("ins_addr")
        if not isinstance(callsite, int) or isinstance(callsite, bool):
            callsite = None
        converted_bindings = self._converted_pointer_bindings.get(callsite, {})
        if converted_bindings and not (
            getattr(expr, "transfer_kind", "unknown") == "far"
            and far_binding is not None
            and far_binding[0] == "external"
        ):
            raise _StructuredCodegenDiagnosticError(
                "Converted-pointer bindings only apply to exact external far-call sites",
                _CONVERTED_POINTER_FAILURE_KIND,
                "prove-external-far-call",
            )
        argument_count = len(expr.args) if expr.args is not None else 0
        missing_bound_indices = sorted(index for index in converted_bindings if index >= argument_count)
        if missing_bound_indices:
            raise _StructuredCodegenDiagnosticError(
                f"Converted-pointer argument indices do not exist at this callsite: {missing_bound_indices!r}",
                _CONVERTED_POINTER_FAILURE_KIND,
                "prove-bound-argument-index",
            )
        local_stack_interval = self._proven_call_local_stack_interval(expr, argument_prototype, target_func)
        args = []
        converted_argument_indices = []
        if expr.args is not None:
            for i, arg in enumerate(expr.args):
                type_ = None
                if argument_prototype is not None and i < len(argument_prototype.args):
                    type_ = argument_prototype.args[i].with_arch(self.project.arch)
                    if (
                        callsite_prototype is None
                        and target_func is not None
                        and target_func.prototype_libname is not None
                    ):
                        type_ = dereference_simtype_by_lib(type_, target_func.prototype_libname)

                if isinstance(arg, Expr.Const):
                    if isinstance(arg.value, int) and type_ is None:
                        type_ = guess_value_type(arg.value, self.project) or type_
                    new_arg = self._handle_Expr_Const(arg, type_=type_)
                else:
                    new_arg = self._handle(arg, type_=type_)
                converted_argument = None
                if getattr(expr, "transfer_kind", "unknown") == "far":
                    converted_argument = self._lower_converted_pointer_argument(
                        arg,
                        new_arg,
                        converted_bindings.get(i),
                        allocated_interval=local_stack_interval,
                        tags=arg.tags,
                    )
                if converted_argument is not None:
                    args.append(converted_argument)
                    converted_argument_indices.append(i)
                    continue
                args.append(
                    self._coerce_x86_pcode_swi_argument(new_arg, type_)
                    if x86_pcode_swi_prototype is not None
                    else self._coerce_guest_register_argument(new_arg, type_)
                    if dynamic_far_dispatch or dynamic_near_dispatch
                    else self._coerce_call_argument(
                        new_arg,
                        type_,
                        guest_near_pointer_boundary=guest_near_pointer_boundary,
                    )
                )

        emitted_target = original_target
        emitted_target_func = target_func
        emitted_prototype = x86_pcode_swi_prototype or runtime_prototype or callsite_prototype
        if far_binding is not None and far_binding[0] == "external":
            # The exact wrapper name is the whole lowering contract. Keep the
            # recovered edge/callee prototype, but do not let CFunctionCall
            # substitute the guest function's declaration name or invent a
            # function-pointer cast for the wrapper.
            emitted_target = far_binding[1]
            emitted_target_func = None
            emitted_prototype = callsite_prototype or (target_func.prototype if target_func is not None else None)

        call_tags = dict(expr.tags if tags is None else tags)
        if converted_argument_indices:
            call_tags[_CONVERTED_POINTER_ARGUMENTS_TAG] = converted_argument_indices
        return (
            CFunctionCall(
                emitted_target,
                emitted_target_func,
                args,
                tags=call_tags,
                show_demangled_name=self.show_demangled_name,
                show_disambiguated_name=self.show_disambiguated_name,
                callsite_prototype=emitted_prototype,
                result_used=result_used,
                codegen=self,
            ),
            target_func,
            far_binding,
        )

    def _scope_internal_far_call(
        self,
        statement: CStatement,
        binding: tuple[str, str, str | None, str | None],
        *,
        tags=None,
    ) -> CStatements:
        kind, segment_symbol, begin_helper, end_helper = binding
        if kind != "internal" or begin_helper is None or end_helper is None:
            raise UnsupportedNodeTypeError("Invalid internal far-call binding reached C code generation")

        segment_type = self.default_simtype_from_bits(self.project.arch.bits, signed=False)
        segment = CRegister(segment_symbol, tags=tags, codegen=self)
        segment.set_type(segment_type)
        begin_call = CFunctionCall(
            begin_helper,
            None,
            [segment],
            callsite_prototype=SimTypeFunction([segment_type], None).with_arch(self.project.arch),
            result_used=False,
            tags=tags,
            codegen=self,
        )
        end_call = CFunctionCall(
            end_helper,
            None,
            [],
            callsite_prototype=SimTypeFunction([], None).with_arch(self.project.arch),
            result_used=False,
            tags=tags,
            codegen=self,
        )
        return CStatements(
            [
                CExpressionStatement(begin_call, returning=True, tags=tags, codegen=self),
                statement,
                CExpressionStatement(end_call, returning=True, tags=tags, codegen=self),
            ],
            codegen=self,
        )

    def _handle_Stmt_Store(self, stmt: Stmt.Store, **kwargs):
        cdata = self._handle(stmt.data)

        store_bits = stmt.size * self.project.arch.byte_width
        if cdata.type is not None and cdata.type.size != store_bits:
            # AIL stores exactly stmt.size bytes even if type recovery assigns a wider C type to the value. Keep the
            # destination access and the value conversion at the actual memory width so generated C has the same
            # truncation semantics as the lifted store.
            cdata = CTypeCast(
                cdata.type,
                self.default_simtype_from_bits(store_bits, signed=False),
                cdata,
                codegen=self,
            )

        def negotiate(old_ty, proposed_ty):
            # transfer casts from the dst to the src if possible
            # if we see something like *(size_t*)&v4 = x; where v4 is a pointer, change to v4 = (void*)x;
            nonlocal cdata
            if old_ty != proposed_ty and qualifies_for_simple_cast(old_ty, proposed_ty):
                cdata = CTypeCast(cdata.type, proposed_ty, cdata, codegen=self)
                return proposed_ty
            return old_ty

        exact_stack_binding = segmented_stack_variable(self.kb.dec_variables[self._func.addr], stmt.addr, stmt.size)
        stmt_var = exact_stack_binding[0] if exact_stack_binding is not None else self._variable_map.variable(stmt)
        segmented_stack_access = (
            isinstance(stmt.addr, Expr.SegmentedAddress)
            and stmt.addr.address_kind == "x86-protected-16:16"
            and self._segmented_address_uses_stack_selector(stmt.addr)
            and isinstance(stmt_var, SimStackVariable)
        )
        if isinstance(stmt.addr, Expr.SegmentedAddress) and not segmented_stack_access:
            if stmt.guard is not None:
                raise UnsupportedNodeTypeError("Guarded segmented-memory stores are not supported")
            segmented_offset, native_stack_address = self._classify_segmented_memory_offset(stmt.addr)
            if native_stack_address:
                cdst = self._access(
                    segmented_offset,
                    cdata.type if cdata.type is not None else SimTypeBottom(),
                    True,
                    negotiate,
                )
                self._remember_native_stack_pointer_assignment(cdst, cdata)
                return CAssignment(cdst, cdata, tags=stmt.tags, codegen=self)
            call = self._segmented_memory_helper_call(
                stmt.addr,
                stmt.size,
                stmt.endness,
                data=cdata,
                offset=segmented_offset,
                tags=stmt.tags,
            )
            return CExpressionStatement(call, tags=stmt.tags, codegen=self)
        if _contains_segmented_address(stmt.addr) and not segmented_stack_access:
            raise UnsupportedNodeTypeError(
                "Segmented-memory stores require an exact SegmentedAddress; refusing a native pointer dereference"
            )

        if stmt_var is not None and cdata.type is not None:
            offset = (
                exact_stack_binding[1]
                if exact_stack_binding is not None
                else self._variable_map.variable_offset(stmt) or 0
            )
            assert type(offset) is int  # I refuse to deal with the alternative
            if segmented_stack_access and self._segmented_stack_access_needs_exact_view(stmt_var, stmt.size, offset):
                cdst = self._segmented_stack_access(stmt_var, stmt.size, offset, stmt.tags)
            else:
                cvar = self._variable(stmt_var, stmt.size)
                cdst = self._access_constant_offset(
                    self._get_variable_reference(cvar), offset, cdata.type, True, negotiate
                )
        else:
            addr_expr = self._handle(stmt.addr)
            cdst = self._access(addr_expr, cdata.type if cdata.type is not None else SimTypeBottom(), True, negotiate)

        self._remember_native_stack_pointer_assignment(cdst, cdata)
        return CAssignment(cdst, cdata, tags=stmt.tags, codegen=self)

    def variables_unify(self, v1: Expr.VirtualVariable, v2: Expr.VirtualVariable) -> bool:
        vmi = self.kb.dec_variables[self._func.addr]
        v1_var = self._variable_map.variable(v1)
        v2_var = self._variable_map.variable(v2)
        v1v = vmi.unified_variable(v1_var) if v1_var is not None else None
        v2v = vmi.unified_variable(v2_var) if v2_var is not None else None
        return v1v == v2v

    def _handle_Stmt_Assignment(self, stmt, **kwargs):
        far_binding = None
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
                    csrc = CTypeCast(csrc.type, proposed_ty, csrc, codegen=self)
                    return proposed_ty
                return old_ty

            assert dst_type is not None
            cdst = self._access_constant_offset(self._get_variable_reference(cvar), offset, dst_type, True, negotiate)
        else:
            if isinstance(stmt.src, Expr.Call) and getattr(stmt.src, "transfer_kind", "unknown") == "far":
                csrc, _, far_binding = self._build_call_expression(stmt.src, result_used=True)
            else:
                csrc = self._handle(stmt.src, lvalue=False)
            cdst = self._handle(stmt.dst, lvalue=True)
            if csrc.type is not None and cdst.type is not None and cdst.type != csrc.type:
                csrc = CTypeCast(csrc.type, cdst.type, csrc, codegen=self)

        self._remember_native_stack_pointer_assignment(cdst, csrc)
        assignment = CAssignment(cdst, csrc, tags=stmt.tags, codegen=self)
        if far_binding is not None and far_binding[0] == "internal":
            lowered_assignment = self._scope_internal_far_call(assignment, far_binding, tags=stmt.tags)
        else:
            lowered_assignment = assignment

        if (
            isinstance(stmt.dst, Expr.VirtualVariable)
            and stmt.dst.was_reg
            and not stmt.tags.get("ambient_register_state_reload", False)
            and (binding := self._register_state_bindings.get((stmt.dst.reg_offset, stmt.dst.size))) is not None
        ):
            # A bound architectural register is mutable ambient state, but its historical SSA versions must remain
            # ordinary locals. Evaluate the machine definition exactly once into the local, then mirror that captured
            # value to the embedding runtime. In particular, this ordering gives every definition produced by one
            # instruction an RHS that cannot be changed by an earlier C assignment.
            bound_register = CRegister(binding, tags=stmt.tags, codegen=self)
            bound_register.set_type(self.default_simtype_from_bits(stmt.dst.bits, signed=False))
            local_value = self._handle(stmt.dst, lvalue=False)
            write_through = CAssignment(bound_register, local_value, tags=stmt.tags, codegen=self)
            return CStatements([lowered_assignment, write_through], codegen=self)

        return lowered_assignment

    def _handle_Stmt_SideEffectStatement(self, stmt: Stmt.SideEffectStatement, is_expr: bool = False, **kwargs):
        far_binding = self._resolve_far_call_binding(stmt.expr)
        if is_expr and far_binding is not None and far_binding[0] == "internal":
            raise UnsupportedNodeTypeError(
                "Internal far calls require a statement boundary for begin/call/end lowering"
            )
        ret_expr = None
        if not is_expr and stmt.ret_expr is not None:
            ret_expr = self._handle(stmt.ret_expr)

        call_expr, target_func, far_binding = self._build_call_expression(
            stmt.expr,
            result_used=is_expr or ret_expr is not None,
            tags=stmt.tags,
        )

        if is_expr:
            # Used as an expression (e.g. nested in another expression)
            if call_expr.type.size != stmt.size * self.project.arch.byte_width:
                call_expr = _coerce_scalar_expression(
                    call_expr,
                    self.default_simtype_from_bits(
                        stmt.size * self.project.arch.byte_width, signed=getattr(call_expr.type, "signed", False)
                    ),
                    self,
                )
            return call_expr

        returning = target_func is None or target_func.returning is not False

        if ret_expr is not None:
            # ret_expr = call()  =>  CAssignment(ret_expr, call_expr)
            statement = CAssignment(ret_expr, call_expr, tags=stmt.tags, codegen=self)
        else:
            # Standalone call statement
            statement = CExpressionStatement(call_expr, returning=returning, tags=stmt.tags, codegen=self)

        if far_binding is not None and far_binding[0] == "internal":
            return self._scope_internal_far_call(statement, far_binding, tags=stmt.tags)
        return statement

    def _handle_Expr_Call(self, expr: Expr.Call, **kwargs):
        """Handle a Call expression (not wrapped in SideEffectStatement)."""
        far_binding = self._resolve_far_call_binding(expr)
        if far_binding is not None and far_binding[0] == "internal":
            raise UnsupportedNodeTypeError(
                "Internal far calls require a statement boundary for begin/call/end lowering"
            )
        call_expr, _, _ = self._build_call_expression(expr, result_used=True)

        if expr.bits and call_expr.type is not None and call_expr.type.size != expr.size * self.project.arch.byte_width:
            call_expr = _coerce_scalar_expression(
                call_expr,
                self.default_simtype_from_bits(
                    expr.size * self.project.arch.byte_width, signed=getattr(call_expr.type, "signed", False)
                ),
                self,
            )
        return call_expr

    def _coerce_call_argument(
        self,
        argument: CExpression,
        expected_type: SimType | None,
        *,
        guest_near_pointer_boundary: bool = False,
    ) -> CExpression:
        """Make recovered call-site ABI conversions explicit in generated C.

        AIL operands are fixed-width bit vectors, while C rejects implicit
        integer/pointer and incompatible-pointer conversions at a prototype
        boundary.  If type recovery supplied a scalar ABI type, retain that
        evidence as a required cast instead of relying on implementation-
        defined implicit conversion.  Aggregate arguments are deliberately
        left alone: C has no aggregate cast, and inventing one would hide an
        unresolved recovery error.
        """

        self._reject_native_stack_pointer_at_guest_near_call_boundary(
            argument,
            expected_type,
            guest_near_pointer_boundary=guest_near_pointer_boundary,
        )
        return _coerce_scalar_expression(argument, expected_type, self, force_numeric=True)

    def _handle_Stmt_Jump(self, stmt: Stmt.Jump, **kwargs):
        if getattr(stmt, "transfer_kind", "unknown") == "far":
            raise UnsupportedNodeTypeError(
                "Far jumps require an explicit guest control-transfer binding; refusing flat goto lowering"
            )
        return CGoto(self._handle(stmt.target), stmt.target_idx, tags=stmt.tags, codegen=self)

    def _handle_Stmt_ConditionalJump(self, stmt: Stmt.ConditionalJump, **kwargs):
        else_node = (
            None
            if stmt.false_target is None
            else CGoto(self._handle(stmt.false_target), None, tags=stmt.tags, codegen=self)
        )
        return CIfElse(
            [(self._handle(stmt.condition), CGoto(self._handle(stmt.true_target), None, tags=stmt.tags, codegen=self))],
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
            goto = CGoto(target_addr, target_idx, tags=stmt.tags, codegen=self)
            if isinstance(case_value, str):
                if case_value == "default":
                    default_goto = goto
                continue
            cond = CBinaryOp(
                "CmpEQ",
                switch_var,
                CConstant(case_value, const_type, codegen=self, tags=stmt.tags),
                codegen=self,
                tags=stmt.tags,
            )
            condition_and_nodes.append((cond, goto))
        if not condition_and_nodes:
            return default_goto if default_goto is not None else CUnsupportedStatement(stmt, codegen=self)
        return CIfElse(
            condition_and_nodes,
            else_node=default_goto,
            cstyle_ifs=self.cstyle_ifs,
            tags=stmt.tags,
            codegen=self,
        )

    def _handle_Stmt_Return(self, stmt: Stmt.Return, **kwargs):
        if not stmt.ret_exprs:
            return CReturn(None, tags=stmt.tags, codegen=self)
        if len(stmt.ret_exprs) == 1:
            ret_expr = stmt.ret_exprs[0]
            return CReturn(self._handle(ret_expr), tags=stmt.tags, codegen=self)

        combined = self._combine_return_expressions(stmt.ret_exprs, stmt.tags)
        if combined is None:
            return CUnsupportedStatement(stmt, tags=stmt.tags, codegen=self)
        return CReturn(combined, tags=stmt.tags, codegen=self)

    def _combine_return_expressions(self, ret_exprs, tags) -> CExpression | None:
        """Reassemble a split scalar return value from least-significant-first ABI locations."""

        prototype = self._func.prototype
        calling_convention = self._func.calling_convention
        if prototype is None or prototype.returnty is None or calling_convention is None:
            return None

        return_type = (
            dereference_simtype_by_lib(prototype.returnty, self._func.prototype_libname)
            if self._func.prototype_libname
            else prototype.returnty
        )
        try:
            return_location = calling_convention.return_val(return_type)
        except (TypeError, ValueError):
            return None
        if not isinstance(return_location, SimComboArg) or len(return_location.locations) != len(ret_exprs):
            return None

        location_bits = [location.size * self.project.arch.byte_width for location in return_location.locations]
        expression_bits = [getattr(expression, "bits", None) for expression in ret_exprs]
        if expression_bits != location_bits:
            return None

        total_bits = sum(location_bits)
        if return_type.size != total_bits:
            return None
        unsigned_type = self.default_simtype_from_bits(total_bits, signed=False)

        combined = None
        bit_offset = 0
        for expression, width in zip(ret_exprs, expression_bits):
            part = self._handle(expression)
            cast_tags = {**tags, _REQUIRED_CAST_TAG: True}
            part = CTypeCast(part.type, unsigned_type, part, tags=cast_tags, codegen=self)
            if bit_offset:
                part = CBinaryOp(
                    "Shl",
                    part,
                    CConstant(bit_offset, unsigned_type, tags=tags, codegen=self),
                    tags=tags,
                    codegen=self,
                )
            combined = part if combined is None else CBinaryOp("Or", combined, part, tags=tags, codegen=self)
            bit_offset += width

        assert combined is not None
        return CTypeCast(combined.type, return_type, combined, tags=tags, codegen=self)

    def _handle_Stmt_Label(self, stmt: Stmt.Label, **kwargs):
        clabel = self._labels_by_name.get(stmt.name)
        duplicate = clabel is not None
        if clabel is None:
            clabel = CLabel(stmt.name, tags=stmt.tags, codegen=self)
            self._labels_by_name[stmt.name] = clabel
        if "ins_addr" in stmt.tags:
            self.map_addr_to_label[(stmt.tags["ins_addr"], stmt.tags.get("block_idx"))] = clabel
        return CStatements([], codegen=self) if duplicate else clabel

    def _handle_Stmt_Dirty(self, stmt: Stmt.DirtyStatement, **kwargs):
        dirty = self._handle(stmt.dirty)
        return CDirtyStatement(dirty, codegen=self)

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

        if isinstance((post_call_register := expr.tags.get("post_call_register_state")), str):
            bound_register = CRegister(post_call_register, tags=expr.tags, codegen=self)
            bound_register.set_type(self.default_simtype_from_bits(expr.bits, signed=False))
            return bound_register

        if (binding := self._register_state_bindings.get((expr.reg_offset, expr.size))) is not None:
            bound_register = CRegister(binding, tags=expr.tags, codegen=self)
            bound_register.set_type(self.default_simtype_from_bits(expr.bits, signed=False))
            return bound_register

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
        return CRegister(expr, tags=expr.tags, codegen=self)

    def _handle_Expr_Load(self, expr: Expr.Load, **kwargs):
        if expr.size == UNDETERMINED_SIZE:
            # the size is undetermined; we force it to 1
            expr_size = 1
            expr_bits = 8
        else:
            expr_size = expr.size
            expr_bits = expr.bits

        if expr.size > 100 and isinstance(expr.addr, Expr.Const):
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

        exact_stack_binding = segmented_stack_variable(self.kb.dec_variables[self._func.addr], expr.addr, expr_size)
        expr_var = exact_stack_binding[0] if exact_stack_binding is not None else self._variable_map.variable(expr)
        segmented_stack_access = (
            isinstance(expr.addr, Expr.SegmentedAddress)
            and expr.addr.address_kind == "x86-protected-16:16"
            and self._segmented_address_uses_stack_selector(expr.addr)
            and isinstance(expr_var, SimStackVariable)
        )
        if isinstance(expr.addr, Expr.SegmentedAddress) and not segmented_stack_access:
            if expr.guard is not None or expr.alt is not None:
                raise UnsupportedNodeTypeError("Guarded segmented-memory loads are not supported")
            segmented_offset, native_stack_address = self._classify_segmented_memory_offset(expr.addr)
            if native_stack_address:
                return self._access(segmented_offset, ty, False, negotiate)
            return self._segmented_memory_helper_call(
                expr.addr,
                expr_size,
                expr.endness,
                offset=segmented_offset,
                tags=expr.tags,
            )
        if _contains_segmented_address(expr.addr) and not segmented_stack_access:
            raise UnsupportedNodeTypeError(
                "Segmented-memory loads require an exact SegmentedAddress; refusing a native pointer dereference"
            )

        if expr_var is not None:
            offset = (
                exact_stack_binding[1]
                if exact_stack_binding is not None
                else self._variable_map.variable_offset(expr) or 0
            )
            assert type(offset) is int  # I refuse to deal with the alternative
            if segmented_stack_access and self._segmented_stack_access_needs_exact_view(expr_var, expr_size, offset):
                return self._segmented_stack_access(expr_var, expr_size, offset, expr.tags)

            cvar = self._variable(expr_var, expr_size)
            return self._access_constant_offset(CUnaryOp("Reference", cvar, codegen=self), offset, ty, False, negotiate)

        addr_expr = self._handle(expr.addr)
        return self._access(addr_expr, ty, False, negotiate)

    def _handle_Expr_SegmentedAddress(self, expr: Expr.SegmentedAddress, **kwargs):
        raise UnsupportedNodeTypeError(
            f"Segmented address {expr.address_kind!r} cannot be emitted as a native C pointer"
        )

    def _handle_Expr_Tmp(self, expr: Tmp, **kwargs):
        l.warning("FIXME: Leftover Tmp expressions are found.")
        return self._variable(SimTemporaryVariable(expr.tmp_idx, expr.bits), expr.size)

    def _handle_Expr_Const(
        self,
        expr: Expr.Const,
        type_=None,
        reference_values: dict[SimType | str, str | bytes | int | float | Function | CExpression] | None = None,
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
                if expr.value in self.project.kb.functions and isinstance(type_, SimTypePointer):
                    # It's a function pointer
                    # We don't care about the actual prototype here. Do not infer a pointer from address equality
                    # alone: ordinary constants frequently collide with mapped function addresses (especially zero
                    # and 0x10000 in segmented programs).
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
        return CConstant(expr.value, type_, reference_values=reference_values, tags=expr.tags, codegen=self)

    def _handle_Expr_UnaryOp(self, expr, type_: SimType | None = None, **kwargs):
        data_type = None
        ref = False
        if expr.op == "Reference":
            ref = True
            if isinstance(type_, SimTypePointer) and not isinstance(type_.pts_to, SimTypeBottom):
                data_type = type_.pts_to

        operand = self._handle(expr.operand, lvalue=expr.op == "Reference", type_=data_type, ref=ref)

        operand_type = unpack_typeref(operand.type) if operand.type is not None else None
        if expr.op in {"Neg", "BitwiseNeg"} and isinstance(
            operand_type, (SimTypePointer, SimTypeArray, SimTypeFixedSizeArray)
        ):
            # AIL unary operations are bit-vector operations. C does not permit arithmetic negation or bitwise
            # complement directly on pointers, even when type recovery has assigned a pointer type to the machine
            # word. Preserve the machine operation with an explicit exact-width integer cast.
            operand = CTypeCast(
                operand.type,
                self.default_simtype_from_bits(expr.bits, signed=False),
                operand,
                codegen=self,
            )

        if expr.op == "Reference" and isinstance(operand, CUnaryOp) and operand.op == "Dereference":
            # cancel out
            return operand.operand
        return CUnaryOp(
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

        if expr.op == "Concat":
            result_type = self.default_simtype_from_bits(expr.bits, signed=False)
            cast_tags = {**expr.tags, _REQUIRED_CAST_TAG: True}
            lhs = CTypeCast(lhs.type, result_type, lhs, tags=cast_tags, codegen=self)
            rhs = CTypeCast(rhs.type, result_type, rhs, tags=cast_tags, codegen=self)
            shifted = CBinaryOp(
                "Shl",
                lhs,
                CConstant(expr.operands[1].bits, result_type, codegen=self),
                codegen=self,
            )
            return CBinaryOp("Or", shifted, rhs, tags=expr.tags, codegen=self)

        # Every AIL BinaryOp describes fixed-width machine arithmetic. Pointer types are a type-recovery aid, not
        # permission to apply C's scaled pointer arithmetic (and operations such as &, ^, and * are not legal on C
        # pointers at all). Cast pointer-like operands back to their exact-width unsigned bit-vector representation.
        # Loads and stores later cast the resulting numeric address to the requested pointer type.
        for operand_idx, (ail_operand, c_operand) in enumerate(((expr.operands[0], lhs), (expr.operands[1], rhs))):
            operand_type = unpack_typeref(c_operand.type) if c_operand.type is not None else None
            if isinstance(operand_type, (SimTypePointer, SimTypeArray, SimTypeFixedSizeArray)):
                converted = CTypeCast(
                    c_operand.type,
                    self.default_simtype_from_bits(ail_operand.bits, signed=False),
                    c_operand,
                    codegen=self,
                )
                if operand_idx == 0:
                    lhs = converted
                else:
                    rhs = converted

        if expr.op.startswith("Cmp"):
            # C promotes narrow arithmetic operands to int before comparing them. AIL operands are fixed-width
            # bit-vectors, so an expression such as ``uint16_max + carry`` must wrap to 16 bits before an unsigned
            # carry comparison observes it. Cast compound narrow operands at this semantic boundary; plain variables
            # and constants already denote values representable at their declared width.
            comparison_is_signed = expr.op.endswith("s")
            for operand_idx, (ail_operand, c_operand) in enumerate(((expr.operands[0], lhs), (expr.operands[1], rhs))):
                if ail_operand.bits not in {8, 16} or not isinstance(ail_operand, (BinaryOp, Expr.UnaryOp, Expr.ITE)):
                    continue
                exact_type = self.default_simtype_from_bits(ail_operand.bits, signed=comparison_is_signed)
                converted = CTypeCast(
                    c_operand.type,
                    exact_type,
                    c_operand,
                    tags={**expr.tags, _REQUIRED_CAST_TAG: True},
                    codegen=self,
                )
                if operand_idx == 0:
                    lhs = converted
                else:
                    rhs = converted

        return CBinaryOp(
            expr.op,
            lhs,
            rhs,
            tags=expr.tags,
            codegen=self,
            collapsed=expr.depth > self.binop_depth_cutoff,
        )

    def _handle_Expr_Convert(self, expr: Expr.Convert, **kwargs):
        if expr.from_type == Expr.Convert.TYPE_FP or expr.to_type == Expr.Convert.TYPE_FP:
            child = self._handle(expr.operand)
            if expr.to_type == Expr.Convert.TYPE_FP:
                dst_type = self.float_simtype_from_bits(expr.to_bits)
            else:
                dst_type = self.default_simtype_from_bits(expr.to_bits, signed=expr.is_signed)
            return CTypeCast(child.type, dst_type, child, tags=expr.tags, codegen=self)

        # width of converted type is easy
        dst_type: SimTypeInt | SimTypeChar
        if 512 >= expr.to_bits > 256:
            dst_type = SimTypeInt512()
        elif 256 >= expr.to_bits > 128:
            dst_type = SimTypeInt256()
        elif 128 >= expr.to_bits > 64:
            dst_type = SimTypeInt128()
        elif 64 >= expr.to_bits > 32:
            dst_type = SimTypeLongLong()
        elif 32 >= expr.to_bits > 16:
            dst_type = SimTypeInt()
        elif 16 >= expr.to_bits > 8:
            dst_type = SimTypeShort()
        elif 8 >= expr.to_bits > 1:
            dst_type = SimTypeChar()
        elif expr.to_bits == 1:
            dst_type = SimTypeChar()  # FIXME: Add a SimTypeBit?
        else:
            raise UnsupportedNodeTypeError(f"Unsupported conversion bits {expr.to_bits}.")

        # convert child
        child = self._handle(expr.operand)
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
            child = CTypeCast(None, child_ty, child, codegen=self)

        return CTypeCast(None, dst_type.with_arch(self.project.arch), child, tags=expr.tags, codegen=self)

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
                return CVariableField(child, CStructField(child_type, offset, field, codegen=self), codegen=self)
        if isinstance(child_type, (SimTypeChar, SimTypeInt, SimTypeNum, SimTypePointer)) and offset is not None:
            # Extract bits from scalar values arithmetically. Taking the address and loading a sub-object both changes
            # the meaning for pointer values (it reads the pointee) and produces invalid C for scalar rvalues.
            if expr.endness == "Iend_LE":
                shift = offset * self.project.arch.byte_width
            elif expr.endness == "Iend_BE":
                shift = expr.base.bits - expr.bits - offset * self.project.arch.byte_width
            else:
                shift = -1
            if shift >= 0 and shift + expr.bits <= expr.base.bits:
                source_type = self.default_simtype_from_bits(expr.base.bits, False)
                numeric_child = CTypeCast(child.type, source_type, child, codegen=self)
                if shift:
                    numeric_child = CBinaryOp(
                        "Shr",
                        numeric_child,
                        CConstant(shift, source_type, codegen=self),
                        codegen=self,
                    )
                if expr.bits < expr.base.bits:
                    numeric_child = CBinaryOp(
                        "And",
                        numeric_child,
                        CConstant((1 << expr.bits) - 1, source_type, codegen=self),
                        codegen=self,
                    )
                return CTypeCast(numeric_child.type, target_type, numeric_child, tags=expr.tags, codegen=self)

        voidp = SimTypePointer(SimTypeBottom()).with_arch(self.project.arch)
        inner_expr = CTypeCast(
            SimTypePointer(child_type).with_arch(self.project.arch),
            voidp,
            CUnaryOp("Reference", child, codegen=self),
            codegen=self,
        )
        if offset != 0:
            inner_expr = CBinaryOp(
                "Add",
                inner_expr,
                CConstant(offset, SimTypeInt(), codegen=self),
                codegen=self,
            )
        return CUnaryOp(
            "Dereference",
            CTypeCast(
                voidp,
                SimTypePointer(target_type).with_arch(self.project.arch),
                inner_expr,
                codegen=self,
            ),
            codegen=self,
        )

    def _handle_Expr_Insert(self, expr: Expr.Insert, **kwargs):
        if not isinstance(expr.offset, Expr.Const) or not isinstance(expr.offset.value, int):
            return CDirtyExpression(expr, tags=expr.tags, codegen=self)

        inserted_bits = min(expr.value.bits, expr.bits)
        if expr.endness == "Iend_LE":
            offset_bits = expr.offset.value * self.project.arch.byte_width
        elif expr.endness == "Iend_BE":
            offset_bits = expr.bits - inserted_bits - expr.offset.value * self.project.arch.byte_width
        else:
            offset_bits = -1
        if offset_bits < 0 or offset_bits + inserted_bits > expr.bits:
            return CDirtyExpression(expr, tags=expr.tags, codegen=self)

        result_type = self.default_simtype_from_bits(expr.bits, signed=False)
        base = self._handle(expr.base)
        value = self._handle(expr.value)
        base = CTypeCast(base.type, result_type, base, codegen=self)
        value = CTypeCast(value.type, result_type, value, codegen=self)

        full_mask = (1 << expr.bits) - 1
        value_mask = (1 << inserted_bits) - 1
        inserted_mask = value_mask << offset_bits
        cleared = CBinaryOp(
            "And",
            base,
            CConstant(full_mask ^ inserted_mask, result_type, codegen=self),
            codegen=self,
        )
        inserted = CBinaryOp(
            "And",
            value,
            CConstant(value_mask, result_type, codegen=self),
            codegen=self,
        )
        if offset_bits:
            inserted = CBinaryOp(
                "Shl",
                inserted,
                CConstant(offset_bits, result_type, codegen=self),
                codegen=self,
            )
        return CBinaryOp("Or", cleared, inserted, tags=expr.tags, codegen=self)

    def _handle_Expr_VEXCCallExpression(self, expr: Expr.VEXCCallExpression, **kwargs):
        operands = [self._handle(arg) for arg in expr.operands]
        return CVEXCCallExpression(expr.callee, operands, tags=expr.tags, codegen=self)

    def _handle_Expr_Dirty(self, expr: Expr.DirtyExpression, **kwargs):
        return CDirtyExpression(expr, codegen=self)

    def _handle_Expr_ITE(self, expr: Expr.ITE, **kwargs):
        return CITE(
            self._handle(expr.cond), self._handle(expr.iftrue), self._handle(expr.iffalse), tags=expr.tags, codegen=self
        )

    def _handle_Reinterpret(self, expr: Expr.Reinterpret, **kwargs):
        if expr.from_type == "I":
            src_type = self.default_simtype_from_bits(expr.from_bits, signed=False)
        elif expr.from_type == "F":
            src_type = self.float_simtype_from_bits(expr.from_bits)
        else:
            raise TypeError(f"Unexpected reinterpret type {expr.from_type}")
        if expr.to_type == "I":
            dst_type = self.default_simtype_from_bits(expr.to_bits, signed=False)
        elif expr.to_type == "F":
            dst_type = self.float_simtype_from_bits(expr.to_bits)
        else:
            raise TypeError(f"Unexpected reinterpret type {expr.to_type}")
        child = self._handle(expr.operand)
        if child.type != src_type:
            child = CTypeCast(child.type, src_type, child, tags=expr.tags, codegen=self)
        return CReinterpret(
            expr.from_bits,
            expr.from_type,
            expr.to_bits,
            expr.to_type,
            child,
            dst_type,
            tags=expr.tags,
            codegen=self,
        )

    def _handle_MultiStatementExpression(self, expr: Expr.MultiStatementExpression, **kwargs):
        statements: list[CStatement] = []

        def append_statement(cstmt: CStatement) -> None:
            # A single AIL assignment may lower to multiple C assignments (for example, a local SSA snapshot followed
            # by an ambient-register write-through). MultiStatementExpression renders its statements with comma
            # separators, so retaining a nested CStatements would give both the inner and outer sequence a trailing
            # separator and emit invalid `..., , ...` C. Flatten all such lowering sequences at this expression
            # boundary while preserving their exact order.
            if isinstance(cstmt, CStatements):
                for nested in cstmt.statements:
                    append_statement(nested)
            else:
                statements.append(cstmt)

        for stmt in expr.stmts:
            append_statement(self._handle(stmt, is_expr=False))
        cstmts = CStatements(statements, codegen=self)
        cexpr = self._handle(expr.expr)
        return CMultiStatementExpression(cstmts, cexpr, tags=expr.tags, codegen=self)

    def _handle_VirtualVariable(
        self,
        expr: Expr.VirtualVariable,
        lvalue: bool = False,
        type_: SimType | None = None,
        ref: bool = False,
        **kwargs,
    ):
        if expr.was_reg and isinstance((initial_register := expr.tags.get("initial_register_state")), str):
            bound_register = CRegister(initial_register, tags=expr.tags, codegen=self)
            bound_register.set_type(self.default_simtype_from_bits(expr.bits, signed=False))
            return bound_register

        expr_var = self._variable_map.variable(expr)
        if expr_var is not None:
            cvar = self._variable(expr_var, None, vvar_id=expr.varid)
            initial_seed = expr.tags.get(_INITIAL_REGISTER_STATE_SEED_TAG)
            if (
                not isinstance(initial_seed, str)
                and expr.was_reg
                and expr.tags.get(_AMBIENT_REGISTER_STATE_SEED_TAG, False)
            ):
                initial_seed = self._register_state_bindings.get((expr.reg_offset, expr.size))
            if isinstance(initial_seed, str):
                # A loop-header phi merges the explicit machine-entry binding with values produced by backedges. It
                # is a mutable C local, not a permanently bound register expression. Ambient-bound entry definitions
                # use the same initializer mechanism so every historical SSA version remains independent.
                cvar.tags[_INITIAL_REGISTER_STATE_SEED_TAG] = initial_seed

            # P-code represents x87 values as exact bit-vectors and wraps semantic FP uses in Reinterpret nodes. Its
            # 16-bit architecture metadata also cannot name a native 64-bit C integer. Type recovery may therefore
            # label a 64- or 80-bit register/memory carrier as an ordinary narrow integer. Keep every such AIL carrier
            # at its actual width; Reinterpret is responsible for exposing floating-point meaning at arithmetic sites.
            if expr.bits in {64, 80} and (cvar.type is None or cvar.type.size != expr.bits):
                cvar.variable_type = self.default_simtype_from_bits(expr.bits, signed=False)

            storage_type = unpack_typeref(cvar.type) if cvar.type is not None else None
            storage_width = getattr(storage_type, "size", None)
            if storage_type is None or (
                isinstance(storage_type, (SimTypeArray, SimTypeFixedSizeArray)) or storage_width != expr.bits
            ):
                access_type = self.default_simtype_from_bits(expr.bits, signed=False)
                l.debug(
                    "VirtualVariable width (%d bits) and storage type width (%s bits) do not match. "
                    "Use a scalar storage view.",
                    expr.bits,
                    storage_width,
                )
            else:
                # Preserve recovered same-width scalar and pointer semantics.
                # Aggregate storage has already selected an exact integer view
                # above because a C aggregate expression is not an AIL value.
                access_type = storage_type

            cvar.variable_type = access_type.with_arch(self.project.arch)
            cvar.tags = {
                **cvar.tags,
                _EXACT_STORAGE_ACCESS_TAG: True,
                _EXACT_STORAGE_OFFSET_TAG: self._variable_map.variable_offset(expr) or 0,
            }
            self._apply_native_stack_frame_to_cvariable(cvar)
            return cvar
        if expr.was_reg and isinstance(expr.oident, int):
            register_name = expr.tags.get("reg_name")
            if not isinstance(register_name, str):
                register_name = self.project.arch.translate_register_name(expr.oident, expr.size)
            if isinstance(register_name, str) and CDirtyExpression._IDENT_RE.fullmatch(register_name):
                return CRegister(register_name.lower(), tags=expr.tags, codegen=self)
        return CDirtyExpression(expr, codegen=self)

    def _handle_Expr_StackBaseOffset(self, expr: StackBaseOffset, **kwargs):
        expr_var = self._variable_map.variable(expr)
        if expr_var is not None:
            var_thing = self._variable(expr_var, expr.size)
            var_thing.tags = dict(expr.tags)
            if "def_at" in var_thing.tags and "ins_addr" not in var_thing.tags:
                var_thing.tags["ins_addr"] = var_thing.tags["def_at"].tags["ins_addr"]
            return self._get_variable_reference(var_thing)

        # FIXME
        stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=self)
        return CBinaryOp("Add", stack_base, CConstant(expr.offset, SimTypeInt(), codegen=self), codegen=self)

    #
    # Serialization
    #

    @classmethod
    def _get_cmsg(cls):
        from angr.protos import codegen_pb2  # pylint:disable=import-outside-toplevel

        return codegen_pb2.Codegen()  # pylint:disable=no-member

    def serialize_to_cmessage(self):
        from . import c_serialize  # pylint:disable=import-outside-toplevel

        return c_serialize.serialize_codegen(self)

    @classmethod
    def parse_from_cmessage(cls, cmsg, *, project=None, kb=None, func=None, **kwargs):
        from . import c_serialize  # pylint:disable=import-outside-toplevel

        return c_serialize.parse_codegen(cmsg, project=project, kb=kb, func=func)


class CStructuredCodeWalker:
    def handle(self, obj):
        handler = getattr(self, "handle_" + type(obj).__name__, self.handle_default)
        return handler(obj)

    def handle_default(self, obj):
        return obj

    def handle_CFunction(self, obj):
        obj.statements = self.handle(obj.statements)
        return obj

    def handle_CStatements(self, obj):
        obj.statements = [self.handle(stmt) for stmt in obj.statements]
        return obj

    def handle_CWhileLoop(self, obj):
        obj.condition = self.handle(obj.condition)
        obj.body = self.handle(obj.body)
        return obj

    def handle_CDoWhileLoop(self, obj):
        obj.condition = self.handle(obj.condition)
        obj.body = self.handle(obj.body)
        return obj

    def handle_CForLoop(self, obj):
        obj.initializer = self.handle(obj.initializer)
        obj.condition = self.handle(obj.condition)
        obj.iterator = self.handle(obj.iterator)
        obj.body = self.handle(obj.body)
        return obj

    def handle_CIfElse(self, obj):
        obj.condition_and_nodes = [
            (self.handle(condition), self.handle(node)) for condition, node in obj.condition_and_nodes
        ]
        obj.else_node = self.handle(obj.else_node)
        return obj

    def handle_CIfBreak(self, obj):
        obj.condition = self.handle(obj.condition)
        return obj

    def handle_CSwitchCase(self, obj):
        obj.switch = self.handle(obj.switch)
        obj.cases = [(case, self.handle(body)) for case, body in obj.cases]
        obj.default = self.handle(obj.default)
        return obj

    def handle_CAssignment(self, obj):
        obj.lhs = self.handle(obj.lhs)
        obj.rhs = self.handle(obj.rhs)
        return obj

    def handle_CExpressionStatement(self, obj):
        obj.expr = self.handle(obj.expr)
        return obj

    def handle_CFunctionCall(self, obj):
        obj.callee_target = self.handle(obj.callee_target)
        obj.args = [self.handle(arg) for arg in obj.args]
        return obj

    def handle_CReturn(self, obj):
        obj.retval = self.handle(obj.retval)
        return obj

    def handle_CGoto(self, obj):
        obj.target = self.handle(obj.target)
        return obj

    def handle_CIndexedVariable(self, obj):
        obj.variable = self.handle(obj.variable)
        obj.index = self.handle(obj.index)
        return obj

    def handle_CVariableField(self, obj):
        obj.variable = self.handle(obj.variable)
        return obj

    def handle_CUnaryOp(self, obj):
        obj.operand = self.handle(obj.operand)
        return obj

    def handle_CBinaryOp(self, obj):
        obj.lhs = self.handle(obj.lhs)
        obj.rhs = self.handle(obj.rhs)
        return obj

    def handle_CTypeCast(self, obj):
        obj.expr = self.handle(obj.expr)
        return obj

    def handle_CITE(self, obj):
        obj.cond = self.handle(obj.cond)
        obj.iftrue = self.handle(obj.iftrue)
        obj.iffalse = self.handle(obj.iffalse)
        return obj


class _UnsupportedAILExpressionCollector(AILBlockViewer):
    def __init__(self, record, cnode: CConstruct, root: Expr.Expression):
        super().__init__()
        self._record = record
        self._cnode = cnode
        self._root = root

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr is not self._root:
            operation = getattr(expr, "callee", None)
            if operation is None:
                operation = getattr(expr, "kind", None)
            self._record(
                "dirty_expression",
                operation,
                self._cnode,
                source=expr,
                fallback_source=self._root,
            )
        return super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op not in CUnaryOp._OPERATION_HANDLERS:
            self._record(
                "unary_operation",
                expr.op,
                self._cnode,
                source=expr,
                fallback_source=self._root,
            )
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op not in CBinaryOp._OPERATION_HANDLERS:
            self._record(
                "binary_operation",
                expr.op,
                self._cnode,
                source=expr,
                fallback_source=self._root,
            )
        return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)


class _UnsupportedSegmentedAddressCollector(AILBlockViewer):
    def __init__(self, record, cnode: CConstruct, root: Stmt.Statement):
        super().__init__()
        self._record = record
        self._cnode = cnode
        self._root = root

    def _handle_SegmentedAddress(self, expr_idx, expr, stmt_idx, stmt, block):
        self._record(
            "segmented_address",
            expr.address_kind,
            self._cnode,
            source=expr,
            fallback_source=self._root,
        )
        return super()._handle_SegmentedAddress(expr_idx, expr, stmt_idx, stmt, block)


class _UnsupportedConstructCollector:
    def __init__(self):
        self._occurrences: dict[
            tuple[str, str],
            list[UnsupportedConstructLocation],
        ] = defaultdict(list)

    def handle(self, obj) -> None:
        if not isinstance(obj, CConstruct):
            return

        if isinstance(obj, CAILBlock):
            self._record("ail_block", "Block", obj, source=obj.block)
        elif isinstance(obj, CUnsupportedStatement):
            diagnostic_kind = obj.tags.get(_UNSUPPORTED_DIAGNOSTIC_KIND_TAG)
            diagnostic_operation = obj.tags.get(_UNSUPPORTED_DIAGNOSTIC_OPERATION_TAG)
            if isinstance(diagnostic_kind, str) and isinstance(diagnostic_operation, str):
                self._record(diagnostic_kind, diagnostic_operation, obj, source=obj.stmt)
            else:
                self._record("unsupported_statement", getattr(obj.stmt, "kind", None), obj, source=obj.stmt)
            _UnsupportedSegmentedAddressCollector(self._record, obj, obj.stmt).walk_statement(obj.stmt)
        elif isinstance(obj, CGoto):
            if not isinstance(obj.target, int):
                self._record("indirect_goto", "computed-target", obj)
            elif obj.codegen is None or (obj.target, obj.target_idx) not in obj.codegen.map_addr_to_label:
                self._record("unresolved_goto", f"{obj.target:#x}", obj)
        elif isinstance(obj, CDirtyExpression):
            operation = getattr(obj.dirty, "callee", None)
            if operation is None:
                operation = getattr(obj.dirty, "kind", None)
            self._record("dirty_expression", operation, obj, source=obj.dirty)
            _UnsupportedAILExpressionCollector(self._record, obj, obj.dirty).walk_expression(obj.dirty)
        elif isinstance(obj, CFunctionCall) and (
            # The tag is only installed while coercing a call at a consumed scalar boundary. Treat it as independent
            # structural evidence so a legacy cache's default-false result_used field cannot hide the conflict.
            obj.tags.get(_VOID_CALL_RESULT_TAG, False)
            or (obj.result_used and (_is_void_type(obj.prototype_returnty) or obj.current_callee_prototype_is_void))
        ):
            self._record("void_call_value", "call-result-consumed", obj)
        elif isinstance(obj, CExpression) and obj.collapsed:
            # ``...`` is useful in an interactive UI, but it is not executable C and must be visible to consumers
            # deciding whether a decompilation result is complete.
            self._record("collapsed_expression", type(obj).__name__, obj)
        elif isinstance(obj, CUnaryOp) and obj.op not in CUnaryOp._OPERATION_HANDLERS:
            self._record("unary_operation", obj.op, obj)
        elif isinstance(obj, CBinaryOp) and obj.op not in CBinaryOp._OPERATION_HANDLERS:
            self._record("binary_operation", obj.op, obj)

        for cls in type(obj).__mro__:
            slots = cls.__dict__.get("__slots__", ())
            if isinstance(slots, str):
                slots = (slots,)
            for slot in slots:
                if slot in {"codegen", "ident", "idx", "tags"}:
                    continue
                self._visit_value(getattr(obj, slot, None))

    def _visit_value(self, value) -> None:
        if isinstance(value, CConstruct):
            self.handle(value)
        elif isinstance(value, dict):
            for item in value.values():
                self._visit_value(item)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                self._visit_value(item)

    @property
    def result(self) -> tuple[UnsupportedConstruct, ...]:
        result = []
        for (kind, operation), locations in sorted(self._occurrences.items()):
            ordered_locations = tuple(sorted(locations, key=self._location_sort_key))
            result.append(
                UnsupportedConstruct(
                    kind=kind,
                    operation=operation,
                    count=len(ordered_locations),
                    locations=ordered_locations,
                )
            )
        return tuple(result)

    @staticmethod
    def _location_sort_key(location: UnsupportedConstructLocation) -> tuple[tuple[bool, int], ...]:
        return tuple(
            (value is None, value if value is not None else 0)
            for value in (location.instruction_address, location.block_address, location.statement_index)
        )

    @staticmethod
    def _operation_name(value) -> str:
        if isinstance(value, str) and value:
            return value
        name = getattr(value, "name", None)
        if isinstance(name, str) and name:
            return name
        return type(value).__name__ if value is not None else "unknown"

    @staticmethod
    def _location(obj, source=None, fallback_source=None) -> UnsupportedConstructLocation:
        tags = {}
        if fallback_source is not None:
            tags.update(getattr(fallback_source, "tags", None) or {})
        if source is not None:
            tags.update(getattr(source, "tags", None) or {})
        tags.update(getattr(obj, "tags", None) or {})

        def int_tag(*names):
            for name in names:
                value = tags.get(name)
                if type(value) is int:
                    return value
            return None

        block_address = int_tag("vex_block_addr", "block_addr")
        if block_address is None and isinstance(obj, CAILBlock):
            value = getattr(obj.block, "addr", None)
            block_address = value if type(value) is int else None

        return UnsupportedConstructLocation(
            instruction_address=int_tag("ins_addr"),
            block_address=block_address,
            statement_index=int_tag("vex_stmt_idx", "stmt_idx"),
        )

    def _record(self, kind: str, operation, obj, source=None, fallback_source=None) -> None:
        key = kind, self._operation_name(operation)
        self._occurrences[key].append(self._location(obj, source=source, fallback_source=fallback_source))


class _ReapplyCallArgumentCoercions(CStructuredCodeWalker):
    """Restore exact call-boundary conversions after retained variable types change."""

    def handle_CFunctionCall(self, obj: CFunctionCall):
        prototype = obj.prototype
        prototype_args = () if prototype is None else prototype.args
        is_x86_pcode_swi = obj.callee_target == _X86_PCODE_SWI_TARGET and obj.codegen.project.arch.name in {
            "x86:LE:16:Protected Mode",
            "x86:LE:16:Real Mode",
        }
        is_guest_register_runtime = (
            is_x86_pcode_swi
            or obj.tags.get("indirect_far_call_dispatch", False)
            or obj.tags.get("indirect_near_call_dispatch", False)
        )
        converted_argument_indices = set(obj.tags.get(_CONVERTED_POINTER_ARGUMENTS_TAG, ()))
        for index, (argument, expected_type) in enumerate(zip(obj.args, prototype_args)):
            if index in converted_argument_indices:
                continue
            obj.args[index] = (
                obj.codegen._coerce_guest_register_argument(argument, expected_type)
                if is_guest_register_runtime
                else obj.codegen._coerce_call_argument(argument, expected_type)
            )
        return super().handle_CFunctionCall(obj)


class MakeTypecastsImplicit(CStructuredCodeWalker):
    @classmethod
    def collapse(cls, dst_ty: SimType, child: CExpression) -> CExpression:
        result = child
        if isinstance(child, CTypeCast) and not child.tags.get(_REQUIRED_CAST_TAG, False):
            intermediate_ty = child.dst_type
            start_ty = child.src_type

            # Pointer/integer casts are never implicit in the C operators that consume them. Removing one can turn
            # valid machine-word arithmetic into invalid C (for example ``(uint16_t)ptr & 0xff`` into
            # ``ptr & 0xff``). Only collapse redundant integer conversions here.
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

    def handle_CAssignment(self, obj):
        obj.rhs = self.collapse(obj.lhs.type, obj.rhs)
        return super().handle_CAssignment(obj)

    def handle_CFunctionCall(self, obj: CFunctionCall):
        prototype_args = [] if obj.prototype is None else obj.prototype.args
        for i, (c_arg, arg_ty) in enumerate(zip(obj.args, prototype_args)):
            obj.args[i] = self.collapse(arg_ty, c_arg)
        return super().handle_CFunctionCall(obj)

    def handle_CReturn(self, obj: CReturn):
        obj.retval = self.collapse(obj.codegen._func.prototype.returnty, obj.retval)
        return super().handle_CReturn(obj)

    def handle_CBinaryOp(self, obj: CBinaryOp):
        obj = super().handle_CBinaryOp(obj)
        while True:
            new_lhs = self.collapse(obj.common_type, obj.lhs)
            assert obj.rhs.type is not None and new_lhs.type is not None
            if (
                new_lhs is not obj.lhs
                and CBinaryOp.compute_common_type(obj.op, new_lhs.type, obj.rhs.type) == obj.common_type
            ):
                obj.lhs = new_lhs
            else:
                new_rhs = self.collapse(obj.common_type, obj.rhs)
                assert new_rhs.type is not None and obj.lhs.type is not None
                if (
                    new_rhs is not obj.rhs
                    and CBinaryOp.compute_common_type(obj.op, obj.lhs.type, new_rhs.type) == obj.common_type
                ):
                    obj.rhs = new_rhs
                else:
                    break
        return obj

    def handle_CTypeCast(self, obj: CTypeCast):
        # note that the expression that this method returns may no longer be a CTypeCast
        obj = super().handle_CTypeCast(obj)
        if obj.tags.get(_REQUIRED_CAST_TAG, False):
            return obj
        inner = self.collapse(obj.dst_type, obj.expr)
        assert inner.type is not None
        if inner is not obj.expr:
            obj.src_type = inner.type
            obj.expr = inner
        if obj.src_type == obj.dst_type or qualifies_for_implicit_cast(obj.src_type, obj.dst_type):
            return obj.expr
        return obj


class FieldReferenceCleanup(CStructuredCodeWalker):
    def handle_CTypeCast(self, obj):
        if isinstance(obj.dst_type, SimTypePointer) and not isinstance(obj.dst_type.pts_to, SimTypeBottom):
            new_obj = obj.codegen._access_reference(obj.expr, obj.dst_type.pts_to)
            if not isinstance(new_obj, CTypeCast):
                return self.handle(new_obj)
        return super().handle_CTypeCast(obj)


class PointerArithmeticFixer(CStructuredCodeWalker):
    """
    Before calling this fixer class, pointer arithmetics are purely integer-based and ignoring the pointer type.

    For example, in the following case:

    struct A* a_ptr;  // assume struct A is 24 bytes in size
    a_ptr = a_ptr + 24;

    It means adding 24 to the address of a_ptr, without considering the size of struct A. This fixer class will make
    pointer arithmetics aware of the pointer type. In this case, the fixer class will convert the code to
    a_ptr = a_ptr + 1.
    """

    def handle_CAssignment(self, obj: CAssignment):
        if "type" in obj.tags and "dst" in obj.tags["type"] and "src" in obj.tags["type"]:
            # HACK: do not attempt to fix pointer arithmetic if dst and src types are explicitly given
            # FIXME: Properly propagate dst and src types to lhs and rhs
            return obj
        return super().handle_CAssignment(obj)

    def handle_CBinaryOp(self, obj: CBinaryOp):  # type: ignore
        obj: CBinaryOp = super().handle_CBinaryOp(obj)
        if (
            obj.op in ("Add", "Sub")
            and isinstance(obj.type, SimTypePointer)
            and not isinstance(obj.type.pts_to, SimTypeBottom)
        ):
            out = obj.codegen._access_reference(obj, obj.type.pts_to)
            if (
                isinstance(out, CUnaryOp)
                and out.op == "Reference"
                and isinstance(out.operand, CIndexedVariable)
                and isinstance(out.operand.index, CConstant)
            ):
                # rewrite &a[1] to a + 1
                const = out.operand.index
                if isinstance(const.value, int) and const.value < 0:
                    op = "Sub"
                    const = CConstant(
                        -const.value,
                        const.type,
                        reference_values=const.reference_values,
                        tags=const.tags,
                        codegen=const.codegen,
                    )
                else:
                    op = "Add"
                return CBinaryOp(op, out.operand.variable, const, tags=out.operand.tags, codegen=out.codegen)
            return out
        return obj


# StructuredCodeGenerator = CStructuredCodeGenerator
register_analysis(CStructuredCodeGenerator, "CStructuredCodeGenerator")


# Register protobuf serializer/parser pairs for every concrete CConstruct subclass. Imported after all classes are
# defined so that ``c_serialize.register_all`` can reference them by name.
from . import c_serialize as _c_serialize  # noqa: E402  # pylint: disable=wrong-import-position

_c_serialize.register_all()
