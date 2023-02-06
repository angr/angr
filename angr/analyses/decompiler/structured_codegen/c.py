# pylint:disable=missing-class-docstring,too-many-boolean-expressions
from typing import Optional, Dict, List, Tuple, Set, Any, Union, TYPE_CHECKING, Callable
from collections import defaultdict
import logging
from functools import reduce

from ailment import Block, Expr, Stmt, Tmp
from ailment.expression import StackBaseOffset, BinaryOp

from ....sim_type import (
    SimTypeLongLong,
    SimTypeInt,
    SimTypeShort,
    SimTypeChar,
    SimTypePointer,
    SimStruct,
    SimType,
    SimTypeBottom,
    SimTypeArray,
    SimTypeFunction,
    SimTypeFloat,
    SimTypeDouble,
    TypeRef,
    SimTypeNum,
    SimTypeFixedSizeArray,
    SimTypeLength,
    SimTypeReg,
)
from ....sim_variable import SimVariable, SimTemporaryVariable, SimStackVariable, SimMemoryVariable
from ....utils.constants import is_alignment_mask
from ....utils.library import get_cpp_function_name
from ....utils.loader import is_in_readonly_segment, is_in_readonly_section
from ....errors import UnsupportedNodeTypeError
from ....knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from ... import Analysis, register_analysis
from ..region_identifier import MultiNode
from ..structuring.structurer_nodes import (
    SequenceNode,
    CodeNode,
    ConditionNode,
    ConditionalBreakNode,
    LoopNode,
    BreakNode,
    SwitchCaseNode,
    ContinueNode,
    CascadingConditionNode,
)
from .base import BaseStructuredCodeGenerator, InstructionMapping, PositionMapping, PositionMappingElement

if TYPE_CHECKING:
    import archinfo
    import angr
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
    from angr.knowledge_plugins.functions import Function


l = logging.getLogger(name=__name__)

INDENT_DELTA = 4


def unpack_typeref(ty):
    if isinstance(ty, TypeRef):
        return ty.type
    return ty


def unpack_pointer(ty) -> Optional[SimType]:
    if isinstance(ty, SimTypePointer):
        return ty.pts_to
    return None


def unpack_array(ty) -> Optional[SimType]:
    if isinstance(ty, SimTypeArray):
        return ty.elem_type
    if isinstance(ty, SimTypeFixedSizeArray):
        return ty.elem_type
    return None


def squash_array_reference(ty):
    pointed_to = unpack_pointer(ty)
    if pointed_to:
        array_of = unpack_array(pointed_to)
        if array_of:
            return SimTypePointer(array_of)
    return ty


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

    return ty1.size <= ty2.size


def extract_terms(expr: "CExpression") -> Tuple[int, List[Tuple[int, "CExpression"]]]:
    if isinstance(expr, CConstant):
        return expr.value, []
    # elif isinstance(expr, CUnaryOp) and expr.op == 'Minus'
    elif isinstance(expr, CBinaryOp) and expr.op == "Add":
        c1, t1 = extract_terms(expr.lhs)
        c2, t2 = extract_terms(expr.rhs)
        return c1 + c2, t1 + t2
    elif isinstance(expr, CBinaryOp) and expr.op == "Sub":
        c1, t1 = extract_terms(expr.lhs)
        c2, t2 = extract_terms(expr.rhs)
        return c1 - c2, t1 + [(-c, t) for c, t in t2]
    elif isinstance(expr, CBinaryOp) and expr.op == "Mul":
        if isinstance(expr.lhs, CConstant):
            c, t = extract_terms(expr.rhs)
            return c * expr.lhs.value, [(c1 * expr.lhs.value, t1) for c1, t1 in t]
        elif isinstance(expr.rhs, CConstant):
            c, t = extract_terms(expr.lhs)
            return c * expr.rhs.value, [(c1 * expr.rhs.value, t1) for c1, t1 in t]
        else:
            return 0, [(1, expr)]
    elif isinstance(expr, CBinaryOp) and expr.op == "Shl":
        if isinstance(expr.rhs, CConstant):
            c, t = extract_terms(expr.lhs)
            return c << expr.rhs.value, [(c1 << expr.rhs.value, t1) for c1, t1 in t]
        return 0, [(1, expr)]
    else:
        return 0, [(1, expr)]


def is_machine_word_size_type(type_: SimType, arch: "archinfo.Arch") -> bool:
    return isinstance(type_, SimTypeReg) and type_.size == arch.bits


def guess_value_type(value: int, project: "angr.Project") -> Optional[SimType]:
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


#
#   C Representation Classes
#


class CConstruct:
    """
    Represents a program construct in C.
    Acts as the base class for all other representation constructions.
    """

    __slots__ = ("codegen",)

    def __init__(self, codegen):
        self.codegen: "StructuredCodeGenerator" = codegen

    def c_repr(self, indent=0, pos_to_node=None, pos_to_addr=None, addr_to_pos=None):
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
            pos = 0

            last_insn_addr = None

            # track all Function Calls for highlighting
            used_func_calls = set()

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
                    if isinstance(
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
                        ),
                    ):
                        if pos_to_node is not None:
                            pos_to_node.add_mapping(pos, len(s), obj)
                    elif isinstance(obj, CFunctionCall):
                        if obj not in used_func_calls:
                            used_func_calls.add(obj)
                            if pos_to_node is not None:
                                pos_to_node.add_mapping(pos, len(s), obj)

                # add (), {}, and [] to mapping for highlighting as well as the full functions name
                elif isinstance(obj, (CClosingObject, CFunction)):
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
                    text = pending_stmt_comments.pop(last_insn_addr, None)
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
                    text = pending_expr_comments.pop(last_insn_addr, None)
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
        raise NotImplementedError()

    @staticmethod
    def indent_str(indent=0):
        return " " * indent


class CFunction(CConstruct):  # pylint:disable=abstract-method
    """
    Represents a function in C.
    """

    __slots__ = (
        "addr",
        "name",
        "functy",
        "arg_list",
        "statements",
        "variables_in_use",
        "variable_manager",
        "demangled_name",
    )

    def __init__(
        self,
        addr,
        name,
        functy: SimTypeFunction,
        arg_list: List["CVariable"],
        statements,
        variables_in_use,
        variable_manager,
        demangled_name=None,
        **kwargs,
    ):
        super().__init__(**kwargs)

        self.addr = addr
        self.name = name
        self.functy = functy
        self.arg_list = arg_list
        self.statements = statements
        self.variables_in_use = variables_in_use
        self.variable_manager: "VariableManagerInternal" = variable_manager
        self.demangled_name = demangled_name

    def variable_list_repr_chunks(self, indent=0):
        def _varname_to_id(varname: str) -> int:
            # extract id from default variable name "v{id}"
            if varname.startswith("v"):
                try:
                    return int(varname[1:])
                except ValueError:
                    pass
            return 0

        unified_to_var_and_types: Dict[SimVariable, Set[Tuple[CVariable, SimType]]] = defaultdict(set)

        arg_set: Set[SimVariable] = set()
        for arg in self.arg_list:
            # TODO: Handle CIndexedVariable
            if isinstance(arg, CVariable):
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

        indent_str = self.indent_str(indent)

        for variable, cvar_and_vartypes in sorted(
            unified_to_var_and_types.items(), key=lambda x: _varname_to_id(x[0].name) if x[0].name else 0
        ):
            yield indent_str, None

            # pick the first cvariable
            # this is enough since highlighting works on the unified variable
            try:
                cvariable = next(iter(cvar_and_vartypes))[0]
            except StopIteration:
                # this should never happen, but pylint complains
                continue

            if variable.name:
                name = variable.name
            elif isinstance(variable, SimTemporaryVariable):
                name = "tmp_%d" % variable.tmp_id
            else:
                name = str(variable)

            # sort by number of occurrences
            vartypes = [x[1] for x in cvar_and_vartypes]
            vartypes = list(dict.fromkeys(sorted(vartypes, key=vartypes.count, reverse=True)))

            for i, var_type in enumerate(vartypes):
                if i == 0:
                    if isinstance(var_type, SimType):
                        raw_type_str = var_type.c_repr(name=name)
                    else:
                        raw_type_str = f"{var_type} {name}"

                    assert name in raw_type_str
                    type_pre, type_post = raw_type_str.split(name, 1)
                    if type_pre.endswith(" "):
                        type_pre_spaces = " " * (len(type_pre) - len(type_pre.rstrip(" ")))
                        type_pre = type_pre.rstrip(" ")
                    else:
                        type_pre_spaces = ""
                    yield type_pre, var_type
                    if type_pre_spaces:
                        yield type_pre_spaces, None
                    yield name, cvariable
                    yield type_post, var_type
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

        if unified_to_var_and_types:
            yield "\n", None

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent)

        if self.codegen.show_local_types:
            local_types = [unpack_typeref(ty) for ty in self.variable_manager.types.iter_own()]
            for ty in local_types:
                if isinstance(ty, SimStruct):
                    for field in ty.fields.values():
                        if isinstance(field, SimTypePointer):
                            if isinstance(field.pts_to, (SimTypeArray, SimTypeFixedSizeArray)):
                                field = field.pts_to.elem_type
                            else:
                                field = field.pts_to
                        if isinstance(field, SimStruct) and field not in local_types:
                            local_types.append(field)
                c_repr = ty.c_repr(full=True)
                c_repr = f"typedef {c_repr} {ty._name}"
                first = True
                for line in c_repr.split("\n"):
                    if first:
                        first = False
                    else:
                        yield "\n", None
                    yield indent_str, None
                    yield line, None
                yield ";\n\n", None

        if self.codegen.show_externs and self.codegen.cexterns:
            for v in sorted(self.codegen.cexterns, key=lambda v: v.variable.name):
                if v.type is None:
                    varname = v.c_repr()
                    raw_typed_varname = f"<missing-type> {varname}"
                else:
                    varname = v.variable.name
                    raw_typed_varname = v.type.c_repr(name=varname)
                # FIXME: Add a .c_repr_chunks() to SimType so that we no longer need to parse the string output
                varname_pos = raw_typed_varname.rfind(varname)
                type_pre = raw_typed_varname[:varname_pos]
                if type_pre.endswith(" "):
                    type_pre_spaces = " " * (len(type_pre) - len(type_pre.rstrip(" ")))
                    type_pre = type_pre.rstrip(" ")
                else:
                    type_pre_spaces = ""
                type_post = raw_typed_varname[varname_pos + len(varname) :]
                yield "extern ", None
                yield type_pre, v.type
                if type_pre_spaces:
                    yield type_pre_spaces, None
                yield varname, v
                yield type_post, v.type
                yield ";\n", None
            yield "\n", None

        yield indent_str, None
        # return type
        yield self.functy.returnty.c_repr(name="").strip(" "), None
        yield " ", None
        # function name
        if self.demangled_name:
            normalized_name = get_cpp_function_name(self.demangled_name, specialized=False, qualified=False)
        else:
            normalized_name = self.name
        yield normalized_name, self
        # argument list
        paren = CClosingObject("(")
        brace = CClosingObject("{")
        yield "(", paren
        for i, (arg_type, arg) in enumerate(zip(self.functy.args, self.arg_list)):
            if i:
                yield ", ", None

            if isinstance(arg, CVariable):
                variable = arg.unified_variable if arg.unified_variable is not None else arg.variable
                variable_name = variable.name
            else:
                variable_name = arg.c_repr()
            raw_type_str: str = arg_type.c_repr(name=variable_name)
            # FIXME: Add a .c_repr_chunks() to SimType so that we no longer need to parse the string output
            assert variable_name in raw_type_str
            varname_pos = raw_type_str.rfind(variable_name)
            type_pre, type_post = raw_type_str[:varname_pos], raw_type_str[varname_pos + len(variable_name) :]
            if type_pre.endswith(" "):
                type_pre_spaces = " " * (len(type_pre) - len(type_pre.rstrip(" ")))
                type_pre = type_pre.rstrip(" ")
            else:
                type_pre_spaces = ""

            yield type_pre, arg_type
            if type_pre_spaces:
                yield type_pre_spaces, None
            yield variable_name, arg
            yield type_post, arg_type
        yield ")", paren
        # function body
        if self.codegen.braces_on_own_lines:
            yield "\n", None
            yield indent_str, None
        else:
            yield " ", None
        yield "{", brace
        yield "\n", None
        yield from self.variable_list_repr_chunks(indent=indent + INDENT_DELTA)
        yield from self.statements.c_repr_chunks(indent=indent + INDENT_DELTA)
        yield indent_str, None
        yield "}", brace
        yield "\n", None


class CStatement(CConstruct):  # pylint:disable=abstract-method
    """
    Represents a statement in C.
    """

    __slots__ = ()


class CExpression(CConstruct):
    """
    Base class for C expressions.
    """

    __slots__ = (
        "_type",
        "collapsed",
    )

    def __init__(self, collapsed=False, **kwargs):
        super().__init__(**kwargs)
        self._type = None
        self.collapsed = collapsed

    @property
    def type(self):
        raise NotImplementedError("Class %s does not implement type()." % type(self))

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

    __slots__ = ("statements",)

    def __init__(self, statements, **kwargs):
        super().__init__(**kwargs)

        self.statements = statements

    def c_repr_chunks(self, indent=0, asexpr=False):
        for stmt in self.statements:
            yield from stmt.c_repr_chunks(indent=indent, asexpr=asexpr)
            if asexpr:
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
        "condition",
        "body",
        "tags",
    )

    def __init__(self, condition, body, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.condition = condition
        self.body = body
        self.tags = tags

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
            yield from self.body.c_repr_chunks(indent=indent + INDENT_DELTA)
            yield indent_str, None
            yield "}", brace
            yield "\n", None


class CDoWhileLoop(CLoop):
    """
    Represents a do-while loop in C.
    """

    __slots__ = (
        "condition",
        "body",
        "tags",
    )

    def __init__(self, condition, body, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.condition = condition
        self.body = body
        self.tags = tags

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
            yield from self.body.c_repr_chunks(indent=indent + INDENT_DELTA)
            yield indent_str, None
            yield "}", brace
        else:
            yield "{", brace
            yield " ", None
            yield "}", brace
        if self.codegen.braces_on_own_lines:
            yield "\n", None
            yield indent_str, None
        else:
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

    __slots__ = ("initializer", "condition", "iterator", "body", "tags")

    def __init__(self, initializer, condition, iterator, body, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.initializer = initializer
        self.condition = condition
        self.iterator = iterator
        self.body = body

        self.tags = tags

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

        if self.codegen.braces_on_own_lines:
            yield "\n", None
            yield indent_str, None
        else:
            yield " ", None
        if self.body is not None:
            yield "{", brace
            yield "\n", None
            yield from self.body.c_repr_chunks(indent=indent + INDENT_DELTA)
            yield indent_str, None
            yield "}", brace
        else:
            yield ";", None
        yield "\n", None


class CIfElse(CStatement):
    """
    Represents an if-else construct in C.
    """

    __slots__ = ("condition_and_nodes", "else_node", "tags")

    def __init__(
        self, condition_and_nodes: List[Tuple[CExpression, Optional[CStatement]]], else_node=None, tags=None, **kwargs
    ):
        super().__init__(**kwargs)

        self.condition_and_nodes = condition_and_nodes
        self.else_node = else_node
        self.tags = tags

        if not self.condition_and_nodes:
            raise ValueError("You must specify at least one condition")

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        paren = CClosingObject("(")
        brace = CClosingObject("{")

        first_node = True

        for condition, node in self.condition_and_nodes:
            if first_node:
                first_node = False
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
            if self.codegen.braces_on_own_lines:
                yield "\n", self
                yield indent_str, None
            else:
                yield " ", None
            yield "{", brace
            yield "\n", self
            if node is not None:
                yield from node.c_repr_chunks(indent=indent + INDENT_DELTA)
            yield indent_str, None
            yield "}", brace

        if self.else_node is not None:
            brace = CClosingObject("{")

            if self.codegen.braces_on_own_lines:
                yield "\n", None
                yield indent_str, None
            else:
                yield " ", None
            yield "else", self
            if self.codegen.braces_on_own_lines:
                yield "\n", None
                yield indent_str, None
            else:
                yield " ", None
            yield "{", brace
            yield "\n", self
            yield from self.else_node.c_repr_chunks(indent=indent + INDENT_DELTA)
            yield indent_str, None
            yield "}", brace
        yield "\n", self


class CIfBreak(CStatement):
    """
    Represents an if-break statement in C.
    """

    __slots__ = (
        "condition",
        "tags",
    )

    def __init__(self, condition, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.condition = condition
        self.tags = tags

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        paren = CClosingObject("(")
        brace = CClosingObject("{")

        yield indent_str, None
        yield "if ", self
        yield "(", paren
        yield from self.condition.c_repr_chunks()
        yield ")", paren
        if self.codegen.braces_on_own_lines:
            yield "\n", None
            yield indent_str, None
        else:
            yield " ", None
        yield "{", brace
        yield "\n", self
        yield self.indent_str(indent=indent + INDENT_DELTA), self
        yield "break;\n", self
        yield indent_str, None
        yield "}", brace
        yield "\n", self


class CBreak(CStatement):
    """
    Represents a break statement in C.
    """

    __slots__ = ("tags",)

    def __init__(self, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.tags = tags

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "break;\n", self


class CContinue(CStatement):
    """
    Represents a continue statement in C.
    """

    __slots__ = ("tags",)

    def __init__(self, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.tags = tags

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "continue;\n", self


class CSwitchCase(CStatement):
    """
    Represents a switch-case statement in C.
    """

    __slots__ = ("switch", "cases", "default", "tags")

    def __init__(self, switch, cases, default, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.switch = switch
        self.cases: List[Tuple[Union[int, Tuple[int]], CStatements]] = cases
        self.default = default
        self.tags = tags

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
        yield "\n", self

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
            yield from case.c_repr_chunks(indent=indent + INDENT_DELTA)

        if self.default is not None:
            yield indent_str, None
            yield "default:\n", self
            yield from self.default.c_repr_chunks(indent=indent + INDENT_DELTA)

        yield indent_str, None
        yield "}", brace
        yield "\n", self


class CAssignment(CStatement):
    """
    a = b
    """

    __slots__ = (
        "lhs",
        "rhs",
        "tags",
    )

    def __init__(self, lhs, rhs, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.lhs = lhs
        self.rhs = rhs
        self.tags = tags

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

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

        if (
            self.codegen.use_compound_assignments
            and isinstance(self.lhs, CVariable)
            and isinstance(self.rhs, CBinaryOp)
            and isinstance(self.rhs.lhs, CVariable)
            and self.lhs.unified_variable is not None
            and self.rhs.lhs.unified_variable is not None
            and self.lhs.unified_variable is self.rhs.lhs.unified_variable
            and self.rhs.op in compound_assignment_ops
        ):
            # a = a + x  =>  a += x
            yield f" {compound_assignment_ops[self.rhs.op]}= ", self
            yield from CExpression._try_c_repr_chunks(self.rhs.rhs)
        else:
            yield " = ", self
            yield from CExpression._try_c_repr_chunks(self.rhs)
        if not asexpr:
            yield ";\n", self


class CFunctionCall(CStatement, CExpression):
    """
    func(arg0, arg1)

    :ivar Function callee_func:  The function getting called.
    """

    __slots__ = (
        "callee_target",
        "callee_func",
        "args",
        "returning",
        "ret_expr",
        "tags",
        "is_expr",
    )

    def __init__(
        self,
        callee_target,
        callee_func,
        args,
        returning=True,
        ret_expr=None,
        tags=None,
        is_expr: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)

        self.callee_target = callee_target
        self.callee_func: Optional["Function"] = callee_func
        self.args = args if args is not None else []
        self.returning = returning
        self.ret_expr = ret_expr
        self.tags = tags
        self.is_expr = is_expr

    @property
    def prototype(self) -> Optional[SimTypeFunction]:  # TODO there should be a prototype for each callsite!
        if self.callee_func is not None and self.callee_func.prototype is not None:
            return self.callee_func.prototype
        returnty = SimTypeInt(signed=False)
        return SimTypeFunction([arg.type for arg in self.args], returnty).with_arch(self.codegen.project.arch)

    @property
    def type(self):
        if self.is_expr:
            return self.prototype.returnty or SimTypeInt(signed=False).with_arch(self.codegen.project.arch)
        else:
            raise RuntimeError("CFunctionCall.type should not be accessed if the function call is used as a statement.")

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        yield indent_str, None

        if not self.is_expr and self.ret_expr is not None:
            yield from CExpression._try_c_repr_chunks(self.ret_expr)
            yield " = ", None

        if self.callee_func is not None:
            if self.callee_func.demangled_name:
                func_name = get_cpp_function_name(self.callee_func.demangled_name, specialized=False, qualified=True)
            else:
                func_name = self.callee_func.name
            yield func_name, self
        else:
            yield from CExpression._try_c_repr_chunks(self.callee_target)

        paren = CClosingObject("(")
        yield "(", paren

        for i, arg in enumerate(self.args):
            if i:
                yield ", ", self
            yield from CExpression._try_c_repr_chunks(arg)

        yield ")", paren

        if not self.is_expr:
            yield ";", self
            if not self.returning:
                yield " /* do not return */", self
            yield "\n", self


class CReturn(CStatement):
    __slots__ = (
        "retval",
        "tags",
    )

    def __init__(self, retval, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.retval = retval
        self.tags = tags

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
        "tags",
    )

    def __init__(self, target, target_idx, tags=None, **kwargs):
        super().__init__(**kwargs)

        if isinstance(target, CConstant):
            # unpack target
            target = target.value

        self.target: Union[int, CExpression] = target
        self.target_idx = target_idx
        self.tags = tags

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)
        lbl = None
        if self.codegen is not None:
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
        yield "\n", self


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
        yield str(self.stmt), None
        yield "\n", None


class CLabel(CStatement):
    """
    Represents a label in C code.
    """

    __slots__ = (
        "name",
        "ins_addr",
        "block_idx",
        "tags",
    )

    def __init__(self, name: str, ins_addr: int, block_idx: Optional[int], tags=None, **kwargs):
        super().__init__(**kwargs)
        self.name = name
        self.ins_addr = ins_addr
        self.block_idx = block_idx
        self.tags = tags

    def c_repr_chunks(self, indent=0, asexpr=False):
        # indent-_str = self.indent_str(indent=indent)

        yield self.name, self
        yield ":", None
        yield "\n", None


class CStructField(CExpression):
    __slots__ = (
        "struct_type",
        "offset",
        "field",
        "tags",
    )

    def __init__(self, struct_type: SimStruct, offset, field, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.struct_type = struct_type
        self.offset = offset
        self.field = field
        self.tags = tags

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

    __slots__ = ("name", "tags")

    def __init__(self, name: str, ty: SimType, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.name = name
        self._type = ty.with_arch(self.codegen.project.arch)
        self.tags = tags

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
        "variable",
        "variable_type",
        "unified_variable",
        "tags",
    )

    def __init__(self, variable: SimVariable, unified_variable=None, variable_type=None, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.variable: SimVariable = variable
        self.unified_variable: Optional[SimVariable] = unified_variable
        self.variable_type: SimType = variable_type.with_arch(self.codegen.project.arch)
        self.tags = tags

    @property
    def type(self):
        return self.variable_type

    def c_repr_chunks(self, indent=0, asexpr=False):
        v = self.variable if self.unified_variable is None else self.unified_variable

        if v.name:
            yield v.name, self
        elif isinstance(v, SimTemporaryVariable):
            yield "tmp_%d" % v.tmp_id, self
        else:
            yield str(v), self


class CIndexedVariable(CExpression):
    """
    Represent a variable (an array) that is indexed.
    """

    def __init__(self, variable: CExpression, index: CExpression, variable_type=None, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.variable = variable
        self.index: CExpression = index
        self._type = variable_type
        self.tags = tags

        if self._type is None and self.variable.type is not None:
            u = unpack_typeref(self.variable.type)
            if isinstance(u, SimTypePointer):
                if isinstance(u.pts_to, (SimTypeArray, SimTypeFixedSizeArray)):
                    # special case: (&array)[x]
                    u = u.pts_to.elem_type
                else:
                    u = u.pts_to
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

    def __init__(self, variable: CExpression, field: CStructField, var_is_ptr: bool = False, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.variable = variable
        self.field = field
        self.var_is_ptr = var_is_ptr
        self.tags = tags

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
        "tags",
    )

    def __init__(self, op, operand: CExpression, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.op = op
        self.operand = operand
        self.tags = tags

        if operand.type is not None:
            var_type = unpack_typeref(operand.type)
            if op == "Reference":
                if isinstance(var_type, SimTypePointer) and isinstance(
                    var_type.pts_to, (SimTypeArray, SimTypeFixedSizeArray)
                ):
                    # special case: &array
                    self._type = var_type
                else:
                    self._type = SimTypePointer(var_type).with_arch(self.codegen.project.arch)
            elif op == "Dereference":
                if isinstance(var_type, SimTypePointer):
                    self._type = unpack_typeref(var_type.pts_to)
                elif isinstance(var_type, (SimTypeArray, SimTypeFixedSizeArray)):
                    self._type = unpack_typeref(var_type.elem_type)

    @property
    def type(self):
        if self._type is None:
            if self.operand is not None and hasattr(self.operand, "type"):
                self._type = self.operand.type
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return

        OP_MAP = {
            "Not": self._c_repr_chunks_not,
            "Neg": self._c_repr_chunks_neg,
            "Reference": self._c_repr_chunks_reference,
            "Dereference": self._c_repr_chunks_dereference,
        }

        handler = OP_MAP.get(self.op, None)
        if handler is not None:
            yield from handler()
        else:
            yield "UnaryOp %s" % (self.op), self

    #
    # Handlers
    #

    def _c_repr_chunks_not(self):
        paren = CClosingObject("(")
        yield "!", self
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
        yield "&", self
        yield from CExpression._try_c_repr_chunks(self.operand)

    def _c_repr_chunks_dereference(self):
        paren = CClosingObject("(")
        yield "*", self
        yield "(", paren
        yield from CExpression._try_c_repr_chunks(self.operand)
        yield ")", paren


class CBinaryOp(CExpression):
    """
    Binary operations.
    """

    __slots__ = (
        "op",
        "lhs",
        "rhs",
        "tags",
        "common_type",
    )

    def __init__(self, op, lhs, rhs, tags: Optional[dict] = None, **kwargs):
        super().__init__(**kwargs)

        self.op = op
        self.lhs = lhs
        self.rhs = rhs
        self.tags = tags

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
            if lhs_ty.size > rhs_ty.size:
                return lhs_ty
            else:
                return rhs_ty

        if lhs_signed:
            signed_ty = lhs_ty
            unsigned_ty = rhs_ty
        else:
            signed_ty = rhs_ty
            unsigned_ty = lhs_ty

        if unsigned_ty.size >= signed_ty.size:
            return unsigned_ty
        if signed_ty.size > unsigned_ty.size:
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
            ["LogicalAnd"],
            ["Or"],
            ["Xor"],
            ["And"],
            ["CmpEQ", "CmpNE"],
            ["CmpLE", "CmpLT", "CmpGT", "CmpGE"],
            ["Shl", "Shr", "Sar"],
            ["Add", "Sub"],
            ["Mul", "Div"],
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
            "DivMod": self._c_repr_chunks_divmod,
            "And": self._c_repr_chunks_and,
            "Xor": self._c_repr_chunks_xor,
            "Or": self._c_repr_chunks_or,
            "Shr": self._c_repr_chunks_shr,
            "Shl": self._c_repr_chunks_shl,
            "Sar": self._c_repr_chunks_sar,
            "LogicalAnd": self._c_repr_chunks_logicaland,
            "LogicalOr": self._c_repr_chunks_logicalor,
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
        }

        handler = OP_MAP.get(self.op, None)
        if handler is not None:
            yield from handler()
        else:
            yield "BinaryOp %s" % (self.op), self

    #
    # Handlers
    #

    def _c_repr_chunks(self, op):
        # lhs
        if isinstance(self.lhs, CBinaryOp) and self.op_precedence > self.lhs.op_precedence:
            paren = CClosingObject("(")
            yield "(", paren
            yield from self._try_c_repr_chunks(self.lhs)
            yield ")", paren
        else:
            yield from self._try_c_repr_chunks(self.lhs)
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
        yield from self._c_repr_chunks(" >> ")

    def _c_repr_chunks_logicaland(self):
        yield from self._c_repr_chunks(" && ")

    def _c_repr_chunks_logicalor(self):
        yield from self._c_repr_chunks(" || ")

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


class CTypeCast(CExpression):
    __slots__ = (
        "src_type",
        "dst_type",
        "expr",
        "tags",
    )

    def __init__(self, src_type: Optional[SimType], dst_type: SimType, expr: CExpression, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.src_type = (src_type or expr.type).with_arch(self.codegen.project.arch)
        self.dst_type = dst_type.with_arch(self.codegen.project.arch)
        self.expr = expr
        self.tags = tags

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
            yield f"{self.dst_type.c_repr(name=None)}", self
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
        "value",
        "reference_values",
        "tags",
    )

    def __init__(self, value, type_: SimType, reference_values=None, tags: Optional[Dict] = None, **kwargs):
        super().__init__(**kwargs)

        self.value = value
        self._type = type_.with_arch(self.codegen.project.arch)
        self.reference_values = reference_values
        self.tags = tags

    @property
    def _ident(self):
        ident = (self.tags or {}).get("ins_addr", None)
        if ident is not None:
            return ("inst", ident)
        else:
            return ("val", self.value)

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
                result = hex(self.value).endswith("00") or is_alignment_mask(self.value)
        return result

    @fmt_hex.setter
    def fmt_hex(self, v):
        self._fmt_setter["hex"] = v

    @property
    def fmt_neg(self):
        result = self.fmt.get("neg", None)
        if result is None:
            result = False
            if isinstance(self.value, int):
                if self._type is not None:
                    value_size = self._type.size
                else:
                    value_size = None
                if value_size == 32 and 0xF000_0000 <= self.value <= 0xFFFF_FFFF:
                    result = True
                elif value_size == 64 and 0xF000_0000_0000_0000 <= self.value <= 0xFFFF_FFFF_FFFF_FFFF:
                    result = True

        return result

    @fmt_neg.setter
    def fmt_neg(self, v):
        self._fmt_setter["neg"] = v

    @property
    def type(self):
        return self._type

    @staticmethod
    def str_to_c_str(_str):
        repr_str = repr(_str)
        base_str = repr_str[1:-1]
        if repr_str[0] == "'":
            # check if there's double quotes in the body
            if '"' in base_str:
                base_str = base_str.replace('"', '\\"')
        return f'"{base_str}"'

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return

        # default priority: string references -> variables -> other reference values
        if self.reference_values is not None:
            for ty, v in self.reference_values.items():  # pylint:disable=unused-variable
                if isinstance(v, MemoryData) and v.sort == MemoryDataSort.String:
                    yield CConstant.str_to_c_str(v.content.decode("utf-8")), self
                    return

        if self.reference_values is not None and self._type is not None and self._type in self.reference_values:
            if isinstance(self._type, SimTypeInt):
                yield hex(self.reference_values[self._type]), self
            elif isinstance(self._type, SimTypePointer) and isinstance(self._type.pts_to, SimTypeChar):
                refval = self.reference_values[self._type]  # angr.knowledge_plugin.cfg.MemoryData
                yield CConstant.str_to_c_str(refval.content.decode("utf-8")), self
            else:
                yield self.reference_values[self.type], self

        elif isinstance(self.value, int) and self.value == 0 and isinstance(self.type, SimTypePointer):
            # print NULL instead
            yield "NULL", self

        elif isinstance(self._type, SimTypePointer) and isinstance(self.value, int):
            # Print pointers in hex
            yield hex(self.value), self

        elif isinstance(self.value, bool):
            # C doesn't have true or false, but whatever...
            yield "true" if self.value else "false", self

        elif isinstance(self.value, int):
            value = self.value
            if self.fmt_neg:
                if value > 0:
                    value = value - 2**self._type.size
                elif value < 0:
                    value = value + 2**self._type.size

            if self.fmt_hex:
                str_value = hex(value)
            else:
                str_value = str(value)

            yield str_value, self
        else:
            yield str(self.value), self


class CRegister(CExpression):
    __slots__ = (
        "reg",
        "tags",
    )

    def __init__(self, reg, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.reg = reg
        self.tags = tags

    @property
    def type(self):
        # FIXME
        return SimTypeInt().with_arch(self.codegen.project.arch)

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield str(self.reg), None


class CITE(CExpression):
    __slots__ = (
        "cond",
        "iftrue",
        "iffalse",
        "tags",
    )

    def __init__(self, cond, iftrue, iffalse, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.cond = cond
        self.iftrue = iftrue
        self.iffalse = iffalse
        self.tags = tags

    @property
    def type(self):
        return SimTypeInt().with_arch(self.codegen.project.arch)

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        paren = CClosingObject("(")
        yield "(", paren
        yield from self.cond.c_repr_chunks()
        yield "? ", self
        yield from self.iftrue.c_repr_chunks()
        yield " : ", self
        yield from self.iffalse.c_repr_chunks()
        yield ")", paren


class CMultiStatementExpression(CExpression):
    """
    (stmt0, stmt1, stmt2, expr)
    """

    __slots__ = ("stmts", "expr", "tags")

    def __init__(self, stmts: CStatements, expr: CExpression, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.stmts = stmts
        self.expr = expr
        self.tags = tags

    @property
    def type(self):
        return self.expr.type

    def c_repr_chunks(self, indent=0, asexpr=False):
        paren = CClosingObject("(")
        yield "(", paren
        yield from self.stmts.c_repr_chunks(indent=0, asexpr=True)
        yield from self.expr.c_repr_chunks()
        yield ")", paren


class CDirtyExpression(CExpression):
    """
    Ideally all dirty expressions should be handled and converted to proper conversions during conversion from VEX to
    AIL. Eventually this class should not be used at all.
    """

    __slots__ = ("dirty",)

    def __init__(self, dirty, **kwargs):
        super().__init__(**kwargs)
        self.dirty = dirty

    @property
    def type(self):
        return SimTypeInt().with_arch(self.codegen.project.arch)

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield "...", self
            return
        yield str(self.dirty), None


class CClosingObject:
    """
    A class to represent all objects that can be closed by it's correspodning character.
    Examples: (), {}, []
    """

    __slots__ = ("opening_symbol",)

    def __init__(self, opening_symbol):
        self.opening_symbol = opening_symbol


class CStructuredCodeGenerator(BaseStructuredCodeGenerator, Analysis):
    def __init__(
        self,
        func,
        sequence,
        indent=0,
        cfg=None,
        variable_kb=None,
        func_args: Optional[List[SimVariable]] = None,
        binop_depth_cutoff: int = 16,
        show_casts=True,
        braces_on_own_lines=True,
        use_compound_assignments=True,
        show_local_types=True,
        comment_gotos=False,
        flavor=None,
        stmt_comments=None,
        expr_comments=None,
        show_externs=True,
        externs=None,
        const_formats=None,
    ):
        super().__init__(flavor=flavor)

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
            ContinueNode: self._handle_Continue,
            # AIL statements
            Stmt.Store: self._handle_Stmt_Store,
            Stmt.Assignment: self._handle_Stmt_Assignment,
            Stmt.Call: self._handle_Stmt_Call,
            Stmt.Jump: self._handle_Stmt_Jump,
            Stmt.ConditionalJump: self._handle_Stmt_ConditionalJump,
            Stmt.Return: self._handle_Stmt_Return,
            Stmt.Label: self._handle_Stmt_Label,
            # AIL expressions
            Expr.Register: self._handle_Expr_Register,
            Expr.Load: self._handle_Expr_Load,
            Expr.Tmp: self._handle_Expr_Tmp,
            Expr.Const: self._handle_Expr_Const,
            Expr.UnaryOp: self._handle_Expr_UnaryOp,
            Expr.BinaryOp: self._handle_Expr_BinaryOp,
            Expr.Convert: self._handle_Expr_Convert,
            Expr.StackBaseOffset: self._handle_Expr_StackBaseOffset,
            Expr.DirtyExpression: self._handle_Expr_Dirty,
            Expr.ITE: self._handle_Expr_ITE,
            Expr.Reinterpret: self._handle_Reinterpret,
            Expr.MultiStatementExpression: self._handle_MultiStatementExpression,
        }

        self._func = func
        self._func_args = func_args
        self._cfg = cfg
        self._sequence = sequence
        self._variable_kb = variable_kb if variable_kb is not None else self.kb
        self.binop_depth_cutoff = binop_depth_cutoff

        self._variables_in_use: Optional[Dict] = None
        self._inlined_strings: Set[SimMemoryVariable] = set()
        self.ailexpr2cnode: Optional[Dict[Tuple[Expr.Expression, bool], CExpression]] = None
        self.cnode2ailexpr: Optional[Dict[CExpression, Expr.Expression]] = None
        self._indent = indent
        self.show_casts = show_casts
        self.comment_gotos = comment_gotos
        self.braces_on_own_lines = braces_on_own_lines
        self.use_compound_assignments = use_compound_assignments
        self.show_local_types = show_local_types
        self.expr_comments: Dict[int, str] = expr_comments if expr_comments is not None else {}
        self.stmt_comments: Dict[int, str] = stmt_comments if stmt_comments is not None else {}
        self.const_formats: Dict[Any, Dict[str, Any]] = const_formats if const_formats is not None else {}
        self.externs = externs or set()
        self.show_externs = show_externs

        self.text = None
        self.map_pos_to_node = None
        self.map_pos_to_addr = None
        self.map_addr_to_pos = None
        self.map_ast_to_pos: Optional[Dict[SimVariable, Set[PositionMappingElement]]] = None
        self.map_addr_to_label: Dict[Tuple[int, Optional[int]], CLabel] = {}
        self.cfunc: Optional[CFunction] = None
        self.cexterns: Optional[Set[CVariable]] = None

        self._analyze()

        if flavor is not None:
            self.kb.structured_code[(func.addr, flavor)] = self

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

    def _analyze(self):
        self._variables_in_use = {}

        # memo
        self.ailexpr2cnode = {}

        if self._func_args:
            arg_list = [self._variable(arg, None) for arg in self._func_args]
        else:
            arg_list = []

        obj = self._handle(self._sequence)

        self.cnode2ailexpr = {v: k[0] for k, v in self.ailexpr2cnode.items()}

        self.cfunc = CFunction(
            self._func.addr,
            self._func.name,
            self._func.prototype,
            arg_list,
            obj,
            self._variables_in_use,
            self._variable_kb.variables[self._func.addr],
            demangled_name=self._func.demangled_name,
            codegen=self,
        )
        self.cfunc = FieldReferenceCleanup.handle(self.cfunc)
        self.cfunc = PointerArithmeticFixer.handle(self.cfunc)
        self.cfunc = MakeTypecastsImplicit.handle(self.cfunc)

        # TODO store extern fallback size somewhere lol
        self.cexterns = {self._variable(v, 1) for v in self.externs if v not in self._inlined_strings}

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
        self.cleanup()
        (
            self.text,
            self.map_pos_to_node,
            self.map_pos_to_addr,
            self.map_addr_to_pos,
            self.map_ast_to_pos,
        ) = self.render_text(self.cfunc)

    RENDER_TYPE = Tuple[str, PositionMapping, PositionMapping, InstructionMapping, Dict[Any, Set[Any]]]

    def render_text(self, cfunc: CFunction) -> RENDER_TYPE:
        pos_to_node = PositionMapping()
        pos_to_addr = PositionMapping()
        addr_to_pos = InstructionMapping()
        ast_to_pos = defaultdict(set)

        text = cfunc.c_repr(
            indent=self._indent, pos_to_node=pos_to_node, pos_to_addr=pos_to_addr, addr_to_pos=addr_to_pos
        )

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
                if node.obj.callee_func is not None:
                    ast_to_pos[node.obj.callee_func].add(elem)
                else:
                    ast_to_pos[node.obj.callee_target].add(elem)
            elif isinstance(node.obj, CStructField):
                key = (node.obj.struct_type, node.obj.offset)
                ast_to_pos[key].add(elem)
            else:
                ast_to_pos[node.obj].add(elem)

        return text, pos_to_node, pos_to_addr, addr_to_pos, ast_to_pos

    def _get_variable_type(self, var, is_global=False):
        if is_global:
            return self._variable_kb.variables["global"].get_variable_type(var)
        else:
            return self._variable_kb.variables[self._func.addr].get_variable_type(var)

    def _get_derefed_type(self, ty: SimType) -> Optional[SimType]:
        if ty is None:
            return None
        ty = unpack_typeref(ty)
        if isinstance(ty, SimTypePointer):
            return unpack_typeref(ty.pts_to).with_arch(self.project.arch)
        if isinstance(ty, SimTypeArray):
            return unpack_typeref(ty.elem_type).with_arch(self.project.arch)
        return ty

    def reload_variable_types(self) -> None:
        for var in self._variables_in_use.values():
            if isinstance(var, CVariable):
                var.variable_type = self._get_variable_type(
                    var.variable,
                    is_global=isinstance(var.variable, SimMemoryVariable)
                    and not isinstance(var.variable, SimStackVariable),
                )

        for var in self.cexterns:
            if isinstance(var, CVariable):
                var.variable_type = self._get_variable_type(var.variable, is_global=True)

    #
    # Util methods
    #

    def default_simtype_from_size(self, n: int, signed: bool = True) -> SimType:
        _mapping = {
            8: SimTypeLongLong,
            4: SimTypeInt,
            2: SimTypeShort,
            1: SimTypeChar,
        }
        if n in _mapping:
            return _mapping.get(n)(signed=signed).with_arch(self.project.arch)
        return SimTypeNum(n * self.project.arch.byte_width, signed=signed).with_arch(self.project.arch)

    def _variable(self, variable: SimVariable, fallback_type_size: Optional[int]):
        # TODO: we need to fucking make sure that variable recovery and type inference actually generates a size
        # TODO: for each variable it links into the fucking ail. then we can remove fallback_type_size.
        unified = self._variable_kb.variables[self._func.addr].unified_variable(variable)
        variable_type = self._get_variable_type(
            variable, is_global=isinstance(variable, SimMemoryVariable) and not isinstance(variable, SimStackVariable)
        )
        if variable_type is None:
            variable_type = self.default_simtype_from_size(fallback_type_size or self.project.arch.bytes)
        cvar = CVariable(variable, unified_variable=unified, variable_type=variable_type, codegen=self)
        self._variables_in_use[variable] = cvar
        return cvar

    def _access_reference(self, expr: CExpression, data_type: SimType):
        result = self._access(expr, data_type, True)
        if isinstance(result, CUnaryOp) and result.op == "Dereference":
            result = result.operand
        else:
            result = CUnaryOp("Reference", result, codegen=self)
        return result

    def _access_constant_offset_reference(self, expr: CExpression, offset: int, data_type: Optional[SimType]):
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
        base_type = unpack_typeref(unpack_pointer(expr.type))
        if base_type is None:
            # well, not much we can do
            if data_type is None:
                raise Exception("CStructuredCodeGenerator programming error: no type whatsoever for dereference")
            if offset:
                expr = CBinaryOp("Add", expr, CConstant(offset, SimTypeInt(), codegen=self), codegen=self)
            return CUnaryOp(
                "Dereference",
                CTypeCast(expr.type, SimTypePointer(data_type).with_arch(self.project.arch), expr, codegen=self),
                codegen=self,
            )

        if isinstance(expr, CUnaryOp) and expr.op == "Reference":
            base_expr = expr.operand
        else:
            base_expr = None

        if offset == 0:
            data_type = renegotiate_type(data_type, base_type)
            if base_type == data_type or (
                not isinstance(base_type, SimTypeBottom)
                and not isinstance(data_type, SimTypeBottom)
                and base_type.size < data_type.size
            ):
                # case 1: we're done because we found it
                # case 2: we're done because we can never find it and we might as well stop early
                if base_expr:
                    if base_type != data_type:
                        return _force_type_cast(base_type, data_type, base_expr)
                    return base_expr

                if base_type != data_type:
                    return _force_type_cast(base_type, data_type, expr)
                return CUnaryOp("Dereference", expr, codegen=self)

        if isinstance(base_type, SimTypeBottom):
            stride = 1
        else:
            stride = base_type.size // self.project.arch.byte_width or 1
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

        if isinstance(base_type, SimStruct):
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
        base_type = unpack_pointer(expr.type)
        if base_type is None:
            # use the fallback from above
            return self._access_constant_offset(expr, 0, data_type, lvalue, renegotiate_type)

        o_constant, o_terms = extract_terms(expr)

        def bail_out():
            result = reduce(
                lambda a1, a2: CBinaryOp("Add", a1, a2, codegen=self),
                (
                    CBinaryOp(
                        "Mul",
                        CConstant(c, t.type, codegen=self),
                        t
                        if not isinstance(t.type, SimTypePointer)
                        else CTypeCast(t.type, SimTypePointer(SimTypeChar()), t, codegen=self),
                        codegen=self,
                    )
                    if c != 1
                    else t
                    if not isinstance(t.type, SimTypePointer)
                    else CTypeCast(t.type, SimTypePointer(SimTypeChar()), t, codegen=self)
                    for c, t in o_terms
                ),
            )
            if o_constant != 0:
                result = CBinaryOp("Add", CConstant(o_constant, SimTypeInt(), codegen=self), result, codegen=self)

            return CUnaryOp(
                "Dereference", CTypeCast(result.type, SimTypePointer(data_type), result, codegen=self), codegen=self
            )

        # pain.
        # step 1 is split expr into a sum of terms, each of which is a product of a constant stride and an index
        # also identify the "kernel", the root of the expression
        constant, terms = o_constant, list(o_terms)
        i = 0
        kernel = None
        while i < len(terms):
            c, t = terms[i]
            if isinstance(unpack_typeref(t.type), SimTypePointer):
                if kernel is not None:
                    l.warning("Summing two different pointers together. Uh oh!")
                    return bail_out()
                if c != 1:
                    l.warning("Multiplying a pointer by a constant??")
                    return bail_out()
                kernel = t
                terms.pop(i)
                continue
            i += 1

        if kernel is None:
            l.warning("Dereferencing a plain integer. Uh oh!")
            return bail_out()

        terms.sort(key=lambda x: x[0])

        # suffering.
        while terms:
            kernel_type = unpack_typeref(unpack_pointer(kernel.type))
            assert kernel_type

            if isinstance(kernel_type, SimTypeBottom):
                return bail_out()
            kernel_stride = kernel_type.size // self.project.arch.byte_width

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
                if unpack_typeref(unpack_pointer(kernel.type)) == kernel_type:
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

    def _handle(self, node, is_expr: bool = True):
        if (node, is_expr) in self.ailexpr2cnode:
            return self.ailexpr2cnode[(node, is_expr)]

        handler: Optional[Callable] = self._handlers.get(node.__class__, None)
        if handler is not None:
            if isinstance(node, Stmt.Call):
                # special case for Call
                converted = handler(node, is_expr=is_expr)
            else:
                converted = handler(node)
            self.ailexpr2cnode[(node, is_expr)] = converted
            return converted
        raise UnsupportedNodeTypeError("Node type %s is not supported yet." % type(node))

    def _handle_Code(self, node):
        return self._handle(node.node, is_expr=False)

    def _handle_Sequence(self, seq):
        lines = []

        for node in seq.nodes:
            lines.append(self._handle(node, is_expr=False))

        if not lines:
            return CStatements([], codegen=None)

        return CStatements(lines, codegen=self) if len(lines) > 1 else lines[0]

    def _handle_Loop(self, loop_node):
        tags = {"ins_addr": loop_node.addr}

        if loop_node.sort == "while":
            return CWhileLoop(
                None if loop_node.condition is None else self._handle(loop_node.condition),
                None if loop_node.sequence_node is None else self._handle(loop_node.sequence_node, is_expr=False),
                tags=tags,
                codegen=self,
            )
        elif loop_node.sort == "do-while":
            return CDoWhileLoop(
                self._handle(loop_node.condition),
                None if loop_node.sequence_node is None else self._handle(loop_node.sequence_node, is_expr=False),
                tags=tags,
                codegen=self,
            )
        elif loop_node.sort == "for":
            return CForLoop(
                None if loop_node.initializer is None else self._handle(loop_node.initializer),
                None if loop_node.condition is None else self._handle(loop_node.condition),
                None if loop_node.iterator is None else self._handle(loop_node.iterator),
                None if loop_node.sequence_node is None else self._handle(loop_node.sequence_node, is_expr=False),
                tags=tags,
                codegen=self,
            )

        else:
            raise NotImplementedError()

    def _handle_Condition(self, condition_node: ConditionNode):
        tags = {"ins_addr": condition_node.addr}

        condition_and_nodes = [
            (
                self._handle(condition_node.condition),
                self._handle(condition_node.true_node, is_expr=False) if condition_node.true_node else None,
            )
        ]

        else_node = self._handle(condition_node.false_node, is_expr=False) if condition_node.false_node else None

        code = CIfElse(
            condition_and_nodes,
            else_node=else_node,
            tags=tags,
            codegen=self,
        )
        return code

    def _handle_CascadingCondition(self, cond_node: CascadingConditionNode):
        tags = {"ins_addr": cond_node.addr}

        condition_and_nodes = [
            (self._handle(cond), self._handle(node, is_expr=False)) for cond, node in cond_node.condition_and_nodes
        ]
        else_node = self._handle(cond_node.else_node) if cond_node.else_node is not None else None

        code = CIfElse(
            condition_and_nodes,
            else_node=else_node,
            tags=tags,
            codegen=self,
        )
        return code

    def _handle_ConditionalBreak(self, node):
        tags = {"ins_addr": node.addr}

        return CIfBreak(self._handle(node.condition), tags=tags, codegen=self)

    def _handle_Break(self, node):
        tags = {"ins_addr": node.addr}

        return CBreak(tags=tags, codegen=self)

    def _handle_MultiNode(self, node):
        lines = []

        for n in node.nodes:
            r = self._handle(n, is_expr=False)
            lines.append(r)

        return CStatements(lines, codegen=self) if len(lines) > 1 else lines[0]

    def _handle_SwitchCase(self, node):
        """

        :param SwitchCaseNode node:
        :return:
        """

        switch_expr = self._handle(node.switch_expr)
        cases = [(idx, self._handle(case, is_expr=False)) for idx, case in node.cases.items()]
        default = self._handle(node.default_node, is_expr=False) if node.default_node is not None else None
        tags = {"ins_addr": node.addr}
        switch_case = CSwitchCase(switch_expr, cases, default=default, tags=tags, codegen=self)
        return switch_case

    def _handle_Continue(self, node):
        tags = {"ins_addr": node.addr}

        return CContinue(tags=tags, codegen=self)

    def _handle_AILBlock(self, node):
        """

        :param Block node:
        :return:
        """

        # return CStatements([ CAILBlock(node) ])
        cstmts = []
        for stmt in node.statements:
            try:
                cstmt = self._handle(stmt, is_expr=False)
            except UnsupportedNodeTypeError:
                l.warning("Unsupported AIL statement or expression %s.", type(stmt), exc_info=True)
                cstmt = CUnsupportedStatement(stmt, codegen=self)
            cstmts.append(cstmt)

        return CStatements(cstmts, codegen=self)

    #
    # AIL statement handlers
    #

    def _handle_Stmt_Store(self, stmt: Stmt.Store):
        cdata = self._handle(stmt.data)

        if cdata.type.size != stmt.size * self.project.arch.byte_width:
            l.error("Store data lifted to a C type with a different size. Decompilation output will be wrong.")

        def negotiate(old_ty, proposed_ty):
            # transfer casts from the dst to the src if possible
            # if we see something like *(size_t*)&v4 = x; where v4 is a pointer, change to v4 = (void*)x;
            nonlocal cdata
            if old_ty != proposed_ty and qualifies_for_simple_cast(old_ty, proposed_ty):
                cdata = CTypeCast(cdata.type, proposed_ty, cdata, codegen=self)
                return proposed_ty
            return old_ty

        if stmt.variable is not None:
            cvar = self._variable(stmt.variable, stmt.size)
            offset = stmt.offset or 0
            assert type(offset) is int  # I refuse to deal with the alternative

            cdst = self._access_constant_offset(
                CUnaryOp("Reference", cvar, codegen=self), offset, cdata.type, True, negotiate
            )
        else:
            addr_expr = self._handle(stmt.addr)
            cdst = self._access(addr_expr, cdata.type, True, negotiate)

        return CAssignment(cdst, cdata, tags=stmt.tags, codegen=self)

    def _handle_Stmt_Assignment(self, stmt):
        cdst = self._handle(stmt.dst)
        csrc = self._handle(stmt.src)

        return CAssignment(cdst, csrc, tags=stmt.tags, codegen=self)

    def _handle_Stmt_Call(self, stmt: Stmt.Call, is_expr: bool = False):
        try:
            # Try to handle it as a normal function call
            if not isinstance(stmt.target, str):
                target = self._handle(stmt.target)
            else:
                target = stmt.target
        except UnsupportedNodeTypeError:
            target = stmt.target

        if isinstance(target, CConstant):
            target_func = self.kb.functions.function(addr=target.value)
        else:
            target_func = None

        args = []
        if stmt.args is not None:
            for i, arg in enumerate(stmt.args):
                type_ = None
                if target_func is not None:
                    if target_func.prototype is not None and i < len(target_func.prototype.args):
                        type_ = target_func.prototype.args[i].with_arch(self.project.arch)

                if isinstance(arg, Expr.Const):
                    if type_ is None or is_machine_word_size_type(type_, self.project.arch):
                        type_ = guess_value_type(arg.value, self.project) or type_

                    new_arg = self._handle_Expr_Const(arg, type_=type_)
                else:
                    new_arg = self._handle(arg)
                args.append(new_arg)

        ret_expr = None
        if stmt.ret_expr is not None:
            ret_expr = self._handle(stmt.ret_expr)

        result = CFunctionCall(
            target,
            target_func,
            args,
            returning=target_func.returning if target_func is not None else True,
            ret_expr=ret_expr,
            tags=stmt.tags,
            is_expr=is_expr,
            codegen=self,
        )

        if result.is_expr and result.type.size != stmt.size * self.project.arch.byte_width:
            result = CTypeCast(
                result.type,
                self.default_simtype_from_size(stmt.size, signed=getattr(result.type, "signed", False)),
                result,
                codegen=self,
            )

        return result

    def _handle_Stmt_Jump(self, stmt: Stmt.Jump):
        return CGoto(self._handle(stmt.target), stmt.target_idx, tags=stmt.tags, codegen=self)

    def _handle_Stmt_ConditionalJump(self, stmt: Stmt.ConditionalJump):
        else_node = (
            None
            if stmt.false_target is None
            else CGoto(self._handle(stmt.false_target), None, tags=stmt.tags, codegen=self)
        )
        ifelse = CIfElse(
            [(self._handle(stmt.condition), CGoto(self._handle(stmt.true_target), None, tags=stmt.tags, codegen=self))],
            else_node=else_node,
            tags=stmt.tags,
            codegen=self,
        )
        return ifelse

    def _handle_Stmt_Return(self, stmt: Stmt.Return):
        if not stmt.ret_exprs:
            return CReturn(None, tags=stmt.tags, codegen=self)
        elif len(stmt.ret_exprs) == 1:
            ret_expr = stmt.ret_exprs[0]
            return CReturn(self._handle(ret_expr), tags=stmt.tags, codegen=self)
        else:
            # TODO: Multiple return expressions
            l.warning("StructuredCodeGen does not support multiple return expressions yet. Only picking the first one.")
            ret_expr = stmt.ret_exprs[0]
            return CReturn(self._handle(ret_expr), tags=stmt.tags, codegen=self)

    def _handle_Stmt_Label(self, stmt: Stmt.Label):
        clabel = CLabel(stmt.name, stmt.ins_addr, stmt.block_idx, tags=stmt.tags, codegen=self)
        self.map_addr_to_label[(stmt.ins_addr, stmt.block_idx)] = clabel
        return clabel

    #
    # AIL expression handlers
    #

    def _handle_Expr_Register(self, expr: Expr.Register):
        if expr.variable:
            return self._variable(expr.variable, expr.size)
        else:
            return CRegister(expr, tags=expr.tags, codegen=self)

    def _handle_Expr_Load(self, expr: Expr.Load):
        ty = self.default_simtype_from_size(expr.size)

        def negotiate(old_ty: SimType, proposed_ty: SimType) -> SimType:
            if old_ty.size == proposed_ty.size:
                # we do not allow returning a struct for a primitive type
                if not (isinstance(proposed_ty, SimStruct) and not isinstance(old_ty, SimStruct)):
                    return proposed_ty
            return old_ty

        if expr.variable is not None:
            cvar = self._variable(expr.variable, expr.size)
            offset = expr.variable_offset or 0
            assert type(offset) is int  # I refuse to deal with the alternative
            return self._access_constant_offset(CUnaryOp("Reference", cvar, codegen=self), offset, ty, False, negotiate)

        addr_expr = self._handle(expr.addr)
        return self._access(addr_expr, ty, False, negotiate)

    def _handle_Expr_Tmp(self, expr: Tmp):
        l.warning("FIXME: Leftover Tmp expressions are found.")
        return self._variable(SimTemporaryVariable(expr.tmp_idx), expr.size)

    def _handle_Expr_Const(self, expr, type_=None, reference_values=None, variable=None):
        inline_string = False

        if reference_values is None:
            reference_values = {}
            type_ = unpack_typeref(type_)
            if isinstance(type_, SimTypePointer) and isinstance(type_.pts_to, SimTypeChar):
                # char*
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
                reference_values[type_] = expr.value

            # we don't know the type of this argument, or the type is not what we are expecting
            # edge cases: (void*)"this is a constant string pointer". in this case, the type_ will be a void*
            # (BOT*) instead of a char*.

            # pure guessing: is it possible that it's a string?
            if (
                self._cfg is not None
                and expr.bits == self.project.arch.bits
                and expr.value > 0x10000
                and expr.value in self._cfg.memory_data
                and self._cfg.memory_data[expr.value].sort == MemoryDataSort.String
            ):
                type_ = SimTypePointer(SimTypeChar()).with_arch(self.project.arch)
                reference_values[type_] = self._cfg.memory_data[expr.value]
                # is it a constant string?
                if is_in_readonly_segment(self.project, expr.value) or is_in_readonly_section(self.project, expr.value):
                    inline_string = True

        if type_ is None:
            # default to int
            type_ = self.default_simtype_from_size(expr.size)

        if variable is None and hasattr(expr, "reference_variable") and expr.reference_variable is not None:
            variable = expr.reference_variable
            if inline_string:
                self._inlined_strings.add(expr.reference_variable)

        if variable is not None and not reference_values:
            cvar = self._variable(variable, None)
            offset = getattr(expr, "reference_variable_offset", 0)
            return self._access_constant_offset_reference(CUnaryOp("Reference", cvar, codegen=self), offset, None)

        return CConstant(expr.value, type_, reference_values=reference_values, tags=expr.tags, codegen=self)

    def _handle_Expr_UnaryOp(self, expr):
        return CUnaryOp(
            expr.op,
            self._handle(expr.operand),
            tags=expr.tags,
            codegen=self,
        )

    def _handle_Expr_BinaryOp(self, expr: BinaryOp):
        if expr.variable is not None:
            cvar = self._variable(expr.variable, None)
            return self._access_constant_offset_reference(
                CUnaryOp("Reference", cvar, codegen=self), expr.variable_offset or 0, None
            )

        lhs = self._handle(expr.operands[0])
        rhs = self._handle(expr.operands[1])

        return CBinaryOp(
            expr.op,
            lhs,
            rhs,
            tags=expr.tags,
            codegen=self,
            collapsed=expr.depth > self.binop_depth_cutoff,
        )

    def _handle_Expr_Convert(self, expr: Expr.Convert):
        if 64 >= expr.to_bits > 32:
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
            raise UnsupportedNodeTypeError("Unsupported conversion bits %s." % expr.to_bits)

        dst_type.signed = expr.is_signed
        child = self._handle(expr.operand)
        if getattr(child.type, "signed", False) != expr.is_signed:
            # this is a problem. sign-extension only happens when the SOURCE of the cast is signed
            child_ty = self.default_simtype_from_size(child.type.size // self.project.arch.byte_width, expr.is_signed)
            child = CTypeCast(None, child_ty, child, codegen=self)

        return CTypeCast(None, dst_type.with_arch(self.project.arch), child, tags=expr.tags, codegen=self)

    def _handle_Expr_Dirty(self, expr):
        return CDirtyExpression(expr, codegen=self)

    def _handle_Expr_ITE(self, expr: Expr.ITE):
        return CITE(
            self._handle(expr.cond), self._handle(expr.iftrue), self._handle(expr.iffalse), tags=expr.tags, codegen=self
        )

    def _handle_Reinterpret(self, expr: Expr.Reinterpret):
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
        return CTypeCast(src_type, dst_type, self._handle(expr.operand), tags=expr.tags, codegen=self)

    def _handle_MultiStatementExpression(self, expr: Expr.MultiStatementExpression):
        cstmts = CStatements([self._handle(stmt, is_expr=False) for stmt in expr.stmts], codegen=self)
        cexpr = self._handle(expr.expr)
        return CMultiStatementExpression(cstmts, cexpr, tags=expr.tags, codegen=self)

    def _handle_Expr_StackBaseOffset(self, expr: StackBaseOffset):
        if expr.variable is not None:
            var_thing = self._variable(expr.variable, expr.size)
            var_thing.tags = dict(expr.tags)
            if "def_at" in var_thing.tags and "ins_addr" not in var_thing.tags:
                var_thing.tags["ins_addr"] = var_thing.tags["def_at"].ins_addr
            return CUnaryOp("Reference", var_thing, codegen=self)

        # FIXME
        stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=self)
        ptr = CBinaryOp("Add", stack_base, CConstant(expr.offset, SimTypeInt(), codegen=self), codegen=self)
        return ptr


class CStructuredCodeWalker:
    @classmethod
    def handle(cls, obj):
        handler = getattr(cls, "handle_" + type(obj).__name__, cls.handle_default)
        return handler(obj)

    @classmethod
    def handle_default(cls, obj):
        return obj

    @classmethod
    def handle_CFunction(cls, obj):
        obj.statements = cls.handle(obj.statements)
        return obj

    @classmethod
    def handle_CStatements(cls, obj):
        obj.statements = [cls.handle(stmt) for stmt in obj.statements]
        return obj

    @classmethod
    def handle_CWhileLoop(cls, obj):
        obj.condition = cls.handle(obj.condition)
        obj.body = cls.handle(obj.body)
        return obj

    @classmethod
    def handle_CDoWhileLoop(cls, obj):
        obj.condition = cls.handle(obj.condition)
        obj.body = cls.handle(obj.body)
        return obj

    @classmethod
    def handle_CForLoop(cls, obj):
        obj.initializer = cls.handle(obj.initializer)
        obj.condition = cls.handle(obj.condition)
        obj.iterator = cls.handle(obj.iterator)
        obj.body = cls.handle(obj.body)
        return obj

    @classmethod
    def handle_CIfElse(cls, obj):
        obj.condition_and_nodes = [
            (cls.handle(condition), cls.handle(node)) for condition, node in obj.condition_and_nodes
        ]
        obj.else_node = cls.handle(obj.else_node)
        return obj

    @classmethod
    def handle_CIfBreak(cls, obj):
        obj.condition = cls.handle(obj.condition)
        return obj

    @classmethod
    def handle_CSwitchCase(cls, obj):
        obj.switch = cls.handle(obj.switch)
        obj.cases = [(case, cls.handle(body)) for case, body in obj.cases]
        obj.default = cls.handle(obj.default)
        return obj

    @classmethod
    def handle_CAssignment(cls, obj):
        obj.lhs = cls.handle(obj.lhs)
        obj.rhs = cls.handle(obj.rhs)
        return obj

    @classmethod
    def handle_CFunctionCall(cls, obj):
        obj.callee_target = cls.handle(obj.callee_target)
        obj.args = [cls.handle(arg) for arg in obj.args]
        obj.ret_expr = cls.handle(obj.ret_expr)
        return obj

    @classmethod
    def handle_CReturn(cls, obj):
        obj.retval = cls.handle(obj.retval)
        return obj

    @classmethod
    def handle_CGoto(cls, obj):
        obj.target = cls.handle(obj.target)
        return obj

    @classmethod
    def handle_CIndexedVariable(cls, obj):
        obj.variable = cls.handle(obj.variable)
        obj.index = cls.handle(obj.index)
        return obj

    @classmethod
    def handle_CVariableField(cls, obj):
        obj.variable = cls.handle(obj.variable)
        return obj

    @classmethod
    def handle_CUnaryOp(cls, obj):
        obj.operand = cls.handle(obj.operand)
        return obj

    @classmethod
    def handle_CBinaryOp(cls, obj):
        obj.lhs = cls.handle(obj.lhs)
        obj.rhs = cls.handle(obj.rhs)
        return obj

    @classmethod
    def handle_CTypeCast(cls, obj):
        obj.expr = cls.handle(obj.expr)
        return obj

    @classmethod
    def handle_CITE(cls, obj):
        obj.cond = cls.handle(obj.cond)
        obj.iftrue = cls.handle(obj.iftrue)
        obj.iffalse = cls.handle(obj.iffalse)
        return obj


class MakeTypecastsImplicit(CStructuredCodeWalker):
    @classmethod
    def collapse(cls, dst_ty: SimType, child: CExpression) -> CExpression:
        result = child
        if isinstance(child, CTypeCast):
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

    @classmethod
    def handle_CAssignment(cls, obj):
        obj.rhs = cls.collapse(obj.lhs.type, obj.rhs)
        return super().handle_CAssignment(obj)

    @classmethod
    def handle_CFunctionCall(cls, obj: CFunctionCall):
        for i, (c_arg, arg_ty) in enumerate(zip(obj.args, obj.prototype.args)):
            obj.args[i] = cls.collapse(arg_ty, c_arg)
        return super().handle_CFunctionCall(obj)

    @classmethod
    def handle_CReturn(cls, obj: CReturn):
        obj.retval = cls.collapse(obj.codegen._func.prototype.returnty, obj.retval)
        return super().handle_CReturn(obj)

    @classmethod
    def handle_CBinaryOp(cls, obj: CBinaryOp):
        obj = super().handle_CBinaryOp(obj)
        while True:
            new_lhs = cls.collapse(obj.common_type, obj.lhs)
            if (
                new_lhs is not obj.lhs
                and CBinaryOp.compute_common_type(obj.op, new_lhs.type, obj.rhs.type) == obj.common_type
            ):
                obj.lhs = new_lhs
            else:
                new_rhs = cls.collapse(obj.common_type, obj.rhs)
                if (
                    new_rhs is not obj.rhs
                    and CBinaryOp.compute_common_type(obj.op, obj.lhs.type, new_rhs.type) == obj.common_type
                ):
                    obj.rhs = new_rhs
                else:
                    break
        return obj

    @classmethod
    def handle_CTypeCast(cls, obj):
        # note that the expression that this method returns may no longer be a CTypeCast
        obj = super().handle_CTypeCast(obj)
        return cls.collapse(obj.dst_type, obj.expr)


class FieldReferenceCleanup(CStructuredCodeWalker):
    @classmethod
    def handle_CTypeCast(cls, obj):
        if isinstance(obj.dst_type, SimTypePointer) and not isinstance(obj.dst_type.pts_to, SimTypeBottom):
            obj = obj.codegen._access_reference(obj.expr, obj.dst_type.pts_to)
            if not isinstance(obj, CTypeCast):
                return cls.handle(obj)
        return super().handle_CTypeCast(obj)


class PointerArithmeticFixer(CStructuredCodeWalker):
    @classmethod
    def handle_CBinaryOp(cls, obj):
        obj = super().handle_CBinaryOp(obj)
        if (
            obj.op in ("Add", "Sub")
            and isinstance(obj.type, SimTypePointer)
            and not isinstance(obj.type.pts_to, SimTypeBottom)
        ):
            obj = obj.codegen._access_reference(obj, obj.type.pts_to)
        return obj


StructuredCodeGenerator = CStructuredCodeGenerator
register_analysis(StructuredCodeGenerator, "StructuredCodeGenerator")
