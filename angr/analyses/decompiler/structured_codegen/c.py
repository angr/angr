# pylint:disable=line-too-long,missing-class-docstring,too-many-boolean-expressions
from typing import Optional, Dict, List, Tuple, Set, Any, Union, TYPE_CHECKING, Callable
from collections import defaultdict
import logging

from ailment import Block, Expr, Stmt

from ....sim_type import (SimTypeLongLong, SimTypeInt, SimTypeShort, SimTypeChar, SimTypePointer, SimStruct, SimType,
    SimTypeBottom, SimTypeArray, SimTypeFunction, SimTypeFloat, SimTypeDouble, TypeRef, SimTypeNum)
from ....sim_variable import SimVariable, SimTemporaryVariable, SimStackVariable, SimRegisterVariable, SimMemoryVariable
from ....utils.constants import is_alignment_mask
from ....utils.library import get_cpp_function_name
from ....errors import UnsupportedNodeTypeError
from ....knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from ... import Analysis, register_analysis
from ..region_identifier import MultiNode
from ..structurer import (SequenceNode, CodeNode, ConditionNode, ConditionalBreakNode, LoopNode, BreakNode,
                         SwitchCaseNode, ContinueNode, CascadingConditionNode)
from .base import BaseStructuredCodeGenerator, InstructionMapping, PositionMapping, PositionMappingElement

if TYPE_CHECKING:
    from ailment import Expression

    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
    from angr.knowledge_plugins.functions import Function


l = logging.getLogger(name=__name__)

INDENT_DELTA = 4


def unpack_typeref(ty):
    if isinstance(ty, TypeRef):
        return ty.type
    return ty


#
#   C Representation Classes
#

class CConstruct:
    """
    Represents a program construct in C.
    Acts as the base class for all other representation constructions.
    """

    __slots__ = ('codegen',)

    def __init__(self, codegen):
        self.codegen: 'StructuredCodeGenerator' = codegen

    def c_repr(self, indent=0, pos_to_node=None, pos_to_addr=None, addr_to_pos=None):
        """
        Creates the C representation of the code and displays it by
        constructing a large string. This function is called by each program function that needs to be decompiled.
        The map_pos_to_node and map_pos_to_addr act as position maps for the location of each variable and statment to be
        tracked for later GUI operations. The map_pos_to_addr also contains expressions that are nested inside of
        statements.

        :param indent:  # of indents (int)
        :param pos_to_nodemap_pos_to_ast:
        :return:
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
                    if hasattr(obj, 'tags') and obj.tags is not None and 'ins_addr' in obj.tags:
                        if isinstance(obj, CVariable) and obj not in used_vars:
                            used_vars.add(obj)
                        else:
                            last_insn_addr = obj.tags['ins_addr']

                            # all valid statements and expressions should be added to map_pos_to_addr and
                            # tracked for instruction mapping from disassembly
                            if pos_to_addr is not None:
                                pos_to_addr.add_mapping(pos, len(s), obj)
                            if addr_to_pos is not None:
                                addr_to_pos.add_mapping(obj.tags['ins_addr'], pos)

                    # add all variables, constants, and function calls to map_pos_to_node for highlighting
                    # add ops to pos_to_node but NOT ast_to_pos
                    if isinstance(obj, (CVariable, CConstant, CStructField, CIndexedVariable, CVariableField, CBinaryOp, CUnaryOp)):
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
                    if isinstance(obj, TypeRef):
                        pos_to_node.add_mapping(pos, len(s), obj.type)
                    else:
                        pos_to_node.add_mapping(pos, len(s), obj)

                if s.endswith('\n'):
                    text = pending_stmt_comments.pop(last_insn_addr, None)
                    if text is not None:
                        todo = '  // ' + text
                        pos += len(s) - 1
                        yield s[:-1]
                        pos += len(todo)
                        yield todo
                        s = '\n'

                pos += len(s)
                yield s

                if isinstance(obj, CExpression):
                    text = pending_expr_comments.pop(last_insn_addr, None)
                    if text is not None:
                        todo = ' /*' + text + '*/ '
                        pos += len(todo)
                        yield todo

            if pending_expr_comments or pending_stmt_comments:
                yield '// Orphaned comments\n'
                for text in pending_stmt_comments.values():
                    yield '// ' + text + '\n'
                for text in pending_expr_comments.values():
                    yield '/* ' + text + '*/\n'

        # A special note about this line:
        # Polymorphism allows that the c_repr_chunks() call will be called
        # by the CFunction class, which will then call each statement within it and construct
        # the chunks that get printed in qccode_edit in angr-management.
        return ''.join(mapper(self.c_repr_chunks(indent)))

    def c_repr_chunks(self, indent=0, asexpr=False):
        raise NotImplementedError()

    @staticmethod
    def indent_str(indent=0):
        return " " * indent


class CFunction(CConstruct):  # pylint:disable=abstract-method
    """
    Represents a function in C.
    """

    __slots__ = ('addr', 'name', 'functy', 'arg_list', 'statements', 'variables_in_use', 'variable_manager',
                 'demangled_name', )

    def __init__(self, addr, name, functy: SimTypeFunction, arg_list: List['CVariable'], statements, variables_in_use,
                 variable_manager, demangled_name=None, **kwargs):

        super().__init__(**kwargs)

        self.addr = addr
        self.name = name
        self.functy = functy
        self.arg_list = arg_list
        self.statements = statements
        self.variables_in_use = variables_in_use
        self.variable_manager: 'VariableManagerInternal' = variable_manager
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

        unified_to_var_and_types: Dict[SimVariable,Set[Tuple[CVariable,SimType]]] = defaultdict(set)

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
                var_type = SimTypeBottom()

            unified_to_var_and_types[key].add((cvar, var_type))

        indent_str = self.indent_str(indent)

        for variable, cvar_and_vartypes in sorted(unified_to_var_and_types.items(),
                                                  key=lambda x: _varname_to_id(x[0].name) if x[0].name else 0):

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

            if len(cvar_and_vartypes) == 1:
                # a single type. let's be as C as possible
                _, var_type = next(iter(cvar_and_vartypes), (None, None))
                if isinstance(var_type, SimType):
                    raw_type_str = var_type.c_repr(name=name)
                else:
                    raw_type_str = '%s %s' % (var_type, name)

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
            else:
                # multiple types...
                for i, var_type in enumerate(set(typ for _, typ in cvar_and_vartypes)):
                    if i:
                        yield "|", None

                    if isinstance(var_type, SimType):
                        yield var_type.c_repr(), var_type
                    else:
                        yield str(var_type), var_type

                yield " ", None
                yield name, cvariable
            yield ";", None

            loc_repr = variable.loc_repr(self.codegen.project.arch)
            yield "  // ", None
            yield loc_repr, None
            yield "\n", None

        if unified_to_var_and_types:
            yield "\n", None

    def c_repr_chunks(self, indent=0, asexpr=False):

        indent_str = self.indent_str(indent)

        if self.codegen.show_local_types:
            for ty in self.variable_manager.types.iter_own():
                c_repr = ty.c_repr(full=True)
                c_repr = f'typedef {c_repr} {ty._name}'
                first = True
                for line in c_repr.split('\n'):
                    if first:
                        first = False
                    else:
                        yield '\n', None
                    yield indent_str, None
                    yield line, None
                yield ';\n\n', None

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
                type_post = raw_typed_varname[varname_pos + len(varname):]
                yield 'extern ', None
                yield type_pre, v.type
                if type_pre_spaces:
                    yield type_pre_spaces, None
                yield varname, v
                yield type_post, v.type
                yield ";\n", None
            yield '\n', None

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
            type_pre, type_post = raw_type_str[:varname_pos], raw_type_str[varname_pos + len(variable_name):]
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

    __slots__ = ('_type', 'collapsed', )

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
        if hasattr(expr, 'c_repr_chunks'):
            yield from expr.c_repr_chunks()
        else:
            yield str(expr), expr


class CStatements(CStatement):
    """
    Represents a sequence of statements in C.
    """

    __slots__ = ('statements', )

    def __init__(self, statements, **kwargs):

        super().__init__(**kwargs)

        self.statements = statements

    def c_repr_chunks(self, indent=0, asexpr=False):

        for stmt in self.statements:
            yield from stmt.c_repr_chunks(indent=indent)


class CAILBlock(CStatement):
    """
    Represents a block of AIL statements.
    """

    __slots__ = ('block', )

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

    __slots__ = ('condition', 'body', 'tags',)

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

    __slots__ = ('condition', 'body', 'tags',)

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
        yield "{", brace
        yield "\n", None
        yield from self.body.c_repr_chunks(indent=indent + INDENT_DELTA)
        yield indent_str, None
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

    __slots__ = ('initializer', 'condition', 'iterator', 'body', 'tags')

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
        yield '(', paren
        if self.initializer is not None:
            yield from self.initializer.c_repr_chunks(indent=0, asexpr=True)
        yield '; ', None
        if self.condition is not None:
            yield from self.condition.c_repr_chunks(indent=0)
        yield '; ', None
        if self.iterator is not None:
            yield from self.iterator.c_repr_chunks(indent=0, asexpr=True)
        yield ')', paren

        if self.codegen.braces_on_own_lines:
            yield "\n", None
            yield indent_str, None
        else:
            yield " ", None
        yield "{", brace
        yield "\n", None
        yield from self.body.c_repr_chunks(indent=indent + INDENT_DELTA)
        yield indent_str, None
        yield "}", brace
        yield '\n', None


class CIfElse(CStatement):
    """
    Represents an if-else construct in C.
    """

    __slots__ = ('condition_and_nodes', 'else_node', 'tags')

    def __init__(self, condition_and_nodes: List[Tuple[CExpression,Optional[CStatement]]], else_node=None, tags=None,
                 **kwargs):

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

    __slots__ = ('condition', 'tags', )

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

    __slots__ = ('tags', )

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

    __slots__ = ('tags', )

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

    __slots__ = ('switch', 'cases', 'default', 'tags')

    def __init__(self, switch, cases, default, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.switch = switch
        self.cases: List[Tuple[Union[int,Tuple[int]],CStatements]] = cases
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

    __slots__ = ('lhs', 'rhs', 'tags', )

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
            'Add': '+',
            'Sub': '-',
            'Mul': '*',
            'Div': '/',
            'And': '&',
            'Xor': '^',
            'Or': '|',
            'Shr': '>>',
            'Shl': '<<',
            'Sar': '>>',
        }

        if (self.codegen.use_compound_assignments
                and isinstance(self.lhs, CVariable)
                and isinstance(self.rhs, CBinaryOp)
                and isinstance(self.rhs.lhs, CVariable)
                and self.lhs.unified_variable is not None and self.rhs.lhs.unified_variable is not None
                and self.lhs.unified_variable is self.rhs.lhs.unified_variable
                and self.rhs.op in compound_assignment_ops):
            # a = a + x  =>  a += x
            yield f' {compound_assignment_ops[self.rhs.op]}= ', self
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

    __slots__ = ('callee_target', 'callee_func', 'args', 'returning', 'ret_expr', 'tags', 'is_expr', )

    def __init__(self, callee_target, callee_func, args, returning=True, ret_expr=None, tags=None, is_expr: bool=False,
                 **kwargs):
        super().__init__(**kwargs)

        self.callee_target = callee_target
        self.callee_func: Optional['Function'] = callee_func
        self.args = args if args is not None else [ ]
        self.returning = returning
        self.ret_expr = ret_expr
        self.tags = tags
        self.is_expr = is_expr

    @property
    def type(self):
        if self.is_expr:
            # TODO: Return the proper type of the ret_expr's
            return SimTypeInt(signed=False)
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
            yield "\n",  self


class CReturn(CStatement):

    __slots__ = ('retval', 'tags', )

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

    __slots__ = ('target', 'tags', )

    def __init__(self, target, tags=None, **kwargs):
        super().__init__(**kwargs)

        self.target = target
        self.tags = tags

    def c_repr_chunks(self, indent=0, asexpr=False):
        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        if self.codegen.comment_gotos:
            yield "/* ", None
        yield "goto ", self
        yield from self.target.c_repr_chunks()
        yield ";", self
        if self.codegen.comment_gotos:
            yield " */", None
        yield "\n", self


class CUnsupportedStatement(CStatement):
    """
    A wrapper for unsupported AIL statement.
    """

    __slots__ = ('stmt', )

    def __init__(self, stmt, **kwargs):
        super().__init__(**kwargs)

        self.stmt = stmt

    def c_repr_chunks(self, indent=0, asexpr=False):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield str(self.stmt), None
        yield "\n", None


class CStructField(CExpression):

    __slots__ = ('struct_type', 'offset', 'field', 'tags', )

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
            yield '...', self
            return
        yield str(self.field), self


class CVariable(CExpression):
    """
    CVariable represents access to a variable at the specified byte offset (`offset`) with the specified type
    (`variable_type`).

    `variable` is either a SimVariable or an arbitrarily complex CExpression.

    Example CVariables:

    .. code-block:: text

       v0 (on the stack, int)      -  CVariable(variable=SimStackVariable(), offset=0, variable_type=int)
       v0 (in a register, int)     -  CVariable(variable=SimRegisterVariable(), offset=0, variable_type=int)
       v0[0] (v0 is an int array)  -  CIndexedVariable(variable=CVariable(variable=..., offset=0, variable_type=int[]),
                                                       index=CConstant(0))
       v0[n] (v0 is an int array)  -  CIndexedVariable(variable=CVariable(variable=..., offset=0, variable_type=int[]),
                                                       index=CVariable(variable=n))
       v0->field (v0 is a struct)  -  CVariableField(variable=CVariable(variable=v0, offset=0, variable_type=struct *),
                                                     field="field", var_is_ptr=True)
       *(short*)((char*)&v0 + 1)   -  CVariable(variable=CVariable(variable=v0, offset=0, variable_type=int),
                                                offset=1, variable_type=short)
       *(short*)((char*)&v0 + n)   -  CVariable(variable=CVariable(variable=v0, offset=0, variable_type=int),
                                                offset=CVariable(variable=n, ...), variable_type=short)
       *(int*)((char*)g0 + off)  (g0 is a global variable: an array of structs, but we don't know the struct type)
                                   -  CVariable(variable=CVariable(variable=g0,...), offset=off, variable_type=int)
    """

    __slots__ = ('variable', 'offset', 'variable_type', 'unified_variable', 'tags', )

    def __init__(self, variable, unified_variable=None, offset=0, variable_type=None, tags=None, **kwargs):

        super().__init__(**kwargs)

        self.variable: Union[SimVariable,CExpression] = variable
        self.unified_variable: Optional[SimVariable] = unified_variable
        self.offset: Union[int,CExpression] = offset
        self.variable_type: Optional[SimType] = variable_type
        self.tags = tags

    @property
    def type(self):
        return self.variable_type

    def _get_offset_string_chunks(self, in_hex=False):
        if type(self.offset) is int:
            if in_hex:
                yield "%#x" % self.offset, self
            else:
                yield "%d" % self.offset, self
        else:
            yield from self.offset.c_repr_chunks()

    def _c_repr_variable(self, v: Union[SimVariable,CExpression]):
        if isinstance(v, SimVariable):
            if not v.name:
                yield repr(v), self
            else:
                yield v.name, self
        else:
            yield from v.c_repr_chunks()

    def _c_repr_with_offset(self, v: Union[SimVariable,'CVariable'], v_type: SimType, offset: Union[int,CExpression],
                            self_type: SimType):
        if offset == 0:
            if self_type is None or v_type == self_type:
                # no casting required
                yield from self._c_repr_variable(v)
                return
            else:
                # we need to cast
                cast = CTypeCast(self_type, v_type, v, codegen=self.codegen)
                return

        #
        # offset > 0 or is not an integer
        #

        # if it's a pointer
        arch = v_type._arch
        if isinstance(v_type, SimTypePointer):
            bracket = CClosingObject("[")

            # cast the variable to a pointer
            if self.type is not None:
                self_size = self.type.size // arch.byte_width
            else:
                self_size = 1
            if isinstance(self.offset, int) and self.offset % self_size == 0:
                offset = CConstant(self.offset // self_size, None, codegen=self.codegen)
            else:
                # uhhhhh divide by stuff
                if isinstance(self.offset, int):
                    offset = CConstant(self.offset, None, codegen=self.codegen)
                else:
                    offset = self.offset
                offset = CBinaryOp('Div', offset, CConstant(self_size, None, codegen=self.codegen), None,
                                   codegen=self.codegen)

            if isinstance(v_type, SimTypePointer) and v_type.pts_to == self.type:
                yield from self._c_repr_variable(v)
            else:
                yield from CTypeCast(v_type, SimTypePointer(self.type).with_arch(arch), v,
                                     codegen=self.codegen).c_repr_chunks()

            yield "[", bracket
            yield from offset.c_repr_chunks()
            yield "]", bracket
            return

        # for stack and global variables, we need to get the address, cast to char*, add offset, and then cast to type*,
        # and finally dereference it
        if isinstance(v, SimMemoryVariable):
            cv = CVariable(v, offset=0, codegen=self.codegen)
        elif isinstance(v, CVariable) and isinstance(v.variable, SimMemoryVariable):
            assert v.offset == 0
            cv = v
        else:
            cv = None

        if cv is not None:
            cast_inner = CTypeCast(None, SimTypePointer(SimTypeChar().with_arch(arch)).with_arch(arch),
                                   CUnaryOp("Reference", cv, codegen=self.codegen),
                                   codegen=self.codegen)
            added = CBinaryOp('Add', cast_inner, offset, None, codegen=self.codegen)

            yield "*", None
            cast_outer = CTypeCast(None, SimTypePointer(v_type).with_arch(arch), added,
                                 codegen=self.codegen)
            yield from cast_outer.c_repr_chunks()
            return

        # for other variables, we simplify perform a bit shift and type cast
        shifted = CBinaryOp('Shr', v, offset * self.codegen.project.arch.byte_width,
                            None, codegen=self.codegen, tags=getattr(v, 'tags', None))
        cast = CTypeCast(None, v_type, shifted, codegen=self.codegen)
        yield from cast.c_repr_chunks()

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield '...', self
            return

        v = self.variable if self.unified_variable is None else self.unified_variable

        if isinstance(self.offset, int) and self.offset == 0:
            if isinstance(v, SimVariable):
                if v.name:
                    yield v.name, self
                elif isinstance(v, SimTemporaryVariable):
                    yield "tmp_%d" % v.tmp_id, self
                else:
                    yield str(v), self
            elif isinstance(v, CExpression):
                yield from v.c_repr_chunks()
            else:
                yield str(v), self
        else:  # self.offset > 0
            if isinstance(v, SimVariable):
                raise TypeError("v cannot be SimVariable if offset != 0")

            if isinstance(v, CVariable):
                yield from self._c_repr_with_offset(v, v.type, self.offset, self.type)

            elif isinstance(v, CExpression):
                # this really should not happen...
                yield from self._c_repr_with_offset(v, v.type, self.offset, self.type)

            elif isinstance(v, Expr.Register):
                # umm this should not happen, either
                yield v.reg_name if hasattr(v, 'reg_name') else str(v), self
                yield ":", self
                yield from self._get_offset_string_chunks(in_hex=True)

            else:
                # ??????
                raise RuntimeError("Unexpected type of v %s" % type(v))


class CIndexedVariable(CExpression):
    """
    Represent a variable (an array) that is indexed.
    """
    def __init__(self, variable: CExpression, index: CExpression, variable_type=None, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.variable = variable
        self.index: Union[int,CExpression] = index
        self._type = variable_type
        self.tags = tags

        if self._type is None and isinstance(self.variable, (CVariable, CIndexedVariable, CVariableField)) \
                and self.variable.type is not None:
            u = unpack_typeref(self.variable.type)
            if isinstance(u, SimTypePointer):
                u = u.pts_to
                u = unpack_typeref(u)
            else:
                u = None
            if isinstance(u, SimTypeArray):
                u = u.elem_type
            self._type = u

    @property
    def type(self):
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield '...', self
            return
        if isinstance(self.index, int):
            bracket = CClosingObject("[")
            # it's pointing to an array! take the corresponding element

            yield from self.variable.c_repr_chunks()
            yield "[", bracket
            yield str(self.index), self.index
            yield "]", bracket
            return

        # in the non-int case, the variable has to be the right element index. no conversion is needed
        bracket = CClosingObject("[")
        yield from self.variable.c_repr_chunks()
        yield "[", bracket
        yield from CExpression._try_c_repr_chunks(self.index)
        yield "]", bracket


class CVariableField(CExpression):
    """
    Represent a field of a variable.
    """
    def __init__(self, variable: CExpression, field: CStructField, var_is_ptr: bool=False, tags=None, **kwargs):
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
            yield '...', self
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

    __slots__ = ('op', 'operand', 'tags', )

    def __init__(self, op, operand: CExpression, tags=None, type_=None, **kwargs):

        super().__init__(**kwargs)

        self.op = op
        self.operand = operand
        self.tags = tags
        self._type = type_

        if self._type is None and operand is not None and isinstance(operand, CExpression) and operand.type is not None:
            var_type = unpack_typeref(operand.type)
            if op == "Reference":
                self._type = SimTypePointer(var_type)
                if operand.type._arch is not None:
                    self._type = self._type.with_arch(var_type._arch)
            elif op == "Dereference":
                if isinstance(var_type, SimTypePointer):
                    self._type = unpack_typeref(var_type.pts_to)
                elif isinstance(var_type, SimTypeArray):
                    self._type = var_type.elem_type

    @property
    def type(self):
        if self._type is None:
            if self.operand is not None and hasattr(self.operand, 'type'):
                self._type = self.operand.type
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield '...', self
            return

        OP_MAP = {
            'Not': self._c_repr_chunks_not,
            'Reference': self._c_repr_chunks_reference,
            'Dereference': self._c_repr_chunks_dereference,
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

    __slots__ = ('op', 'lhs', 'rhs', 'variable', 'tags', )

    def __init__(self, op, lhs, rhs, variable, tags: Optional[dict]=None, **kwargs):

        super().__init__(**kwargs)

        self.op = op
        self.lhs = lhs
        self.rhs = rhs
        self.variable = variable
        self.tags = tags

    @property
    def type(self):
        if self._type is None:
            return self.lhs.type
        return self._type

    @property
    def op_precedence(self):
        precedence_list = [
            # lowest precedence
            ['Concat'],
            ['LogicalOr'],
            ['LogicalAnd'],
            ['Or'],
            ['Xor'],
            ['And'],
            ['CmpEQ', 'CmpNE'],
            ['CmpLE', 'CmpLT', 'CmpGT', 'CmpGE'],
            ['Shl', 'Shr', 'Sar'],
            ['Add', 'Sub'],
            ['Mul', 'Div'],
            # highest precedence
        ]
        for i, sublist in enumerate(precedence_list):
            if self.op in sublist:
                return i
        return len(precedence_list)

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield '...', self
            return

        if self.variable is not None:
            yield "&", self
            yield from self.variable.c_repr_chunks()
            return

        OP_MAP = {
            'Add': self._c_repr_chunks_add,
            'Sub': self._c_repr_chunks_sub,
            'Mul': self._c_repr_chunks_mul,
            'Mull': self._c_repr_chunks_mull,
            'Div': self._c_repr_chunks_div,
            'DivMod': self._c_repr_chunks_divmod,
            'And': self._c_repr_chunks_and,
            'Xor': self._c_repr_chunks_xor,
            'Or': self._c_repr_chunks_or,
            'Shr': self._c_repr_chunks_shr,
            'Shl': self._c_repr_chunks_shl,
            'Sar': self._c_repr_chunks_sar,
            'LogicalAnd': self._c_repr_chunks_logicaland,
            'LogicalOr': self._c_repr_chunks_logicalor,
            'CmpLE': self._c_repr_chunks_cmple,
            'CmpLEs': self._c_repr_chunks_cmple,
            'CmpLT': self._c_repr_chunks_cmplt,
            'CmpLTs': self._c_repr_chunks_cmplt,
            'CmpGT': self._c_repr_chunks_cmpgt,
            'CmpGTs': self._c_repr_chunks_cmpgt,
            'CmpGE': self._c_repr_chunks_cmpge,
            'CmpGEs': self._c_repr_chunks_cmpge,
            'CmpEQ': self._c_repr_chunks_cmpeq,
            'CmpNE': self._c_repr_chunks_cmpne,
            'Concat': self._c_repr_chunks_concat,
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
        if isinstance(self.rhs, CBinaryOp) \
                and self.op_precedence > self.rhs.op_precedence - (1 if self.op in ['Sub', 'Div'] else 0):
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

    __slots__ = ('src_type', 'dst_type', 'expr', 'tags', )

    def __init__(self, src_type, dst_type, expr, tags=None, **kwargs):

        super().__init__(**kwargs)

        self.src_type = src_type
        self.dst_type = dst_type
        self.expr = expr
        self.tags = tags

    @property
    def type(self):
        if self._type is None:
            return self.dst_type
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield '...', self
            return
        leading_paren = False
        wrapping_paren = False
        paren = CClosingObject("(")
        if self.codegen.show_casts:
            # look ahead to detect if a leading paren is required
            if isinstance(self.expr, CFunctionCall):
                leading_paren = False
            else:
                leading_paren = True
                yield "(", paren
            yield "(", paren
            yield "{}".format(self.dst_type.c_repr(name=None)), self
            yield ")", paren

        if isinstance(self.expr, CBinaryOp):
            wrapping_paren = True
            yield "(", paren
        else:
            wrapping_paren = False
        yield from CExpression._try_c_repr_chunks(self.expr)
        if wrapping_paren:
            yield ")", paren
        if self.codegen.show_casts and leading_paren:
            yield ")", paren


class CConstant(CExpression):

    __slots__ = ('value', 'reference_values', 'reference_variable', 'tags', )

    def __init__(self, value, type_, reference_values=None, reference_variable=None, tags: Optional[Dict]=None, **kwargs):

        super().__init__(**kwargs)

        self.value = value
        self._type = type_
        self.reference_values = reference_values
        self.reference_variable = reference_variable
        self.tags = tags

    @property
    def _ident(self):
        ident = (self.tags or {}).get('ins_addr', None)
        if ident is not None:
            return ('inst', ident)
        else:
            return ('val', self.value)

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
        result = self.fmt.get('hex', None)
        if result is None:
            result = False
            if isinstance(self.value, int):
                result = hex(self.value).endswith('00') or is_alignment_mask(self.value)
        return result

    @fmt_hex.setter
    def fmt_hex(self, v):
        self._fmt_setter['hex'] = v

    @property
    def fmt_neg(self):
        result = self.fmt.get('neg', None)
        if result is None:
            result = False
            if isinstance(self.value, int):
                if self.value <= 0xffff_ffff and self.value >= 0xf000_0000:
                    result = True
                elif self.value <= 0xffff_ffff_ffff_ffff and self.value >= 0xf000_0000_0000_0000:
                    result = True

        return result

    @fmt_neg.setter
    def fmt_neg(self, v):
        self._fmt_setter['neg'] = v

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
        return f"\"{base_str}\""

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield '...', self
            return

        # default priority: string references -> variables -> other reference values
        if self.reference_values is not None:
            for ty, v in self.reference_values.items():  # pylint:disable=unused-variable
                if isinstance(v, MemoryData) and v.sort == MemoryDataSort.String:
                    yield CConstant.str_to_c_str(v.content.decode('utf-8')), self
                    return

        if self.reference_variable is not None:
            yield "&", None
            yield from self.reference_variable.c_repr_chunks()

        elif self.reference_values is not None and self._type is not None and self._type in self.reference_values:
            if isinstance(self._type, SimTypeInt):
                yield hex(self.reference_values[self._type]), self
            elif isinstance(self._type, SimTypePointer) and isinstance(self._type.pts_to, SimTypeChar):
                refval = self.reference_values[self._type]  # angr.knowledge_plugin.cfg.MemoryData
                yield CConstant.str_to_c_str(refval.content.decode('utf-8')), self
            else:
                yield self.reference_values[self.type], self

        elif isinstance(self.value, int) and self.value == 0 and isinstance(self.type, SimTypePointer):
            # print NULL instead
            yield "NULL", self

        elif isinstance(self._type, SimTypePointer) and isinstance(self.value, int):
            # Print pointers in hex
            yield hex(self.value), self

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

    __slots__ = ('reg', 'tags', )

    def __init__(self, reg, tags=None, **kwargs):

        super().__init__(**kwargs)

        self.reg = reg
        self.tags = tags

    @property
    def type(self):
        # FIXME
        return SimTypeInt()

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield str(self.reg), None


class CITE(CExpression):

    __slots__ = ('cond', 'iftrue', 'iffalse', 'tags', )

    def __init__(self, cond, iftrue, iffalse, tags=None, **kwargs):
        super().__init__(**kwargs)
        self.cond = cond
        self.iftrue = iftrue
        self.iffalse = iffalse
        self.tags = tags

    @property
    def type(self):
        return SimTypeInt()

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield '...', self
            return
        paren = CClosingObject("(")
        yield "(", paren
        yield from self.cond.c_repr_chunks()
        yield "? ", self
        yield from self.iftrue.c_repr_chunks()
        yield " : ", self
        yield from self.iffalse.c_repr_chunks()
        yield ")", paren


class CDirtyExpression(CExpression):
    """
    Ideally all dirty expressions should be handled and converted to proper conversions during conversion from VEX to
    AIL. Eventually this class should not be used at all.
    """

    __slots__ = ('dirty', )

    def __init__(self, dirty, **kwargs):
        super().__init__(**kwargs)
        self.dirty = dirty

    @property
    def type(self):
        return SimTypeInt()

    def c_repr_chunks(self, indent=0, asexpr=False):
        if self.collapsed:
            yield '...', self
            return
        yield str(self.dirty), None


class CClosingObject:
    """
    A class to represent all objects that can be closed by it's correspodning character.
    Examples: (), {}, []
    """
    __slots__ = ('opening_symbol',)

    def __init__(self, opening_symbol):
        self.opening_symbol = opening_symbol


class CStructuredCodeGenerator(BaseStructuredCodeGenerator, Analysis):
    def __init__(self, func, sequence, indent=0, cfg=None, variable_kb=None,
                 func_args: Optional[List[SimVariable]]=None, binop_depth_cutoff: int=16,
                 show_casts=True, braces_on_own_lines=True, use_compound_assignments=True, show_local_types=True,
                 comment_gotos=True, flavor=None, stmt_comments=None, expr_comments=None, show_externs=True,
                 externs=None, const_formats=None):
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
            Stmt.Return: self._handle_Stmt_Return,
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
            # SimVariables
            SimStackVariable: self._handle_Variable_SimStackVariable,
            SimRegisterVariable: self._handle_Variable_SimRegisterVariable,
            SimMemoryVariable: self._handle_Variable_SimMemoryVariable,
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
        self.expr_comments: Dict[int,str] = expr_comments if expr_comments is not None else {}
        self.stmt_comments: Dict[int,str] = stmt_comments if stmt_comments is not None else {}
        self.const_formats: Dict[Any, Dict[str, Any]] = const_formats if const_formats is not None else {}
        self.externs = externs or set()
        self.show_externs = show_externs

        self.text = None
        self.map_pos_to_node = None
        self.map_pos_to_addr = None
        self.map_addr_to_pos = None
        self.map_ast_to_pos: Optional[Dict[SimVariable, Set[PositionMappingElement]]] = None
        self.cfunc = None
        self.cexterns: Optional[Set[CVariable]] = None

        self._analyze()

        if flavor is not None:
            self.kb.structured_code[(func.addr, flavor)] = self

    def reapply_options(self, options):
        for option, value in options:
            if option.param == 'braces_on_own_lines':
                self.braces_on_own_lines = value
            elif option.param == 'show_casts':
                self.show_casts = value
            elif option.param == 'comment_gotos':
                self.comment_gotos = value
            elif option.param == 'use_compound_assignments':
                self.use_compound_assignments = value
            elif option.param == 'show_local_types':
                self.show_local_types = value
            elif option.param == 'show_externs':
                self.show_externs = value

    def _analyze(self):

        self._variables_in_use = {}

        # memo
        self.ailexpr2cnode = {}

        if self._func_args:
            arg_list = [self._handle(arg) for arg in self._func_args]
        else:
            arg_list = [ ]

        obj = self._handle(self._sequence)

        self.cnode2ailexpr = dict((v, k[0]) for k, v in self.ailexpr2cnode.items())

        self.cfunc = CFunction(self._func.addr, self._func.name, self._func.prototype, arg_list, obj,
                               self._variables_in_use, self._variable_kb.variables[self._func.addr],
                               demangled_name=self._func.demangled_name, codegen=self)

        self.cexterns = {self._try_make_cvariable(v, variable_type=self._get_variable_type(v, is_global=True))
                         for v in self.externs if v not in self._inlined_strings}

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
        self.text, self.map_pos_to_node, self.map_pos_to_addr, self.map_addr_to_pos, self.map_ast_to_pos = self.render_text(self.cfunc)

    def render_text(self, cfunc: CFunction) -> Tuple[str,PositionMapping,PositionMapping,InstructionMapping,Dict[Any,Set[Any]]]:

        pos_to_node = PositionMapping()
        pos_to_addr = PositionMapping()
        addr_to_pos = InstructionMapping()
        ast_to_pos = defaultdict(set)

        text = cfunc.c_repr(indent=self._indent, pos_to_node=pos_to_node, pos_to_addr=pos_to_addr, addr_to_pos=addr_to_pos)

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
            return self._variable_kb.variables['global'].get_variable_type(var)
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
                var.variable_type = self._get_variable_type(var.variable,
                                                            is_global=isinstance(var.variable, SimMemoryVariable) and
                                                                      not isinstance(var.variable, SimStackVariable))

        for var in self.cexterns:
            if isinstance(var, CVariable):
                var.variable_type = self._get_variable_type(var.variable, is_global=True)

    #
    # Util methods
    #

    def _parse_addr(self, addr) -> Tuple[Optional[CExpression],Optional[CExpression]]:

        if isinstance(addr, CExpression):
            expr = addr
        else:
            expr = self._handle(addr)

        if isinstance(expr, CBinaryOp):
            if expr.op == "And" and isinstance(expr.rhs, CConstant) and is_alignment_mask(expr.rhs.value):
                # alignment - ignore it
                return self._parse_addr(expr.lhs)
            if expr.op in ("Add", "Sub"):
                # variable and a const
                base_addr, offset = None, None
                if isinstance(expr.lhs, CConstant):
                    # const + ...
                    if isinstance(expr.rhs, CVariable):
                        offset = expr.lhs.value
                        base_addr = expr.rhs
                    elif isinstance(expr.lhs.reference_variable, CVariable) \
                            and isinstance(expr.lhs.reference_variable.variable, SimMemoryVariable):
                        base_addr = expr.lhs.reference_variable
                        offset = expr.rhs
                elif isinstance(expr.rhs, CConstant):
                    # ... + const
                    if isinstance(expr.lhs, CVariable):
                        offset = expr.rhs.value
                        base_addr = expr.lhs
                    elif isinstance(expr.rhs.reference_variable, CVariable) \
                            and isinstance(expr.rhs.reference_variable.variable, SimMemoryVariable):
                        base_addr = expr.rhs.reference_variable
                        offset = expr.lhs
                elif isinstance(expr.lhs, CVariable) and isinstance(expr.rhs, CTypeCast):
                    # variable and a typecast
                    offset = expr.rhs
                    base_addr = expr.lhs
                elif isinstance(expr.rhs, CVariable) and isinstance(expr.lhs, CTypeCast):
                    # variable and a typecast
                    offset = expr.lhs
                    base_addr = expr.rhs
                elif isinstance(expr.lhs, CVariable) and isinstance(expr.rhs, CBinaryOp):
                    # variable (probably a pointer) + var1 * sizeof(pointer_type(variable))
                    multiplier = None
                    if expr.rhs.op == "Shl" and isinstance(expr.rhs.rhs, CConstant):
                        multiplier = expr.rhs.rhs.value ** 2
                    # TODO: support multiplication
                    if multiplier is not None:
                        base_addr = expr.lhs
                        offset = expr.rhs
                    else:
                        # no multiplier is found
                        # variable + variable?
                        base_addr = expr.lhs
                        offset = expr.rhs
                elif isinstance(expr.lhs, CVariable) and isinstance(expr.rhs, CVariable):
                    # GUESS: we need some guessing here
                    base_addr = expr.lhs
                    offset = expr.rhs

                if base_addr is None:
                    # this is also a guess
                    base_addr = expr.lhs
                    offset = expr.rhs

                return base_addr, offset
        elif isinstance(expr, CVariable):
            return expr, CConstant(0, SimTypeInt(signed=False), codegen=self)
        elif isinstance(expr, CTypeCast):
            return self._parse_addr(expr.expr)
        elif isinstance(expr, CConstant):
            if expr.reference_variable is not None:
                ref = CUnaryOp("Reference", expr.reference_variable, codegen=self)
                return ref, CConstant(0, SimTypeInt(signed=False), codegen=self)
            else:
                return None, expr.value
        elif isinstance(expr, int):
            return None, CConstant(expr, SimTypeInt(signed=False), codegen=self)
        elif isinstance(expr, Expr.DirtyExpression):
            l.warning("Got a DirtyExpression %s. It should have been handled during VEX->AIL conversion.", expr)
            return expr, None
        elif isinstance(expr, CExpression):  # other expressions
            return expr, None

        l.warning("Unsupported address expression %r", addr)
        return expr, None

    def default_simtype_from_size(self, n: int) -> SimType:
        _mapping = {
            8: SimTypeLongLong,
            4: SimTypeInt,
            2: SimTypeShort,
            1: SimTypeChar,
        }
        if n in _mapping:
            return _mapping.get(n)().with_arch(self.project.arch)
        return SimTypeNum(n * self.project.arch.byte_width).with_arch(self.project.arch)

    def _array_element(self, addr: Union[CExpression,SimVariable], variable_type: SimType,
                       displacement: Union[int,CExpression],
                       tags: Optional[Dict]=None) -> Optional[CIndexedVariable]:
        type_size = None
        if isinstance(variable_type, SimTypePointer) and isinstance(unpack_typeref(variable_type.pts_to), SimTypeArray):
            # unpack the pointer
            type_size = variable_type.pts_to.elem_type.size // self.project.arch.byte_width
        elif isinstance(variable_type, SimTypePointer):
            inner_type = unpack_typeref(variable_type.pts_to)
            if isinstance(inner_type, SimTypePointer):
                type_size = inner_type.size // self.project.arch.byte_width
                # double pointer - unpack the Reference unary operator if there is one
                if isinstance(addr, CUnaryOp) and addr.op == "Reference":
                    addr = addr.operand
        elif isinstance(variable_type, SimTypeArray):
            type_size = variable_type.elem_type.size // self.project.arch.byte_width

        if type_size is not None:
            # the offset argument that is passed in is in terms of bytes. parse the offset argument and convert it into
            # an index
            if isinstance(displacement, int):
                if displacement % type_size != 0:
                    l.warning("offset (%d) is not a multiple of type_size (%d). Implement this case,",
                              displacement, type_size)
                idx = displacement // type_size  # TODO: Handle the case when offset is not a multiple of type_size
            elif isinstance(displacement, CConstant):
                if displacement.value % type_size != 0:
                    l.warning("offset (%d) is not a multiple of type_size (%d). Implement this case,",
                              displacement.value, type_size)
                idx = displacement.value // type_size  # TODO: Handle the case when offset is not a multiple of type_size
            elif isinstance(displacement, CBinaryOp) and isinstance(displacement.rhs, CConstant):
                # calculate element size
                if displacement.op == "Mul":
                    elem_size = displacement.rhs.value
                elif displacement.op == "Shl":
                    elem_size = 2 ** displacement.rhs.value
                else:
                    l.warning("Unsupported variable offsetting operator %s. Default elem_size to 1.", displacement.op)
                    elem_size = 1

                if type_size == elem_size:
                    # awesome - no conversion needed
                    idx = displacement.lhs
                else:
                    # damn - we need conversion
                    if elem_size > type_size:
                        coeff = CConstant(elem_size // type_size,
                                          self.default_simtype_from_size(self.project.arch.bytes),
                                          codegen=self)
                        idx = CBinaryOp("Mul", displacement.lhs, coeff, None, codegen=self)
                    else:  # elem_size < type_size
                        coeff = CConstant(type_size // elem_size,
                                          self.default_simtype_from_size(self.project.arch.bytes),
                                          codegen=self)
                        idx = CBinaryOp("Div",
                                        displacement.lhs,
                                        coeff,
                                        None,
                                        codegen=self)
            else:
                idx = None

            if idx is not None:
                cvariable = self._try_make_cvariable(addr, variable_type=variable_type, tags=tags)
                return CIndexedVariable(cvariable, idx, tags=tags, codegen=self)

        return None

    def _struct_field(self, variable: CExpression, variable_type: SimType, displacement: Union[int,CExpression],
                      tags: Optional[Dict]=None) -> Optional[CVariableField]:
        #
        # struct
        #
        struct_type = None
        is_ptr = None
        if isinstance(variable_type, SimTypePointer) and isinstance(unpack_typeref(variable_type.pts_to), SimStruct):
            is_ptr = True
            struct_type = unpack_typeref(variable_type.pts_to)
        elif isinstance(variable_type, SimStruct):
            is_ptr = False
            struct_type = variable_type

        if struct_type is not None:
            # we use offset to figure out which field it is accessing
            if isinstance(displacement, CConstant):
                displacement = displacement.value

            if isinstance(displacement, int):
                # which field is it pointing to?
                offset_to_field = dict((v, k) for k, v in struct_type.offsets.items())
                # TODO: Handle the case where it is accessing the middle of a field
                if displacement in offset_to_field:
                    cvariable = self._try_make_cvariable(variable, variable_type=variable_type, tags=tags)
                    field = offset_to_field[displacement]
                    c_field = CStructField(struct_type, displacement, field, codegen=self)
                    return CVariableField(cvariable, c_field, var_is_ptr=is_ptr, tags=tags, codegen=self)
                else:
                    # TODO: Handle this case as well
                    # accessing beyond known offset - indicates a bug in type inference
                    l.warning("Accessing non-existent offset %d in struct %s. This indicates a bug in "
                              "the type inference engine.", displacement, struct_type)

        return None

    def _ref_addr_displacement(self, addr: Union[SimVariable,CExpression], displacement: Union[int, CExpression]=0,
                               addr_type=None, tags=None):
        # &arr[2]
        # &v0->field
        # v0 + disp

        addr_type = unpack_typeref(addr_type)
        if addr_type is not None and not isinstance(addr_type, SimTypeBottom):
            # array element?
            var = self._array_element(addr, addr_type, displacement, tags=tags)
            if var is not None:
                return CUnaryOp("Reference", var, codegen=self)

            # struct field?
            var = self._struct_field(addr, addr_type, displacement, tags=tags)
            if var is not None:
                return CUnaryOp("Reference", var, codegen=self)

            # TODO: Handle other types of access

        if displacement == 0 or isinstance(displacement, CConstant) and displacement.value == 0:
            var = addr
        else:
            if isinstance(displacement, int):
                displacement = CConstant(displacement, addr_type, codegen=self)
            var = CBinaryOp("Add", addr, displacement, None, codegen=self)
        return var

    def _deref_addr_displacement(self, addr: Union[SimVariable,CExpression], displacement: Union[int,CExpression]=0,
                                 addr_type=None, tags=None):
        # arr[2]
        # v0->field
        # *(type*)(v0 + disp)

        addr_type = unpack_typeref(addr_type)
        if addr_type is not None and not isinstance(addr_type, SimTypeBottom):
            # struct field?
            var = self._struct_field(addr, addr_type, displacement, tags=tags)
            if var is not None:
                return var

            # array element?
            var = self._array_element(addr, addr_type, displacement, tags=tags)
            if var is not None:
                return var

            # TODO: Handle other types of access

        if displacement == 0 or isinstance(displacement, CConstant) and displacement.value == 0:
            var = CUnaryOp("Dereference", addr, codegen=self)
        else:
            if isinstance(displacement, int):
                displacement = CConstant(displacement, addr_type, codegen=self)
            var_inner = CBinaryOp("Add", addr, displacement, None, codegen=self)
            var = CUnaryOp("Dereference", var_inner, codegen=self)
        return var

    def _try_make_cvariable(self, variable: Union[SimVariable,CExpression], variable_type: Optional[SimType]=None,
                            offset: int=0, tags: Optional[Dict]=None) -> CVariable:
        if isinstance(variable, SimVariable):
            unified = self._variable_kb.variables[self._func.addr].unified_variable(variable)
        else:
            unified = None

        if isinstance(variable, SimVariable):
            inner_var = CVariable(variable, unified_variable=unified, offset=0, variable_type=variable_type,
                                  tags=tags, codegen=self)
            if offset == 0:
                cvariable = inner_var
            else:
                cvariable = CVariable(inner_var, offset=offset, variable_type=variable_type,
                                      tags=tags, codegen=self)
        elif isinstance(variable, CVariable):
            cvariable = CVariable(variable, unified_variable=unified, offset=offset,
                                  variable_type=variable_type, tags=tags,
                                  codegen=self)
        else:
            cvariable = CVariable(variable, unified_variable=unified, offset=offset,
                                  variable_type=variable_type, tags=tags,
                                  codegen=self)

        if isinstance(variable, SimVariable):
            self._variables_in_use[variable] = cvariable

        if variable_type is not None and isinstance(variable, SimVariable) \
                and not isinstance(variable_type, SimTypeBottom) \
                and variable_type.size // self.project.arch.byte_width < variable.size:
            # we need a type cast
            cvariable = CTypeCast(cvariable.type, variable_type, cvariable, codegen=self)

        return cvariable

    #
    # Handlers
    #

    def _handle(self, node, is_expr: bool=True):

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

        lines = [ ]

        for node in seq.nodes:
            lines.append(self._handle(node, is_expr=False))

        if not lines:
            return CStatements([], codegen=None)

        return CStatements(lines, codegen=self) if len(lines) > 1 else lines[0]

    def _handle_Loop(self, loop_node):
        tags = {'ins_addr': loop_node.addr}

        if loop_node.sort == 'while':
            return CWhileLoop(None if loop_node.condition is None else self._handle(loop_node.condition),
                              self._handle(loop_node.sequence_node, is_expr=False),
                              tags=tags,
                              codegen=self,
                              )
        elif loop_node.sort == 'do-while':
            return CDoWhileLoop(self._handle(loop_node.condition),
                                self._handle(loop_node.sequence_node, is_expr=False),
                                tags=tags,
                                codegen=self,
                                )
        elif loop_node.sort == 'for':
            return CForLoop(None if loop_node.initializer is None else self._handle(loop_node.initializer),
                            None if loop_node.condition is None else self._handle(loop_node.condition),
                            None if loop_node.iterator is None else self._handle(loop_node.iterator),
                            self._handle(loop_node.sequence_node, is_expr=False),
                            tags=tags,
                            codegen=self,
                            )

        else:
            raise NotImplementedError()

    def _handle_Condition(self, condition_node: ConditionNode):
        tags = {'ins_addr': condition_node.addr}

        condition_and_nodes = [
            (self._handle(condition_node.condition),
             self._handle(condition_node.true_node, is_expr=False) if condition_node.true_node else None)
        ]

        else_node = self._handle(condition_node.false_node, is_expr=False) if condition_node.false_node else None

        code = CIfElse(condition_and_nodes,
                       else_node=else_node,
                       tags=tags,
                       codegen=self,
                       )
        return code

    def _handle_CascadingCondition(self, cond_node: CascadingConditionNode):
        tags = {'ins_addr': cond_node.addr}

        condition_and_nodes = [(self._handle(cond), self._handle(node, is_expr=False))
                               for cond, node in cond_node.condition_and_nodes]
        else_node = self._handle(cond_node.else_node) if cond_node.else_node is not None else None

        code = CIfElse(condition_and_nodes,
                       else_node=else_node,
                       tags=tags,
                       codegen=self,
                       )
        return code

    def _handle_ConditionalBreak(self, node):  # pylint:disable=no-self-use
        tags = {'ins_addr': node.addr}

        return CIfBreak(self._handle(node.condition), tags=tags, codegen=self)

    def _handle_Break(self, node):  # pylint:disable=no-self-use,unused-argument
        tags = {'ins_addr': node.addr}

        return CBreak(tags=tags, codegen=self)

    def _handle_MultiNode(self, node):  # pylint:disable=no-self-use

        lines = [ ]

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
        cases = [ (idx, self._handle(case, is_expr=False)) for idx, case in node.cases.items() ]
        default = self._handle(node.default_node, is_expr=False) if node.default_node is not None else None
        tags = {'ins_addr': node.addr}
        switch_case = CSwitchCase(switch_expr, cases, default=default, tags=tags, codegen=self)
        return switch_case

    def _handle_Continue(self, node):  # pylint:disable=no-self-use,unused-argument
        tags = {'ins_addr': node.addr}

        return CContinue(tags=tags, codegen=self)

    def _handle_AILBlock(self, node):
        """

        :param Block node:
        :return:
        """

        # return CStatements([ CAILBlock(node) ])
        cstmts = [ ]
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

        if stmt.variable is not None:
            # storing to a variable directly
            cdst = self._handle(stmt.variable)
        elif stmt.addr is not None:
            # storing to an address specified by a variable
            caddr = self._handle(stmt.addr)
            base_addr, displacement = self._parse_addr(caddr)

            if base_addr is not None:
                cdst = self._deref_addr_displacement(base_addr, displacement=displacement,
                                                     addr_type=base_addr.type,
                                                     tags=base_addr.tags)
            else:
                cdst = CUnaryOp("Dereference", caddr, tags=stmt.tags, codegen=self)
        else:
            l.warning("Store statement %s has no variable linked with it.", stmt)
            cdst = None

        cdata = self._handle(stmt.data)

        return CAssignment(cdst, cdata, tags=stmt.tags, codegen=self)

    def _handle_Stmt_Assignment(self, stmt):

        cdst = self._handle(stmt.dst)
        csrc = self._handle(stmt.src)

        return CAssignment(cdst, csrc, tags=stmt.tags, codegen=self)

    def _handle_Stmt_Call(self, stmt, is_expr: bool=False):

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

        args = [ ]
        if stmt.args is not None:
            for i, arg in enumerate(stmt.args):
                type_ = None
                if target_func is not None:
                    if target_func.prototype is not None and i < len(target_func.prototype.args):
                        type_ = target_func.prototype.args[i].with_arch(self.project.arch)

                if isinstance(arg, Expr.Const):
                    new_arg = self._handle_Expr_Const(arg, type_=type_)
                else:
                    new_arg = self._handle(arg)
                args.append(new_arg)

        ret_expr = None
        if stmt.ret_expr is not None:
            if stmt.ret_expr.variable is not None:
                ret_expr = self._try_make_cvariable(
                    stmt.ret_expr.variable,
                    offset=0 if stmt.ret_expr.variable_offset is None else stmt.ret_expr.variable_offset,
                    tags=stmt.ret_expr.tags)
            else:
                ret_expr = self._handle(stmt.ret_expr)

        return CFunctionCall(target, target_func, args,
                             returning=target_func.returning if target_func is not None else True,
                             ret_expr=ret_expr,
                             tags=stmt.tags,
                             is_expr=is_expr,
                             codegen=self,
                             )

    def _handle_Stmt_Jump(self, stmt):
        return CGoto(self._handle(stmt.target), tags=stmt.tags, codegen=self)

    def _handle_Stmt_Return(self, stmt: Stmt.Return):
        if not stmt.ret_exprs:
            return CReturn(None, tags=stmt.tags, codegen=self)
        elif len(stmt.ret_exprs) == 1:
            ret_expr = stmt.ret_exprs[0]
            if not isinstance(ret_expr, Stmt.Call) and ret_expr.variable is not None:
                return CReturn(self._try_make_cvariable(
                    ret_expr.variable,
                    offset=0 if ret_expr.variable_offset is None else ret_expr.variable_offset),
                    tags=stmt.tags,
                    codegen=self)
            return CReturn(self._handle(ret_expr), tags=stmt.tags, codegen=self)
        else:
            # TODO: Multiple return expressions
            l.warning("StructuredCodeGen does not support multiple return expressions yet. Only picking the first one.")
            ret_expr = stmt.ret_exprs[0]
            if ret_expr.variable is not None:
                return CReturn(self._try_make_cvariable(
                    ret_expr.variable,
                    offset=0 if ret_expr.variable_offset is None else ret_expr.variable_offset),
                    tags=stmt.tags, codegen=self,
                )
            return CReturn(self._handle(ret_expr), tags=stmt.tags, codegen=self)

    #
    # AIL expression handlers
    #

    def _handle_Expr_Register(self, expr):  # pylint:disable=no-self-use

        if expr.variable:
            return self._handle(expr.variable)
        else:
            return CRegister(expr, tags=expr.tags, codegen=self)

    def _handle_Expr_Load(self, expr: Expr.Load):

        if expr.variable is not None:
            if expr.variable_offset is not None:
                if isinstance(expr.variable_offset, int):
                    offset = expr.variable_offset
                else:
                    offset = self._handle(expr.variable_offset)
            else:
                offset = None

            vartype = None
            if not offset and expr.size == expr.variable.size:
                vartype = self._get_variable_type(
                    expr.variable,
                    is_global=isinstance(expr.variable, SimMemoryVariable) and
                              not isinstance(expr.variable, SimStackVariable)
                )
            if vartype is None:
                vartype = self.default_simtype_from_size(expr.size)

            return self._try_make_cvariable(expr.variable, offset=offset, variable_type=vartype, tags=expr.tags)

        base_addr, displacement = self._parse_addr(expr.addr)

        if base_addr is not None and displacement is not None:
            expr = self._deref_addr_displacement(base_addr, displacement=displacement, addr_type=base_addr.type,
                                                 tags=expr.tags)
            return expr

        if base_addr is not None and displacement is None:
            return self._deref_addr_displacement(base_addr, displacement=0, addr_type=base_addr.type, tags=expr.tags)
        if base_addr is None and displacement is not None:
            return self._deref_addr_displacement(
                CConstant(displacement, SimTypePointer(SimTypeInt), codegen=self), tags=expr.tags)

        l.error("FIXME: Load with an unparseable address leading to a None in output.")
        return self._try_make_cvariable(CConstant(None, SimTypePointer(SimTypeInt), codegen=self), tags=expr.tags)

    def _handle_Expr_Tmp(self, expr):  # pylint:disable=no-self-use

        l.warning("FIXME: Leftover Tmp expressions are found.")
        return self._try_make_cvariable(SimTemporaryVariable(expr.tmp_idx), tags=expr.tags)

    def _handle_Expr_Const(self, expr, type_=None, reference_values=None, variable=None):  # pylint:disable=no-self-use

        inline_string = False

        if reference_values is None:
            reference_values = { }
            type_ = unpack_typeref(type_)
            if isinstance(type_, SimTypePointer) and isinstance(type_.pts_to, SimTypeChar):
                # char*
                # Try to get a string
                if (self._cfg is not None
                    and expr.value in self._cfg.memory_data
                    and self._cfg.memory_data[expr.value].sort == MemoryDataSort.String):
                    reference_values[type_] = self._cfg.memory_data[expr.value]
                    inline_string = True
            elif isinstance(type_, SimTypeInt):
                # int
                reference_values[type_] = expr.value

            # we don't know the type of this argument, or the type is not what we are expecting
            # edge cases: (void*)"this is a constant string pointer". in this case, the type_ will be a void*
            # (BOT*) instead of a char*.

            # pure guessing: is it possible that it's a string?
            if self._cfg is not None and \
                    expr.bits == self.project.arch.bits and \
                    expr.value > 0x10000 and \
                    expr.value in self._cfg.memory_data and \
                    self._cfg.memory_data[expr.value].sort == MemoryDataSort.String:
                type_ = SimTypePointer(SimTypeChar()).with_arch(self.project.arch)
                reference_values[type_] = self._cfg.memory_data[expr.value]
                inline_string = True

        if type_ is None:
            # default to int
            type_ = SimTypeInt().with_arch(self.project.arch)

        if variable is None and hasattr(expr, 'reference_variable') and expr.reference_variable is not None:
            variable = self._handle(expr.reference_variable)
            if inline_string:
                self._inlined_strings.add(expr.reference_variable)

        return CConstant(expr.value, type_,
                         reference_values=reference_values,
                         reference_variable=variable,
                         tags=expr.tags,
                         codegen=self)

    def _handle_Expr_UnaryOp(self, expr):

        return CUnaryOp(expr.op, self._handle(expr.operand),
                        tags=expr.tags,
                        codegen=self,
                        )

    def _handle_Expr_BinaryOp(self, expr):
        lhs = self._handle(expr.operands[0])
        rhs = self._handle(expr.operands[1])

        return CBinaryOp(expr.op, lhs, rhs,
                         variable=self._handle(expr.variable) if expr.variable is not None else None,
                         tags=expr.tags,
                         codegen=self,
                         collapsed=expr.depth > self.binop_depth_cutoff,
                         )

    def _handle_Expr_Convert(self, expr):
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

        return CTypeCast(None, dst_type, self._handle(expr.operand), tags=expr.tags, codegen=self)

    def _handle_Expr_Dirty(self, expr):  # pylint:disable=no-self-use
        return CDirtyExpression(expr, codegen=self)

    def _handle_Expr_ITE(self, expr: Expr.ITE):
        return CITE(self._handle(expr.cond), self._handle(expr.iftrue), self._handle(expr.iffalse), tags=expr.tags,
                    codegen=self)

    def _handle_Reinterpret(self, expr: Expr.Reinterpret):

        def _to_type(bits, typestr):
            if typestr == "I":
                if bits == 32:
                    return SimTypeInt()
                elif bits == 64:
                    return SimTypeLongLong()
                else:
                    raise TypeError(f"Unsupported integer type with bits {bits} in Reinterpret")
            elif typestr == "F":
                if bits == 32:
                    return SimTypeFloat()
                elif bits == 64:
                    return SimTypeDouble()
                else:
                    raise TypeError(f"Unsupported floating-point type with bits {bits} in Reinterpret")
            raise TypeError(f"Unexpected reinterpret type {typestr}")

        src_type = _to_type(expr.from_bits, expr.from_type)
        dst_type = _to_type(expr.to_bits, expr.to_type)
        return CTypeCast(src_type, dst_type, self._handle(expr.operand), tags=expr.tags, codegen=self)

    def _handle_Expr_StackBaseOffset(self, expr):  # pylint:disable=no-self-use

        if expr.variable is not None:
            var_thing = self._handle(expr.variable)
            var_thing.tags = dict(expr.tags)
            if 'def_at' in var_thing.tags and 'ins_addr' not in var_thing.tags:
                var_thing.tags['ins_addr'] = var_thing.tags['def_at'].ins_addr
            return CUnaryOp('Reference', var_thing, codegen=self)

        # FIXME
        r = CUnaryOp('Reference', expr, tags=expr.tags, codegen=self)
        r.set_type(SimTypeLongLong())
        return r

    def _handle_Variable_SimStackVariable(self, variable):  # pylint:disable=no-self-use
        return self._try_make_cvariable(variable, variable_type=self._get_variable_type(variable))

    def _handle_Variable_SimRegisterVariable(self, variable):  # pylint:disable=no-self-use
        return self._try_make_cvariable(variable, variable_type=self._get_variable_type(variable))

    def _handle_Variable_SimMemoryVariable(self, variable):  # pylint:disable=no-self-use
        return self._try_make_cvariable(variable, variable_type=self._get_variable_type(variable, is_global=True))


StructuredCodeGenerator = CStructuredCodeGenerator
register_analysis(StructuredCodeGenerator, 'StructuredCodeGenerator')
