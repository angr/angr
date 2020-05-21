from typing import Optional, Dict, List
from collections import defaultdict
import logging

from sortedcontainers import SortedDict

from ailment import Block, Expr, Stmt

from ...sim_type import (SimTypeLongLong, SimTypeInt, SimTypeShort, SimTypeChar, SimTypePointer, SimStruct, SimType,
    SimTypeBottom, SimTypeArray, SimTypeFunction)
from ...sim_variable import SimVariable, SimTemporaryVariable, SimStackVariable, SimRegisterVariable, SimMemoryVariable
from ...utils.constants import is_alignment_mask
from ...errors import UnsupportedNodeTypeError
from .. import Analysis, register_analysis
from .region_identifier import MultiNode
from .structurer import (SequenceNode, CodeNode, ConditionNode, ConditionalBreakNode, LoopNode, BreakNode,
                         SwitchCaseNode, ContinueNode)


l = logging.getLogger(name=__name__)

INDENT_DELTA = 4


class PositionMappingElement:

    __slots__ = ('start', 'length', 'obj')

    def __init__(self, start, length, obj):
        self.start = start
        self.length = length
        self.obj = obj

    def __contains__(self, offset):
        return self.start <= offset < self.start + self.length

    def __repr__(self):
        return "<%d-%d: %s>" % (self.start, self.start + self.length, self.obj.c_repr())


class PositionMapping:

    __slots__ = ('_posmap', )

    DUPLICATION_CHECK = True

    def __init__(self):
        self._posmap = SortedDict()

    def items(self):
        return self._posmap.items()

    #
    # Public methods
    #

    def add_mapping(self, start_pos, length, obj):
        # duplication check
        if self.DUPLICATION_CHECK:
            try:
                pre = next(self._posmap.irange(maximum=start_pos, reverse=True))
                if start_pos in self._posmap[pre]:
                    raise ValueError("New mapping is overlapping with an existing element.")
            except StopIteration:
                pass

        self._posmap[start_pos] = PositionMappingElement(start_pos, length, obj)

    def get_node(self, pos):
        element = self.get_element(pos)
        if element is None:
            return None
        return element.obj

    def get_element(self, pos):
        try:
            pre = next(self._posmap.irange(maximum=pos, reverse=True))
        except StopIteration:
            return None

        element = self._posmap[pre]
        if pos in element:
            return element
        return None


class CConstruct:
    """
    Represents a program construct in C.
    """

    __slots__ = ()

    def __init__(self):
        pass

    def c_repr(self, indent=0, posmap=None):

        def mapper(chunks, posmap):
            pos = 0
            for s, obj in chunks:
                if obj is not None:
                    posmap.add_mapping(pos, len(s), obj)
                pos += len(s)
                yield s

        return ''.join(mapper(self.c_repr_chunks(indent), posmap))

    def c_repr_chunks(self, indent=0):
        raise NotImplementedError()

    @staticmethod
    def indent_str(indent=0):
        return " " * indent


class CFunction(CConstruct):  # pylint:disable=abstract-method
    """
    Represents a function in C.
    """

    __slots__ = ('name', 'functy', 'arg_list', 'statements', 'variables_in_use', 'variable_manager', 'demangled_name', )

    def __init__(self, name, functy: SimTypeFunction, arg_list: List['CExpression'], statements, variables_in_use,
                 variable_manager, demangled_name=None):

        super(CFunction, self).__init__()

        self.name = name
        self.functy = functy
        self.arg_list = arg_list
        self.statements = statements
        self.variables_in_use = variables_in_use
        self.variable_manager = variable_manager
        self.demangled_name = demangled_name

    def variable_list_repr_chunks(self, indent=0):

        variable_to_types = defaultdict(set)

        # output each variable and its type
        for var, cvar in self.variables_in_use.items():
            var_type = self.variable_manager.get_variable_type(var)

            if var_type is None:
                var_type = SimTypeBottom()

            variable_to_types[(var, cvar)].add(var_type)

        indent_str = self.indent_str(indent)

        for (variable, cvariable), vartypes in variable_to_types.items():

            yield indent_str, None

            for i, var_type in enumerate(vartypes):
                if i:
                    yield "|", None

                if isinstance(var_type, SimType):
                    yield var_type.c_repr(), None
                else:
                    yield str(var_type), None

            yield " ", None
            if variable.name:
                yield variable.name, cvariable
            else:
                yield str(variable), cvariable
            yield ";\n", None

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent)

        yield indent_str, None
        # return type
        yield self.functy.returnty.c_repr(), None
        yield " ", None
        # function name
        yield self.demangled_name or self.name, None
        # argument list
        yield "(", None
        for i, (arg_type, arg) in enumerate(zip(self.functy.args, self.arg_list)):
            yield arg_type.c_repr(), None
            yield " ", None
            yield from arg.c_repr_chunks()
            if i != len(self.arg_list) - 1:
                yield ", ", None
        yield ")\n", None
        # function body
        yield indent_str, None
        yield "{\n", None
        yield from self.variable_list_repr_chunks(indent=indent + INDENT_DELTA)
        yield "\n", None
        yield from self.statements.c_repr_chunks(indent=indent + INDENT_DELTA)
        yield indent_str, None
        yield "}\n", None


class CStatement(CConstruct):  # pylint:disable=abstract-method
    """
    Represents a statement in C.
    """

    __slots__ = ()


class CStatements(CStatement):
    """
    Represents a sequence of statements in C.
    """

    __slots__ = ('statements', )

    def __init__(self, statements):

        super(CStatements, self).__init__()

        self.statements = statements

    def c_repr_chunks(self, indent=0):

        for stmt in self.statements:
            yield from stmt.c_repr_chunks(indent=indent)


class CAILBlock(CStatement):
    """
    Represents a block of AIL statements.
    """

    __slots__ = ('block', )

    def __init__(self, block):

        super(CAILBlock, self).__init__()

        self.block = block

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)
        r = str(self.block)
        for stmt in r.split("\n"):
            yield indent_str
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

    __slots__ = ('condition', 'body', )

    def __init__(self, condition, body):

        super(CWhileLoop, self).__init__()

        self.condition = condition
        self.body = body

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "while(", None
        if self.condition is None:
            yield "true", None
        else:
            yield from self.condition.c_repr_chunks()
        yield ")\n", None
        yield indent_str, None
        yield "{\n", None
        yield from self.body.c_repr_chunks(indent=indent + INDENT_DELTA)
        yield indent_str, None
        yield "}\n", None


class CDoWhileLoop(CLoop):
    """
    Represents a do-while loop in C.
    """

    __slots__ = ('condition', 'body', )

    def __init__(self, condition, body):

        super().__init__()

        self.condition = condition
        self.body = body

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "do\n", None
        yield indent_str, None
        yield "{\n", None
        yield from self.body.c_repr_chunks(indent=indent + INDENT_DELTA)
        yield indent_str, None
        yield "} while(", None
        if self.condition is None:
            yield "true", None
        else:
            yield from self.condition.c_repr_chunks()
        yield ");\n", None


class CIfElse(CStatement):
    """
    Represents an if-else construct in C.
    """

    __slots__ = ('condition', 'true_node', 'false_node', )

    def __init__(self, condition, true_node=None, false_node=None):

        super(CIfElse, self).__init__()

        self.condition = condition
        self.true_node = true_node
        self.false_node = false_node

        if self.true_node is None and self.false_node is None:
            raise ValueError("'true_node' and 'false_node' cannot be both unspecified.")

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "if (", None
        yield from self.condition.c_repr_chunks()
        yield ")\n", None
        yield indent_str, None
        yield "{\n", None
        yield from self.true_node.c_repr_chunks(indent=indent + INDENT_DELTA)
        yield indent_str, None
        yield "}\n", None


        if self.false_node is not None:

            yield indent_str, None
            yield "else\n", None
            yield indent_str, None
            yield "{\n", None
            yield from self.false_node.c_repr_chunks(indent=indent + INDENT_DELTA)
            yield indent_str, None
            yield "}\n", None


class CIfBreak(CStatement):
    """
    Represents an if-break statement in C.
    """

    __slots__ = ('condition', )

    def __init__(self, condition):

        super(CIfBreak, self).__init__()

        self.condition = condition

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "if (", None
        yield from self.condition.c_repr_chunks()
        yield ")\n", None
        yield indent_str, None
        yield "{\n", None
        yield self.indent_str(indent=indent + INDENT_DELTA), None
        yield "break;\n", None
        yield indent_str, None
        yield "}\n", None


class CBreak(CStatement):
    """
    Represents a break statement in C.
    """

    __slots__ = ()

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "break;\n", None


class CContinue(CStatement):
    """
    Represents a continue statement in C.
    """

    __slots__ = ()

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "continue;\n", None


class CSwitchCase(CStatement):
    """
    Represents a switch-case statement in C.
    """

    __slots__ = ('switch', 'cases', 'default', )

    def __init__(self, switch, cases, default):
        super().__init__()

        self.switch = switch
        self.cases = cases
        self.default = default

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "switch (", None
        yield from self.switch.c_repr_chunks()
        yield ")\n", None
        yield indent_str, None
        yield "{\n", None

        # cases
        for idx, case in self.cases:
            yield indent_str, None
            yield "case {}:\n".format(idx), None
            yield from case.c_repr_chunks(indent=indent + INDENT_DELTA)

        if self.default is not None:
            yield indent_str, None
            yield "default:\n", None
            yield from self.default.c_repr_chunks(indent=indent + INDENT_DELTA)

        yield indent_str, None
        yield "}\n", None


class CAssignment(CStatement):
    """
    a = b
    """

    __slots__ = ('lhs', 'rhs', )

    def __init__(self, lhs, rhs):

        super(CAssignment, self).__init__()

        self.lhs = lhs
        self.rhs = rhs

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield from CExpression._try_c_repr_chunks(self.lhs)
        yield " = ", None
        yield from CExpression._try_c_repr_chunks(self.rhs)
        yield ";\n", None


class CFunctionCall(CStatement):
    """
    func(arg0, arg1)

    :ivar Function callee_func:  The function getting called.
    """

    __slots__ = ('callee_target', 'callee_func', 'args', 'returning', 'ret_expr', )

    def __init__(self, callee_target, callee_func, args, returning=True, ret_expr=None):
        super().__init__()

        self.callee_target = callee_target
        self.callee_func = callee_func
        self.args = args if args is not None else [ ]
        self.returning = returning
        self.ret_expr = ret_expr

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None

        if self.ret_expr is not None:
            yield from CExpression._try_c_repr_chunks(self.ret_expr)
            yield " = ", None

        if self.callee_func is not None:
            func_name = self.callee_func.demangled_name or self.callee_func.name
            yield func_name, self
        else:
            yield from CExpression._try_c_repr_chunks(self.callee_target)

        yield "(", None

        for i, arg in enumerate(self.args):
            if i:
                yield ", ", None
            yield from CExpression._try_c_repr_chunks(arg)

        yield ");", None

        if not self.returning:
            yield " /* do not return */", None

        yield "\n",  None


class CReturn(CStatement):

    __slots__ = ('retval', )

    def __init__(self, retval):
        super().__init__()

        self.retval = retval

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        if self.retval is None:
            yield indent_str, None
            yield "return;", None
        else:
            yield indent_str, None
            yield "return ", None
            yield from self.retval.c_repr_chunks()
            yield ";\n", None


class CGoto(CStatement):

    __slots__ = ('target', )

    def __init__(self, target):
        super().__init__()

        self.target = target

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield "goto ", None
        yield from self.target.c_repr_chunks()
        yield ";\n", None


class CUnsupportedStatement(CStatement):
    """
    A wrapper for unsupported AIL statement.
    """

    __slots__ = ('stmt', )

    def __init__(self, stmt):
        super().__init__()

        self.stmt = stmt

    def c_repr_chunks(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        yield indent_str, None
        yield str(self.stmt), None
        yield "\n", None


class CExpression:
    """
    Base class for C expressions.
    """

    __slots__ = ('_type', )

    def __init__(self):
        self._type = None

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
            yield str(expr), None


class CStructField(CExpression):

    __slots__ = ('struct_type', 'offset', 'field', )

    def __init__(self, struct_type, offset, field):

        super().__init__()

        self.struct_type = struct_type
        self.offset = offset
        self.field = field

    @property
    def type(self):
        return self.struct_type

    def c_repr_chunks(self):
        yield str(self.field), self


class CVariable(CExpression):
    """
    Read value from a variable.
    """

    __slots__ = ('variable', 'offset', 'variable_type', )

    def __init__(self, variable, offset=None, variable_type=None):

        super().__init__()

        self.variable = variable
        self.offset = offset
        self.variable_type = variable_type

    @property
    def type(self):
        return self.variable_type

    def _get_offset_string_chunks(self, in_hex=False):
        if type(self.offset) is int:
            if in_hex:
                yield "%#x" % self.offset, None
            else:
                yield "%d" % self.offset, None
        else:
            yield from self.offset.c_repr_chunks()

    def c_repr_chunks(self):
        if self.offset is None:
            if isinstance(self.variable, SimVariable):
                yield str(self.variable.name), self
            elif isinstance(self.variable, CExpression):
                if isinstance(self.variable, CVariable) and self.variable.type is not None:
                    if isinstance(self.variable.type, SimTypePointer):
                        if isinstance(self.variable.type.pts_to, SimStruct) and self.variable.type.pts_to.fields:
                            # is it pointing to a struct? if so, we take the first field
                            first_field, *_ = self.variable.type.pts_to.fields
                            c_field = CStructField(self.variable.type.pts_to, 0, first_field)
                            yield from self.variable.c_repr_chunks()
                            yield "->", None
                            yield from c_field.c_repr_chunks()
                            return
                        elif isinstance(self.variable.type.pts_to, SimTypeArray):
                            # is it pointing to an array? if so, we take the first element
                            yield from self.variable.c_repr_chunks()
                            yield "[", None
                            yield "0", 0
                            yield "]", None
                            return

                # default output
                yield "*(", None
                yield from self.variable.c_repr_chunks()
                yield ")", None
            else:
                yield str(self.variable), None
        else:  # self.offset is not None
            if isinstance(self.variable, SimVariable):
                yield self.variable.name, self
                yield "[", None
                yield from self._get_offset_string_chunks()
                yield "]", None

            elif isinstance(self.variable, CExpression):
                if isinstance(self.variable, CVariable) and self.variable.type is not None:
                    if isinstance(self.variable.type, SimTypePointer):
                        if isinstance(self.variable.type.pts_to, SimStruct):
                            if isinstance(self.offset, int):
                                # which field is it pointing to?
                                t = self.variable.type.pts_to
                                offset_to_field = dict((v, k) for k, v in t.offsets.items())
                                if self.offset in offset_to_field:
                                    field = offset_to_field[self.offset]
                                    c_field = CStructField(t, self.offset, field)
                                    yield from self.variable.c_repr_chunks()
                                    yield "->", None
                                    yield from c_field.c_repr_chunks()
                                    return

                        elif isinstance(self.variable.type.pts_to, SimTypeArray):
                            # it's pointing to an array!
                            yield from self.variable.c_repr_chunks()
                            yield "[", None
                            yield str(self.offset), self.offset
                            yield "]", None
                            return

                # default output
                yield "*(", None
                yield from self.variable.c_repr_chunks()
                yield ":", None
                yield from self._get_offset_string_chunks()
                yield ")", None

            elif isinstance(self.variable, Expr.Register):
                yield self.variable.reg_name if hasattr(self.variable, 'reg_name') else str(self.variable), self
                yield ":", None
                yield from self._get_offset_string_chunks(in_hex=True)

            else:
                yield "*(", None
                yield str(self.variable), self
                yield ":", None
                yield from self._get_offset_string_chunks()
                yield ")", None


class CUnaryOp(CExpression):
    """
    Unary operations.
    """

    __slots__ = ('op', 'operand', 'variable', )

    def __init__(self, op, operand, variable):

        super().__init__()

        self.op = op
        self.operand = operand
        self.variable = variable

    @property
    def type(self):
        if self._type is None:
            if self.variable is not None:
                self._type = self.variable.type
            if self.operand is not None and hasattr(self.operand, 'type'):  # FIXME: This is hackish
                self._type = self.operand.type
        return self._type

    def c_repr_chunks(self):
        if self.variable is not None:
            yield "&", None
            yield from self.variable.c_repr_chunks()
            return

        OP_MAP = {
            'Not': self._c_repr_chunks_not,
            'Reference': self._c_repr_chunks_reference,
        }

        handler = OP_MAP.get(self.op, None)
        if handler is not None:
            yield from handler()
        else:
            yield "UnaryOp %s" % (self.op), None

    #
    # Handlers
    #

    def _c_repr_chunks_not(self):
        yield "!(", None
        yield from CExpression._try_c_repr_chunks(self.operand)
        yield ")", None

    def _c_repr_chunks_reference(self):
        yield "&", None
        yield from CExpression._try_c_repr_chunks(self.operand)


class CBinaryOp(CExpression):
    """
    Binary operations.
    """

    __slots__ = ('op', 'lhs', 'rhs', 'variable', )

    def __init__(self, op, lhs, rhs, variable):

        super().__init__()

        self.op = op
        self.lhs = lhs
        self.rhs = rhs
        self.variable = variable

    @property
    def type(self):
        if self._type is None:
            return self.lhs.type
        return self._type

    def c_repr_chunks(self):

        if self.variable is not None:
            yield "&", None
            yield from self.variable.c_repr_chunks()
            return

        OP_MAP = {
            'Add': self._c_repr_chunks_add,
            'Sub': self._c_repr_chunks_sub,
            'Mul': self._c_repr_chunks_mul,
            'Div': self._c_repr_chunks_div,
            'And': self._c_repr_chunks_and,
            'Xor': self._c_repr_chunks_xor,
            'Or': self._c_repr_chunks_or,
            'Shr': self._c_repr_chunks_shr,
            'Shl': self._c_repr_chunks_shl,
            'Sar': self._c_repr_chunks_sar,
            'LogicalAnd': self._c_repr_chunks_logicaland,
            'LogicalOr': self._c_repr_chunks_logicalor,
            'CmpLE': self._c_repr_chunks_cmple,
            'CmpLT': self._c_repr_chunks_cmplt,
            'CmpGT': self._c_repr_chunks_cmpgt,
            'CmpGE': self._c_repr_chunks_cmpge,
            'CmpEQ': self._c_repr_chunks_cmpeq,
            'CmpNE': self._c_repr_chunks_cmpne,
        }

        handler = OP_MAP.get(self.op, None)
        if handler is not None:
            yield from handler()
        else:
            yield "BinaryOp %s" % (self.op), None

    #
    # Handlers
    #

    def _c_repr_chunks_add(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " + ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_sub(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " - ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_mul(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " * ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_div(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " / ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_and(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " & ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_xor(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " ^ ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_or(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " | ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_shr(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " >> ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_shl(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " << ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_sar(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " >> ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_logicaland(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " && ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_logicalor(self):
        yield "(", None
        yield from self._try_c_repr_chunks(self.lhs)
        yield ") || (", None
        yield from self._try_c_repr_chunks(self.rhs)
        yield ")", None

    def _c_repr_chunks_cmple(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " <= ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_cmplt(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " < ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_cmpgt(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " > ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_cmpge(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " >= ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_cmpeq(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " == ", None
        yield from self._try_c_repr_chunks(self.rhs)

    def _c_repr_chunks_cmpne(self):
        yield from self._try_c_repr_chunks(self.lhs)
        yield " != ", None
        yield from self._try_c_repr_chunks(self.rhs)


class CTypeCast(CExpression):

    __slots__ = ('src_type', 'dst_type', 'expr', )

    def __init__(self, src_type, dst_type, expr):

        super().__init__()

        self.src_type = src_type
        self.dst_type = dst_type
        self.expr = expr

    @property
    def type(self):
        if self._type is None:
            return self.dst_type
        return self._type

    def c_repr_chunks(self):
        yield "({})".format(self.dst_type), None
        yield from CExpression._try_c_repr_chunks(self.expr)


class CConstant(CExpression):

    __slots__ = ('value', 'reference_values', 'variable', )

    def __init__(self, value, type_, reference_values=None, variable=None):

        super().__init__()

        self.value = value
        self._type = type_
        self.reference_values = reference_values
        self.variable = variable

    @property
    def type(self):
        return self._type

    def c_repr_chunks(self):

        if self.variable is not None:
            yield from self.variable.c_repr_chunks()

        elif self.reference_values is not None and self._type is not None and self._type in self.reference_values:
            if isinstance(self._type, SimTypeInt):
                yield hex(self.reference_values[self._type]), self
            elif isinstance(self._type, SimTypePointer) and isinstance(self._type.pts_to, SimTypeChar):
                refval = self.reference_values[self._type]  # angr.knowledge_plugin.cfg.MemoryData
                yield '"' + repr(refval.content.decode('utf-8')).strip("'").strip('"') + '"', self
            else:
                yield self.reference_values[self.type], self

        elif isinstance(self.value, int) and self.value == 0 and isinstance(self.type, SimTypePointer):
            # print NULL instead
            yield "NULL", self

        elif isinstance(self._type, SimTypePointer) and isinstance(self.value, int):
            # Print pointers in hex
            yield hex(self.value), self

        else:
            yield str(self.value), self


class CRegister(CExpression):

    __slots__ = ('reg', )

    def __init__(self, reg):

        super().__init__()

        self.reg = reg

    @property
    def type(self):
        # FIXME
        return SimTypeInt()

    def c_repr_chunks(self):
        yield str(self.reg), None


class CITE(CExpression):

    __slots__ = ('cond', 'iftrue', 'iffalse', )

    def __init__(self, cond, iftrue, iffalse):
        super().__init__()
        self.cond = cond
        self.iftrue = iftrue
        self.iffalse = iffalse

    @property
    def type(self):
        return SimTypeInt()

    def c_repr_chunks(self):
        yield "(", None
        yield from self.cond.c_repr_chunks()
        yield "? ", None
        yield from self.iftrue.c_repr_chunks()
        yield " : ", None
        yield from self.iffalse.c_repr_chunks()
        yield ")", None


class CDirtyExpression(CExpression):
    """
    Ideally all dirty expressions should be handled and converted to proper conversions during conversion from VEX to
    AIL. Eventually this class should not be used at all.
    """

    __slots__ = ('dirty', )

    def __init__(self, dirty):
        super().__init__()
        self.dirty = dirty

    @property
    def type(self):
        return SimTypeInt()

    def c_repr_chunks(self):
        yield str(self.dirty), None


class StructuredCodeGenerator(Analysis):
    def __init__(self, func, sequence, indent=0, cfg=None, variable_kb=None,
                 func_args: Optional[List[SimVariable]]=None):

        self._handlers = {
            CodeNode: self._handle_Code,
            SequenceNode: self._handle_Sequence,
            LoopNode: self._handle_Loop,
            ConditionNode: self._handle_Condition,
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

        self._variables_in_use: Optional[Dict] = None

        self.text = None
        self.posmap = None
        self.nodemap = None
        self._indent = indent

        self._analyze()

    def _analyze(self):

        self._variables_in_use = {}
        if self._func_args:
            arg_list = [self._handle(arg) for arg in self._func_args]
        else:
            arg_list = [ ]
        obj = self._handle(self._sequence)

        func = CFunction(self._func.name, self._func.prototype, arg_list, obj, self._variables_in_use,
                         self._variable_kb.variables[self._func.addr], demangled_name=self._func.demangled_name)
        self._variables_in_use = None

        self.posmap = PositionMapping()
        self.text = func.c_repr(indent=self._indent, posmap=self.posmap)

        self.nodemap = defaultdict(set)
        for elem, node in self.posmap.items():
            if isinstance(node.obj, CConstant):
                self.nodemap[node.obj.value].add(elem)
            elif isinstance(node.obj, CVariable):
                self.nodemap[node.obj.variable].add(elem)
            elif isinstance(node.obj, CFunctionCall):
                if node.obj.callee_func is not None:
                    self.nodemap[node.obj.callee_func].add(elem)
                else:
                    self.nodemap[node.obj.callee_target].add(elem)
            elif isinstance(node.obj, CStructField):
                key = (node.obj.struct_type, node.obj.offset)
                self.nodemap[key].add(elem)
            else:
                self.nodemap[node.obj].add(elem)

    def _get_variable_type(self, var, is_global=False):
        if is_global:
            return self._variable_kb.variables['global'].get_variable_type(var)
        else:
            return self._variable_kb.variables[self._func.addr].get_variable_type(var)

    #
    # Util methods
    #

    def _parse_load_addr(self, addr):

        if isinstance(addr, CExpression):
            expr = addr
        else:
            expr = self._handle(addr)

        if isinstance(expr, CBinaryOp):
            if expr.op == "And" and isinstance(expr.rhs, CConstant) and is_alignment_mask(expr.rhs.value):
                # alignment - ignore it
                expr = expr.lhs
            if expr.op in ("Add", "Sub"):
                lhs, rhs = expr.lhs, expr.rhs
                if isinstance(lhs, CConstant):
                    lhs = lhs.value
                if isinstance(rhs, CConstant):
                    rhs = rhs.value
                if isinstance(lhs, int) and not isinstance(rhs, int):
                    # swap lhs and rhs
                    lhs, rhs = rhs, lhs
                if expr.op == "Sub":
                    return lhs, -rhs
                return lhs, rhs
        elif isinstance(expr, CTypeCast):
            return self._parse_load_addr(expr.expr)
        elif isinstance(expr, CConstant):
            return None, expr.value
        elif isinstance(expr, int):
            return None, expr
        elif isinstance(expr, Expr.DirtyExpression):
            l.warning("Got a DirtyExpression %s. It should be handled during VEX->AIL conversion.", expr)
            return expr, None
        elif isinstance(expr, CExpression):  # other expressions
            return expr, None

        l.warning("Unsupported address expression %r", addr)
        return expr, None

    def _cvariable(self, variable, offset=None, variable_type=None):
        cvariable = CVariable(variable, offset=offset, variable_type=variable_type)
        if isinstance(variable, SimVariable):
            self._variables_in_use[variable] = cvariable
        return cvariable

    #
    # Handlers
    #

    def _handle(self, node):
        handler = self._handlers.get(node.__class__, None)
        if handler is not None:
            return handler(node)
        raise UnsupportedNodeTypeError("Node type %s is not supported yet." % type(node))

    def _handle_Code(self, node):

        return self._handle(node.node)

    def _handle_Sequence(self, seq):

        lines = [ ]

        for node in seq.nodes:
            lines.append(self._handle(node))

        if not lines:
            return CStatements([])

        return CStatements(lines) if len(lines) > 1 else lines[0]

    def _handle_Loop(self, loop_node):

        if loop_node.sort == 'while':
            return CWhileLoop(None if loop_node.condition is None else self._handle(loop_node.condition),
                              self._handle(loop_node.sequence_node)
                              )
        elif loop_node.sort == 'do-while':
            return CDoWhileLoop(self._handle(loop_node.condition),
                                self._handle(loop_node.sequence_node)
                                )

        else:
            raise NotImplementedError()

    def _handle_Condition(self, condition_node):

        code = CIfElse(self._handle(condition_node.condition),
                       true_node=self._handle(condition_node.true_node) if condition_node.true_node else None,
                       false_node=self._handle(condition_node.false_node) if condition_node.false_node else None,
                       )
        return code

    def _handle_ConditionalBreak(self, node):  # pylint:disable=no-self-use

        return CIfBreak(self._handle(node.condition))

    def _handle_Break(self, node):  # pylint:disable=no-self-use,unused-argument

        return CBreak()

    def _handle_MultiNode(self, node):  # pylint:disable=no-self-use

        lines = [ ]

        for n in node.nodes:
            r = self._handle(n)
            lines.append(r)

        return CStatements(lines) if len(lines) > 1 else lines[0]

    def _handle_SwitchCase(self, node):
        """

        :param SwitchCaseNode node:
        :return:
        """

        switch_expr = self._handle(node.switch_expr)
        cases = [ (idx, self._handle(case)) for idx, case in node.cases.items() ]
        default = self._handle(node.default_node) if node.default_node is not None else None
        switch_case = CSwitchCase(switch_expr, cases, default=default)
        return switch_case

    def _handle_Continue(self, node):  # pylint:disable=no-self-use,unused-argument

        return CContinue()

    def _handle_AILBlock(self, node):
        """

        :param Block node:
        :return:
        """

        # return CStatements([ CAILBlock(node) ])
        cstmts = [ ]
        for stmt in node.statements:
            try:
                cstmt = self._handle(stmt)
            except UnsupportedNodeTypeError:
                l.warning("Unsupported AIL statement or expression %s.", type(stmt), exc_info=True)
                cstmt = CUnsupportedStatement(stmt)
            cstmts.append(cstmt)

        return CStatements(cstmts)

    #
    # AIL statement handlers
    #

    def _handle_Stmt_Store(self, stmt: Stmt.Store):

        if stmt.variable is not None:
            # storing to a variable directly
            cvariable = self._handle(stmt.variable)
        elif stmt.addr is not None:
            # storing to an address specified by a variable
            cvariable = self._handle(stmt.addr)
            # special handling
            base, offset = None, None
            if isinstance(cvariable, CBinaryOp) and cvariable.op == 'Add':
                if isinstance(cvariable.lhs, CConstant) and isinstance(cvariable.rhs, CVariable):
                    offset = cvariable.lhs.value
                    base = cvariable.rhs
                elif isinstance(cvariable.rhs, CConstant) and isinstance(cvariable.lhs, CVariable):
                    offset = cvariable.rhs.value
                    base = cvariable.lhs
                else:
                    base = None
                    offset = None

            if base is not None and offset is not None:
                cvariable = self._cvariable(base, offset=offset, variable_type=base.variable_type)
            else:
                cvariable = self._cvariable(cvariable, offset=None)
        else:
            l.warning("Store statement %s has no variable linked with it.", stmt)
            cvariable = None

        cdata = self._handle(stmt.data)

        return CAssignment(cvariable, cdata)

    def _handle_Stmt_Assignment(self, stmt):

        cdst = self._handle(stmt.dst)
        csrc = self._handle(stmt.src)

        return CAssignment(cdst, csrc)

    def _handle_Stmt_Call(self, stmt):

        try:
            # Try to handle it as a normal function call
            target = self._handle(stmt.target)
        except UnsupportedNodeTypeError:
            target = stmt.target

        if isinstance(target, CConstant):
            target_func = self.kb.functions.function(addr=target.value)
        else:
            target_func = None

        args = [ ]
        if target_func is not None and stmt.args is not None:
            for i, arg in enumerate(stmt.args):
                if target_func.prototype is not None and i < len(target_func.prototype.args):
                    type_ = target_func.prototype.args[i].with_arch(self.project.arch)
                else:
                    type_ = None

                reference_values = { }
                if isinstance(arg, Expr.Const):
                    if isinstance(type_, SimTypePointer) and isinstance(type_.pts_to, SimTypeChar):
                        # char*
                        # Try to get a string
                        if self._cfg is not None:
                            if arg.value in self._cfg.memory_data and self._cfg.memory_data[arg.value].sort == 'string':
                                reference_values[type_] = self._cfg.memory_data[arg.value]
                    elif isinstance(type_, SimTypeInt):
                        # int
                        reference_values[type_] = arg.value
                    elif type_ is None:
                        # we don't know the type of this argument
                        # pure guessing: is it possible that it's a string?
                        if self._cfg is not None and \
                                arg.bits == self.project.arch.bits and \
                                arg.value > 0x10000 and \
                                arg.value in self._cfg.memory_data and \
                                self._cfg.memory_data[arg.value].sort == 'string':
                            type_ = SimTypePointer(SimTypeChar()).with_arch(self.project.arch)
                            reference_values[type_] = self._cfg.memory_data[arg.value]
                    new_arg = CConstant(arg, type_, reference_values=reference_values if reference_values else None,
                                        variable=self._handle(arg.variable) if arg.variable is not None else None)
                else:
                    new_arg = self._handle(arg)
                args.append(new_arg)

        ret_expr = None
        if stmt.ret_expr is not None:
            ret_expr = self._handle(stmt.ret_expr)

        return CFunctionCall(target, target_func, args,
                             returning=target_func.returning if target_func is not None else True,
                             ret_expr=ret_expr,
                             )

    def _handle_Stmt_Jump(self, stmt):
        return CGoto(self._handle(stmt.target))

    #
    # AIL expression handlers
    #

    def _handle_Expr_Register(self, expr):  # pylint:disable=no-self-use

        if expr.variable:
            return self._handle(expr.variable)
        else:
            return CRegister(expr)

    def _handle_Expr_Load(self, expr):

        if expr.variable is not None:
            if expr.variable_offset is not None:
                if isinstance(expr.variable_offset, int):
                    offset = expr.variable_offset
                else:
                    offset = self._handle(expr.variable_offset)
            else:
                offset = None
            return self._cvariable(expr.variable, offset=offset,
                                   variable_type=self._get_variable_type(expr.variable),
                                   )

        variable, offset = self._parse_load_addr(expr.addr)

        if variable is not None:
            return self._cvariable(variable, offset=offset,
                                   variable_type=self._get_variable_type(variable))
        else:
            return self._cvariable(CConstant(offset, SimTypePointer(SimTypeInt)))

    def _handle_Expr_Tmp(self, expr):  # pylint:disable=no-self-use

        l.warning("FIXME: Leftover Tmp expressions are found.")
        return self._cvariable(SimTemporaryVariable(expr.tmp_idx))

    def _handle_Expr_Const(self, expr):  # pylint:disable=no-self-use

        return CConstant(expr.value, int, variable=self._handle(expr.variable) if expr.variable is not None else None)

    def _handle_Expr_UnaryOp(self, expr):

        return CUnaryOp(expr.op, self._handle(expr.operand),
                        variable=self._handle(expr.variable) if expr.variable is not None else None,
                        )

    def _handle_Expr_BinaryOp(self, expr):

        lhs = self._handle(expr.operands[0])
        rhs = self._handle(expr.operands[1])
        rhs.set_type(lhs.type)

        return CBinaryOp(expr.op, lhs, rhs,
                         variable=self._handle(expr.variable) if expr.variable is not None else None,
                         )

    def _handle_Expr_Convert(self, expr):

        if expr.to_bits == 64:
            dst_type = SimTypeLongLong()
        elif expr.to_bits == 32:
            dst_type = SimTypeInt()
        elif expr.to_bits == 16:
            dst_type = SimTypeShort()
        elif expr.to_bits == 8:
            dst_type = SimTypeChar()
        elif expr.to_bits == 1:
            dst_type = SimTypeChar()  # FIXME: Add a SimTypeBit?
        else:
            raise UnsupportedNodeTypeError("Unsupported conversion bits %s." % expr.to_bits)

        return CTypeCast(None, dst_type, self._handle(expr.operand))

    def _handle_Expr_Dirty(self, expr):  # pylint:disable=no-self-use
        return CDirtyExpression(expr)

    def _handle_Expr_ITE(self, expr: Expr.ITE):
        return CITE(self._handle(expr.cond), self._handle(expr.iftrue), self._handle(expr.iffalse))

    def _handle_Expr_StackBaseOffset(self, expr):  # pylint:disable=no-self-use

        if expr.variable is not None:
            return CUnaryOp('Reference', expr, variable=self._handle(expr.variable))

        # FIXME
        r = CUnaryOp('Reference', expr, variable=None)
        r.set_type(SimTypeLongLong())
        return r

    def _handle_Variable_SimStackVariable(self, variable):  # pylint:disable=no-self-use
        return self._cvariable(variable, variable_type=self._get_variable_type(variable))

    def _handle_Variable_SimRegisterVariable(self, variable):  # pylint:disable=no-self-use
        return self._cvariable(variable, variable_type=self._get_variable_type(variable))

    def _handle_Variable_SimMemoryVariable(self, variable):  # pylint:disable=no-self-use
        return self._cvariable(variable, variable_type=self._get_variable_type(variable, is_global=True))


register_analysis(StructuredCodeGenerator, 'StructuredCodeGenerator')
