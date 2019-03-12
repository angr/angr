
from collections import defaultdict
import logging

from sortedcontainers import SortedDict

from ailment import Block, Expr, Stmt

from ...sim_type import SimTypeLongLong, SimTypeInt, SimTypeShort, SimTypeChar, SimTypePointer
from ...sim_variable import SimVariable, SimTemporaryVariable, SimStackVariable, SimRegisterVariable
from ...utils.constants import is_alignment_mask
from .. import Analysis, register_analysis
from .region_identifier import MultiNode
from .structurer import SequenceNode, CodeNode, ConditionNode, ConditionalBreakNode, LoopNode


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

    __slots__ = ('_pos', '_posmap')

    DUPLICATION_CHECK = True

    def __init__(self):
        self._pos = 0
        self._posmap = SortedDict()

    def items(self):
        return self._posmap.items()

    #
    # Properties
    #

    @property
    def pos(self):
        return self._pos

    @pos.setter
    def pos(self, v):
        self._pos = v

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

    def tick_pos(self, delta):
        self._pos += delta

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


class UnsupportedNodeTypeError(NotImplementedError):
    pass


class CConstruct:
    """
    Represents a program construct in C.
    """

    def __init__(self):
        pass

    def c_repr(self, indent=0, posmap=None):
        raise NotImplementedError()


class CFunction(CConstruct):  # pylint:disable=abstract-method
    """
    Represents a function in C.
    """
    def __init__(self, name, statements):

        super(CFunction, self).__init__()

        self.name = name
        self.statements = statements

    def c_repr(self, indent=0, posmap=None):
        func_header = "void %s()" % self.name
        s0 = "\n{\n"
        if posmap:
            posmap.tick_pos(len(func_header + s0))
        func_body = self.statements.c_repr(indent=indent + INDENT_DELTA, posmap=posmap)

        return func_header + s0 + func_body + "\n}\n"


class CStatement(CConstruct):  # pylint:disable=abstract-method
    """
    Represents a statement in C.
    """
    @staticmethod
    def indent_str(indent=0):
        return " " * indent


class CStatements(CStatement):
    """
    Represents a sequence of statements in C.
    """
    def __init__(self, statements):

        super(CStatements, self).__init__()

        self.statements = statements

    def c_repr(self, indent=0, posmap=None):
        stmt_strings = [ ]
        for stmt in self.statements:
            if posmap:
                old_pos = posmap.pos
            stmt_str = stmt.c_repr(indent=indent, posmap=posmap)
            if not stmt_str:
                continue
            if posmap:
                posmap.pos = old_pos + len(stmt_str) + 1  # account for the newline
            stmt_strings.append(stmt_str)

        return "\n".join(stmt_strings)


class CAILBlock(CStatement):
    """
    Represents a block of AIL statements.
    """
    def __init__(self, block):

        super(CAILBlock, self).__init__()

        self.block = block

    def c_repr(self, indent=0, posmap=None):

        lines = [ ]

        r = str(self.block)

        indent_str = self.indent_str(indent=indent)
        for line in r.split("\n"):
            lines.append(indent_str + line)

        return "\n".join(lines)


class CLoop(CStatement):  # pylint:disable=abstract-method
    """
    Represents a loop in C.
    """


class CWhileLoop(CLoop):
    """
    Represents a while loop in C.
    """
    def __init__(self, condition, body):

        super(CWhileLoop, self).__init__()

        self.condition = condition
        self.body = body

    def c_repr(self, indent=0, posmap=None):

        indent_str = self.indent_str(indent=indent)

        lines = [ ]

        if self.condition is None:
            # while(true)
            line = indent_str + 'while (true)'
            if posmap: posmap.tick_pos(len(line) + 1)
            lines.append(line)

            line = indent_str + '{'
            if posmap: posmap.tick_pos(len(line) + 1)
            lines.append(line)

            if posmap: old_pos = posmap.pos
            line = self.body.c_repr(indent=indent + INDENT_DELTA, posmap=posmap)
            if posmap: posmap.pos = old_pos + len(line) + 1
            lines.append(line)

            line = indent_str + '}'
            if posmap: posmap.tick_pos(len(line) + 1)
            lines.append(line)
        else:
            # while(cond)
            line = indent_str + 'while ('
            if posmap: posmap.tick_pos(len(line))
            line_ = '%s)' % self.condition.c_repr(posmap=posmap)
            if posmap: posmap.tick_pos(2)
            line += line_
            lines.append(line)

            line = indent_str + '{'
            if posmap: posmap.tick_pos(len(line) + 1)
            lines.append(line)

            line = self.body.c_repr(indent=indent + INDENT_DELTA, posmap=posmap)
            if posmap: posmap.tick_pos(1)
            lines.append(line)

            line = indent_str + '}'
            if posmap: posmap.tick_pos(len(line) + 1)
            lines.append(line)

        return "\n".join(lines)


class CDoWhileLoop(CLoop):
    """
    Represents a do-while loop in C.
    """
    def __init__(self, condition, body):

        super().__init__()

        self.condition = condition
        self.body = body

    def c_repr(self, indent=0, posmap=None):

        indent_str = self.indent_str(indent=indent)

        lines = [ ]

        if self.condition is None:
            # do-while true
            lines.append(indent_str + 'do')
            lines.append(indent_str + '{')
            lines.append(self.body.c_repr(indent=indent + INDENT_DELTA, posmap=posmap))
            lines.append(indent_str + '} while(true);')
        else:
            # do-while(cond)
            lines.append(indent_str + 'do')
            lines.append(indent_str + '{')
            lines.append(self.body.c_repr(indent=indent + INDENT_DELTA, posmap=posmap))
            lines.append(indent_str + '} while(%s);' % (self.condition.c_repr(posmap=posmap)))

        return "\n".join(lines)


class CIfElse(CStatement):
    """
    Represents an if-else construct in C.
    """
    def __init__(self, condition, true_node=None, false_node=None):

        super(CIfElse, self).__init__()

        self.condition = condition
        self.true_node = true_node
        self.false_node = false_node

        if self.true_node is None and self.false_node is None:
            raise ValueError("'true_node' and 'false_node' cannot be both unspecified.")

    def c_repr(self, indent=0, posmap=None):

        indent_str = self.indent_str(indent=indent)

        line_0 = indent_str + "if ("
        if posmap:
            old_pos = posmap.pos
            posmap.tick_pos(len(line_0))
        line_0 += self.condition.c_repr(posmap=posmap) + ")"
        if posmap: posmap.pos = old_pos + len(line_0) + 1
        line_1 = indent_str + "{"
        if posmap: posmap.tick_pos(len(line_1) + 1)
        lines = [ line_0, line_1 ]

        lines.append(self.true_node.c_repr(indent=indent + INDENT_DELTA, posmap=posmap))

        line_2 = indent_str + "}"
        if posmap: posmap.tick_pos(len(line_2) + 1)
        lines.append(line_2)

        if self.false_node is not None:
            line_3 = indent_str + 'else'
            line_4 = indent_str + '{'
            lines.append(line_3)
            lines.append(line_4)
            posmap.tick_pos(len(line_3) + 1 + len(line_4) + 1)
            lines.append(self.false_node.c_repr(indent=indent + INDENT_DELTA, posmap=posmap))
            posmap.tick_pos(1)
            lines.append(indent_str + "}")

        return "\n".join(lines)


class CIfBreak(CStatement):
    """
    Represents an if-break statement in C.
    """
    def __init__(self, condition):

        super(CIfBreak, self).__init__()

        self.condition = condition

    def c_repr(self, indent=0, posmap=None):

        indent_str = self.indent_str(indent=indent)

        lines = [
            indent_str + "if (%s)" % self.condition.c_repr(posmap=posmap),
            indent_str + "{",
            indent_str + self.indent_str(indent=INDENT_DELTA) + "break;",
            indent_str + "}",
        ]

        return "\n".join(lines)


class CAssignment(CStatement):
    """
    a = b
    """
    def __init__(self, lhs, rhs):

        super(CAssignment, self).__init__()

        self.lhs = lhs
        self.rhs = rhs

    def c_repr(self, indent=0, posmap=None):

        indent_str = self.indent_str(indent=indent)
        if posmap:
            old_pos = posmap.pos
            posmap.tick_pos(len(indent_str))

        if isinstance(self.lhs, CExpression):
            lhs_str = self.lhs.c_repr(posmap=posmap)
        else:
            lhs_str = str(self.lhs)
            if posmap: posmap.tick_pos(len(lhs_str))

        s_equal = " = "
        if posmap:
            posmap.tick_pos(len(s_equal))

        if isinstance(self.rhs, CExpression):
            rhs_str = self.rhs.c_repr(posmap=posmap)
        else:
            rhs_str = str(self.rhs)
            if posmap: posmap.tick_pos(len(rhs_str))

        s = indent_str + lhs_str + s_equal + rhs_str + ";"
        if posmap: posmap.pos = old_pos + len(s)
        return s


class CFunctionCall(CStatement):
    """
    func(arg0, arg1)

    :ivar Function callee_func:  The function getting called.
    """
    def __init__(self, callee_target, callee_func, args, returning=True, ret_expr=None):
        super().__init__()

        self.callee_target = callee_target
        self.callee_func = callee_func
        self.args = args if args is not None else [ ]
        self.returning = returning
        self.ret_expr = ret_expr

    def c_repr(self, indent=0, posmap=None):

        indent_str = self.indent_str(indent=indent)
        if posmap: posmap.tick_pos(len(indent_str))

        ret_expr_str = ""
        if self.ret_expr is not None:
            if isinstance(self.ret_expr, CExpression):
                ret_expr_str = self.ret_expr.c_repr(posmap=posmap)
            else:
                ret_expr_str = str(self.ret_expr)
                if posmap: posmap.tick_pos(len(ret_expr_str))
            ret_expr_str += " = "
            if posmap: posmap.tick_pos(3)

        if self.callee_func is not None:
            func_name = self.callee_func.name
        else:
            func_name = str(self.callee_target)
        s_func = func_name + "("
        if posmap:
            posmap.add_mapping(posmap.pos, len(func_name), self)
            posmap.tick_pos(len(s_func))

        args_list = [ ]
        for arg in self.args:
            if isinstance(arg, CExpression):
                arg_str = arg.c_repr(posmap=posmap)
                if posmap: posmap.tick_pos(len(", "))
            else:
                arg_str = str(arg)
                if posmap: posmap.tick_pos(len(arg_str) + len(", "))
            args_list.append(arg_str)
        args_str = ", ".join(args_list)

        return indent_str + ret_expr_str +  s_func + "%s);%s" % (
            args_str,
            " /* do not return */" if not self.returning else ""
        )


class CReturn(CStatement):
    def __init__(self, retval):
        super().__init__()

        self.retval = retval

    def c_repr(self, indent=0, posmap=None):

        indent_str = self.indent_str(indent=indent)

        if self.retval is None:
            return indent_str + "return;"
        else:
            return indent_str + "return %s;" % (self.retval.c_repr(posmap=posmap))


class CUnsupportedStatement(CStatement):
    """
    A wrapper for unsupported AIL statement.
    """
    def __init__(self, stmt):
        super().__init__()

        self.stmt = stmt

    def c_repr(self, indent=0, posmap=None):

        indent_str = self.indent_str(indent=indent)

        return indent_str + str(self.stmt)


class CExpression:
    """
    Base class for C expressions.
    """
    def c_repr(self, posmap=None):
        raise NotImplementedError()

    @staticmethod
    def _try_c_repr(expr, posmap=None):
        if hasattr(expr, 'c_repr'):
            return expr.c_repr(posmap=posmap)
        else:
            s = str(expr)
            if posmap: posmap.tick_pos(len(s))
            return s


class CVariable(CExpression):
    """
    Read value from a variable.
    """
    def __init__(self, variable, offset=None):
        self.variable = variable
        self.offset = offset

    def _get_offset_string(self, in_hex=False, posmap=None):
        if type(self.offset) is int:
            if in_hex:
                return "%#x" % self.offset
            return "%d" % self.offset
        else:
            return self.offset.c_repr(posmap=posmap)

    def c_repr(self, posmap=None):
        if self.offset is None:
            if isinstance(self.variable, SimVariable):
                s = str(self.variable.name)
                if posmap:
                    posmap.add_mapping(posmap.pos, len(s), self)
                    posmap.tick_pos(len(s))
                return s
            elif isinstance(self.variable, CExpression):
                s0 = "*("
                if posmap: posmap.tick_pos(len(s0))
                s = self.variable.c_repr(posmap=posmap)
                s1 = ")"
                if posmap: posmap.tick_pos(len(s1))
                return s0 + s + s1
            else:
                s = str(self.variable)
                if posmap: posmap.tick_pos(len(s))
                return s
        else:
            if isinstance(self.variable, SimVariable):
                s_v = self.variable.name
                if posmap: posmap.add_mapping(posmap.pos, len(s_v), self)
                s1 = "["
                if posmap: posmap.tick_pos(len(s_v) + len(s1))
                s2 = self._get_offset_string(posmap=posmap)
                s3 = "]"
                if posmap: posmap.tick_pos(len(s2))
                return s_v + s1 + s2 + s3
            elif isinstance(self.variable, CExpression):
                if self.offset:
                    s0 = "*("
                    if posmap: posmap.tick_pos(len(s0))
                    s_v = self.variable.c_repr(posmap=posmap)
                    s1 = ":"
                    if posmap: posmap.tick_pos(len(s1))
                    s2 = self._get_offset_string(posmap=posmap)
                    s3 = ")"
                    if posmap: posmap.tick_pos(len(s3))
                    return s0 + s_v + s1 + s2 + s3
                else:
                    s0 = "*("
                    if posmap: posmap.tick_pos(len(s0))
                    s = self.variable.c_repr(posmap=posmap)
                    s1 = ")"
                    if posmap: posmap.tick_pos(len(s1))
                    return s0 + s + s1
            elif isinstance(self.variable, Expr.Register):
                s0 = self.variable.reg_name if hasattr(self.variable, 'reg_name') else str(self.variable)
                if posmap:
                    posmap.add_mapping(posmap.pos, len(s0), self)
                    posmap.tick_pos(len(s0))
                s1 = ":"
                if posmap: posmap.tick_pos(len(s1))
                s2 = self._get_offset_string(in_hex=True, posmap=posmap)
                return s0 + s1 + s2
            else:
                s0 = "*("
                if posmap: posmap.tick_pos(len(s0))
                s = str(self.variable)
                if posmap:
                    posmap.add_mapping(posmap.pos, len(s), self)
                    posmap.tick_pos(len(s))
                s1 = ":"
                if posmap: posmap.tick_pos(len(s1))
                s2 = self._get_offset_string(posmap=posmap)
                s3 = ")"
                if posmap: posmap.tick_pos(len(s3))
                return s0 + s + s1 + s2 + s3


class CUnaryOp(CExpression):
    """
    Unary operations.
    """
    def __init__(self, op, operand, referenced_variable):

        self.op = op
        self.operand = operand
        self.referenced_variable = referenced_variable

    def c_repr(self, posmap=None):
        if self.referenced_variable is not None:
            if posmap:
                posmap.tick_pos(1)
            s = self.referenced_variable.c_repr(posmap=posmap)
            return "&" + s

        OP_MAP = {
            'Not': self._c_repr_not,
        }

        handler = OP_MAP.get(self.op, None)
        if handler is not None:
            return handler(posmap=posmap)
        return "UnaryOp %s" % (self.op)

    #
    # Handlers
    #

    def _c_repr_not(self, posmap=None):
        if posmap: posmap.tick_pos(2)
        s = "!(%s)" % (self.operand.c_repr(posmap=posmap))
        if posmap: posmap.tick_pos(1)
        return s


class CBinaryOp(CExpression):
    """
    Binary operations.
    """
    def __init__(self, op, lhs, rhs, referenced_variable):

        self.op = op
        self.lhs = lhs
        self.rhs = rhs
        self.referenced_variable = referenced_variable

    def c_repr(self, posmap=None):

        if self.referenced_variable is not None:
            if posmap:
                posmap.tick_pos(1)
            return "&%s" % self.referenced_variable.c_repr(posmap=posmap)

        OP_MAP = {
            'Add': self._c_repr_add,
            'Sub': self._c_repr_sub,
            'And': self._c_repr_and,
            'Xor': self._c_repr_xor,
            'Shr': self._c_repr_shr,
            'LogicalAnd': self._c_repr_logicaland,
            'LogicalOr': self._c_repr_logicalor,
            'CmpLE': self._c_repr_cmple,
            'CmpULE': self._c_repr_cmple,  # FIXME: use the unsigned version
            'CmpLT': self._c_repr_cmplt,
            'CmpGT': self._c_repr_cmpgt,
            'CmpUGT': self._c_repr_cmpgt,  # FIXME: use the unsigned version
            'CmpEQ': self._c_repr_cmpeq,
            'CmpNE': self._c_repr_cmpne,
        }

        handler = OP_MAP.get(self.op, None)
        if handler is not None:
            return handler(posmap=posmap)
        return "BinaryOp %s" % (self.op)

    #
    # Handlers
    #

    def _c_repr_add(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " + "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs

    def _c_repr_sub(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " - "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs

    def _c_repr_and(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " & "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs

    def _c_repr_xor(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " ^ "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs

    def _c_repr_shr(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " >> "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs

    def _c_repr_logicaland(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " && "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs

    def _c_repr_logicalor(self, posmap=None):
        if posmap: posmap.tick_pos(1)
        lhs = "(" + self._try_c_repr(self.lhs, posmap=posmap)
        op = ") || ("
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs + ")"

    def _c_repr_cmple(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " <= "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs

    def _c_repr_cmplt(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " < "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs

    def _c_repr_cmpgt(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " > "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs

    def _c_repr_cmpeq(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " == "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs

    def _c_repr_cmpne(self, posmap=None):
        lhs = self._try_c_repr(self.lhs, posmap=posmap)
        op = " != "
        if posmap: posmap.tick_pos(len(op))
        rhs = self._try_c_repr(self.rhs, posmap=posmap)
        return lhs + op + rhs


class CTypeCast(CExpression):
    def __init__(self, src_type, dst_type, expr):
        self.src_type = src_type
        self.dst_type = dst_type
        self.expr = expr

    def c_repr(self, posmap=None):
        s_pre = "(%s)" % (self.dst_type)
        if posmap: posmap.tick_pos(len(s_pre))
        if not isinstance(self.expr, CExpression):
            expr_str = str(self.expr)
            if posmap: posmap.tick_pos(len(expr_str))
        else:
            expr_str = self.expr.c_repr(posmap=posmap)
        return s_pre + expr_str


class CConstant(CExpression):
    def __init__(self, value, type_, reference_values=None):
        self.value = value
        self.type = type_
        self.reference_values = reference_values

    def c_repr(self, posmap=None):
        s = None
        if self.reference_values is not None and self.type is not None:
            if self.type in self.reference_values:
                if isinstance(self.type, SimTypeInt):
                    s = hex(self.reference_values[self.type])
                elif isinstance(self.type, SimTypePointer) and isinstance(self.type.pts_to, SimTypeChar):
                    refval = self.reference_values[self.type]  # angr.analyses.cfg.MemoryData
                    s = '"' + repr(refval.content.decode('utf-8')).strip("'").strip('"') + '"'
                else:
                    s = self.reference_values[self.type]

        if s is None:
            # Print pointers in hex
            if isinstance(self.type, SimTypePointer) and isinstance(self.value, int):
                s = hex(self.value)

        if s is None:
            s = str(self.value)

        if posmap:
            posmap.add_mapping(posmap.pos, len(s), self)
            posmap.tick_pos(len(s))
        return s


class CRegister(CExpression):
    def __init__(self, reg):
        self.reg = reg

    def c_repr(self, posmap=None):
        s = str(self.reg)
        if posmap: posmap.tick_pos(len(s))
        return s


class StructuredCodeGenerator(Analysis):
    def __init__(self, func, sequence, indent=0, cfg=None):
        self._func = func
        self._sequence = sequence
        self._cfg = cfg

        self.text = None
        self.posmap = None
        self.nodemap = None
        self._indent = indent

        self._handlers = {
            SequenceNode: self._handle_Sequence,
            CodeNode: self._handle_Code,
            LoopNode: self._handle_Loop,
            ConditionNode: self._handle_Condition,
            ConditionalBreakNode: self._handle_ConditionalBreak,
            MultiNode: self._handle_MultiNode,
            Block: self._handle_AILBlock,
            # AIL statements
            Stmt.Store: self._handle_Stmt_Store,
            Stmt.Assignment: self._handle_Stmt_Assignment,
            Stmt.Call: self._handle_Stmt_Call,
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
            # SimVariables
            SimStackVariable: self._handle_Variable_SimStackVariable,
            SimRegisterVariable: self._handle_Variable_SimRegisterVariable,
        }

        self._analyze()

    def _analyze(self):

        obj = self._handle(self._sequence)
        func = CFunction(self._func.name, obj)

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
            else:
                self.nodemap[node.obj].add(elem)

    def _function_header_repr(self):
        """
        Generate text for function header.

        :return:    Text for the function header.
        :rtype:     str
        """

        return "void %s()" % (self._func.name)

    #
    # Util methods
    #

    def _parse_load_addr(self, addr):
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

        raise NotImplementedError("Unsupported address %s." % addr)

    #
    # Handlers
    #

    def _handle(self, node):

        handler = self._handlers.get(node.__class__, None)
        if handler is not None:
            return handler(node)
        raise UnsupportedNodeTypeError("Node type %s is not supported yet." % type(node))

    def _handle_Code(self, code):

        return self._handle(code.node)

    def _handle_Sequence(self, seq):

        lines = [ ]

        for node in seq.nodes:
            lines.append(self._handle(node))

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

    def _handle_MultiNode(self, node):  # pylint:disable=no-self-use

        lines = [ ]

        for n in node.nodes:
            r = self._handle(n)
            lines.append(r)

        return CStatements(lines) if len(lines) > 1 else lines[0]

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

    def _handle_Stmt_Store(self, stmt):

        if stmt.variable is None:
            l.warning("Store statement %s has no variable linked with it.", stmt)
            cvariable = None
        else:
            cvariable = self._handle(stmt.variable)
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
        if target_func is not None and target_func.prototype is not None and stmt.args is not None:
            for i, arg in enumerate(stmt.args):
                if i < len(target_func.prototype.args):
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
                    new_arg = CConstant(arg, type_, reference_values if reference_values else None)
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

    #
    # AIL expression handlers
    #

    def _handle_Expr_Register(self, expr):  # pylint:disable=no-self-use

        if expr.variable:
            return self._handle(expr.variable)
        else:
            return CRegister(expr)

    def _handle_Expr_Load(self, expr):

        if hasattr(expr, 'variable') and expr.variable is not None:
            if expr.offset is not None:
                offset = self._handle(expr.offset)
            else:
                offset = None
            return CVariable(expr.variable, offset=offset)

        variable, offset = self._parse_load_addr(expr.addr)

        if variable is not None:
            return CVariable(variable, offset=offset)
        else:
            return CVariable(CConstant(offset, SimTypePointer(SimTypeInt)))

    def _handle_Expr_Tmp(self, expr):  # pylint:disable=no-self-use

        l.warning("FIXME: Leftover Tmp expressions are found.")
        return CVariable(SimTemporaryVariable(expr.tmp_idx))

    def _handle_Expr_Const(self, expr):  # pylint:disable=no-self-use

        return CConstant(expr.value, int)

    def _handle_Expr_UnaryOp(self, expr):

        return CUnaryOp(expr.op, self._handle(expr.operand),
                        referenced_variable=self._handle(expr.referenced_variable) if hasattr(expr, 'referenced_variable') else None
                        )

    def _handle_Expr_BinaryOp(self, expr):

        return CBinaryOp(expr.op, self._handle(expr.operands[0]), self._handle(expr.operands[1]),
                         referenced_variable=self._handle(expr.referenced_variable) if hasattr(expr, 'referenced_variable') else None
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
        return expr

    def _handle_Expr_StackBaseOffset(self, expr):  # pylint:disable=no-self-use

        if hasattr(expr, 'referenced_variable') and expr.referenced_variable is not None:
            return CUnaryOp('Reference', expr, referenced_variable=self._handle(expr.referenced_variable))

        return expr

    def _handle_Variable_SimStackVariable(self, variable):  # pylint:disable=no-self-use

        return CVariable(variable)

    def _handle_Variable_SimRegisterVariable(self, variable):  # pylint:disable=no-self-use

        return CVariable(variable)


register_analysis(StructuredCodeGenerator, 'StructuredCodeGenerator')
