
import logging

from ailment import Block, Expr, Stmt

from ...sim_type import SimTypeLongLong, SimTypeInt, SimTypeShort, SimTypeChar, SimTypePointer
from ...sim_variable import SimVariable, SimTemporaryVariable
from .. import Analysis, register_analysis
from .region_identifier import MultiNode
from .structurer import SequenceNode, CodeNode, ConditionNode, ConditionalBreakNode, LoopNode


l = logging.getLogger(name=__name__)

INDENT_DELTA = 4


class UnsupportedNodeTypeError(NotImplementedError):
    pass


class CConstruct:
    """
    Represents a program construct in C.
    """

    def __init__(self):
        pass

    def c_repr(self, indent=0):
        raise NotImplementedError()


class CFunction(CConstruct):  # pylint:disable=abstract-method
    """
    Represents a function in C.
    """
    def __init__(self, name, statements):

        super(CFunction, self).__init__()

        self.name = name
        self.statements = statements


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

    def c_repr(self, indent=0):

        return "\n".join([ stmt.c_repr(indent=indent) for stmt in self.statements ])


class CAILBlock(CStatement):
    """
    Represents a block of AIL statements.
    """
    def __init__(self, block):

        super(CAILBlock, self).__init__()

        self.block = block

    def c_repr(self, indent=0):

        lines = [ ]

        r = str(self.block)

        indent_str = self.indent_str(indent=indent)
        for l in r.split("\n"):
            lines.append(indent_str + l)

        return "\n".join(lines)


class CLoop(CStatement):  # pylint:disable=abstract-method
    """
    Represents a loop in C.
    """
    pass


class CWhileLoop(CLoop):
    """
    Represents a while loop in C.
    """
    def __init__(self, condition, body):

        super(CWhileLoop, self).__init__()

        self.condition = condition
        self.body = body

    def c_repr(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        lines = [ ]

        if self.condition is None:
            # while(true)
            lines.append(indent_str + 'while(true)')
            lines.append(indent_str + '{')
            lines.append(self.body.c_repr(indent=indent + INDENT_DELTA))
            lines.append(indent_str + '}')
        else:
            # while(cond)
            lines.append(indent_str + 'while(%s)' % self.condition.c_repr())
            lines.append(indent_str + '{')
            lines.append(self.body.c_repr(indent=indent + INDENT_DELTA))
            lines.append(indent_str + '}')

        return "\n".join(lines)


class CDoWhileLoop(CLoop):
    """
    Represents a do-while loop in C.
    """
    def __init__(self, condition, body):

        super().__init__()

        self.condition = condition
        self.body = body

    def c_repr(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        lines = [ ]

        if self.condition is None:
            # do-while true
            lines.append(indent_str + 'do')
            lines.append(indent_str + '{')
            lines.append(self.body.c_repr(indent=indent + INDENT_DELTA))
            lines.append(indent_str + '} while(true);')
        else:
            # do-while(cond)
            lines.append(indent_str + 'do')
            lines.append(indent_str + '{')
            lines.append(self.body.c_repr(indent=indent + INDENT_DELTA))
            lines.append(indent_str + '} while(%s);' % (self.condition.c_repr()))

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

    def c_repr(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        lines = [
            indent_str + "if (%s)" % self.condition.c_repr(),
            indent_str + "{",
        ]

        lines.append(self.true_node.c_repr(indent=indent + INDENT_DELTA))
        lines.append(indent_str + "}")

        if self.false_node is not None:
            lines += [
                indent_str + 'else',
                indent_str + '{',
            ]
            lines.append(self.false_node.c_repr(indent=indent + INDENT_DELTA))
            lines.append(indent_str + "}")

        return "\n".join(lines)


class CIfBreak(CStatement):
    """
    Represents an if-break statement in C.
    """
    def __init__(self, condition):

        super(CIfBreak, self).__init__()

        self.condition = condition

    def c_repr(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        lines = [
            indent_str + "if (%s)" % self.condition,
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

    def c_repr(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        lhs_str = str(self.lhs)
        if isinstance(self.lhs, SimVariable):
            lhs_str = self.lhs.name

        rhs_str = str(self.rhs)
        if hasattr(self.rhs, 'c_repr'):
            rhs_str = self.rhs.c_repr()

        return indent_str + "%s = %s;" % (lhs_str, rhs_str)


class CFunctionCall(CStatement):
    """
    func(arg0, arg1)

    :ivar Function callee_func:  The function getting called.
    """
    def __init__(self, callee_target, callee_func, args, returning=True):
        super().__init__()

        self.callee_target = callee_target
        self.callee_func = callee_func
        self.args = args if args is not None else [ ]
        self.returning = returning

    def c_repr(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        if self.callee_func is not None:
            func_name = self.callee_func.name
        else:
            func_name = str(self.callee_target)

        args_list = [ ]
        for arg in self.args:
            if isinstance(arg, SimVariable):
                arg_str = arg.name
            elif isinstance(arg, CExpression):
                arg_str = arg.c_repr()
            else:
                arg_str = str(arg)
            args_list.append(arg_str)
        args_str = ", ".join(args_list)

        return indent_str + "%s(%s);%s" % (func_name, args_str, " /* do not return */" if not self.returning else "")


class CReturn(CStatement):
    def __init__(self, retval):
        super().__init__()

        self.retval = retval

    def c_repr(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        if self.retval is None:
            return indent_str + "return;"
        else:
            return indent_str + "return %s;" % (self.retval.c_repr())


class CUnsupportedStatement(CStatement):
    """
    A wrapper for unsupported AIL statement.
    """
    def __init__(self, stmt):
        super().__init__()

        self.stmt = stmt

    def c_repr(self, indent=0):

        indent_str = self.indent_str(indent=indent)

        return indent_str + str(self.stmt)


class CExpression:
    """
    Base class for C expressions.
    """
    def c_repr(self):
        raise NotImplementedError()

    def _try_c_repr(self, expr):
        if hasattr(expr, 'c_repr'):
            return expr.c_repr()
        else:
            return str(expr)


class CVariable(CExpression):
    """
    Read value from a variable.
    """
    def __init__(self, variable, offset=None):
        self.variable = variable
        self.offset = offset

    def c_repr(self):
        if self.offset is None:
            if isinstance(self.variable, SimVariable):
                return self.variable.name
            else:
                return str(self.variable)
        else:
            if isinstance(self.variable, SimVariable):
                return "*(%s[%d])" % (self.variable.name, self.offset)
            elif isinstance(self.variable, CExpression):
                return "*(%s:%d)" % (self.variable.c_repr(), self.offset)
            elif isinstance(self.variable, Expr.Register):
                return "%s:%x" % (self.variable.reg_name if hasattr(self.variable, 'reg_name') else self.variable,
                                   self.offset)
            else:
                return "*(%s:%d)" % (self.variable, self.offset)


class CUnaryOp(CExpression):
    """
    Unary operations.
    """
    def __init__(self, op, operand, referenced_variable):

        self.op = op
        self.operand = operand
        self.referenced_variable = referenced_variable

    def c_repr(self):
        if self.referenced_variable is not None:
            return "&%s" % self.referenced_variable.name

        OP_MAP = {
            'Not': self._c_repr_not,
        }

        handler = OP_MAP.get(self.op, None)
        if handler is not None:
            return handler()
        return "UnaryOp %s" % (self.op)

    #
    # Handlers
    #

    def _c_repr_not(self):
        return "!(%s)" % (self.operand.c_repr())


class CBinaryOp(CExpression):
    """
    Binary operations.
    """
    def __init__(self, op, lhs, rhs, referenced_variable):

        self.op = op
        self.lhs = lhs
        self.rhs = rhs
        self.referenced_variable = referenced_variable

    def c_repr(self):

        if self.referenced_variable is not None:
            return "&%s" % self.referenced_variable.name

        OP_MAP = {
            'Add': self._c_repr_add,
            'Sub': self._c_repr_sub,
            'Xor': self._c_repr_xor,
            'CmpLE': self._c_repr_cmple,
            'CmpEQ': self._c_repr_cmpeq,
        }

        handler = OP_MAP.get(self.op, None)
        if handler is not None:
            return handler()
        return "BinaryOp %s" % (self.op)

    #
    # Handlers
    #

    def _c_repr_add(self):
        return "%s + %s" % (self._try_c_repr(self.lhs), self._try_c_repr(self.rhs))

    def _c_repr_sub(self):
        return "%s - %s" % (self._try_c_repr(self.lhs), self._try_c_repr(self.rhs))

    def _c_repr_xor(self):
        return "%s ^ %s" % (self._try_c_repr(self.lhs), self._try_c_repr(self.rhs))

    def _c_repr_cmple(self):
        return "%s <= %s" % (self._try_c_repr(self.lhs), self._try_c_repr(self.rhs))

    def _c_repr_cmpeq(self):
        return "%s == %s" % (self._try_c_repr(self.lhs), self._try_c_repr(self.rhs))


class CTypeCast(CExpression):
    def __init__(self, src_type, dst_type, expr):
        self.src_type = src_type
        self.dst_type = dst_type
        self.expr = expr

    def c_repr(self):
        expr_str = str(self.expr) if not isinstance(self.expr, CExpression) else self.expr.c_repr()
        return "(%s)%s" % (self.dst_type, expr_str)


class CConstant(CExpression):
    def __init__(self, value, type_, reference_values=None):
        self.value = value
        self.type = type_
        self.reference_values = reference_values

    def c_repr(self):
        if self.reference_values is not None and self.type is not None:
            if self.type in self.reference_values:
                if isinstance(self.type, SimTypeInt):
                    return hex(self.reference_values[self.type])
                elif isinstance(self.type, SimTypePointer) and isinstance(self.type.pts_to, SimTypeChar):
                    refval = self.reference_values[self.type]  # angr.analyses.cfg.MemoryData
                    return '"' + refval.content.decode('utf-8') + '"'
                else:
                    return self.reference_values[self.type]

        return str(self.value)


class StructuredCodeGenerator(Analysis):
    def __init__(self, func, sequence, indent=0, cfg=None):
        self._func = func
        self._sequence = sequence
        self._cfg = cfg

        self.text = None
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
        }

        self._analyze()

    def _analyze(self):

        obj = self._handle(self._sequence)
        func_header = self._function_header_repr()
        func_body = obj.c_repr(indent=self._indent + INDENT_DELTA)

        self.text = func_header + "\n{\n" + func_body + "\n}\n"

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
            if expr.op in ("Add", "Sub"):
                lhs, rhs = expr.lhs, expr.rhs
                if isinstance(expr.lhs, int) and not isinstance(expr.rhs, int):
                    # swap lhs and rhs
                    lhs, rhs = rhs, lhs
                if expr.op == "Sub":
                    return lhs, -rhs
                return lhs, rhs


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

        lines = [ ]

        if loop_node.sort == 'while':
            return CWhileLoop(self._handle(loop_node.condition),
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

        return CIfBreak(node.condition)

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

        # cvariable = self._handle(stmt.variable)
        cvariable = stmt.variable
        cdata = self._handle(stmt.data)

        return CAssignment(cvariable, cdata)

    def _handle_Stmt_Assignment(self, stmt):

        cdst = stmt.dst
        csrc = self._handle(stmt.src)

        return CAssignment(cdst, csrc)

    def _handle_Stmt_Call(self, stmt):

        try:
            # Try to handle it as a normal function call
            target = self._handle(stmt.target)
        except UnsupportedNodeTypeError:
            target = stmt.target

        if isinstance(target, int):
            target_func = self.kb.functions.function(addr=target)
        else:
            target_func = None

        args = [ ]
        if target_func.prototype is not None:
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
                    new_arg = arg
                args.append(new_arg)

        return CFunctionCall(target, target_func, args, returning=target_func.returning)

    #
    # AIL expression handlers
    #

    def _handle_Expr_Register(self, expr):

        return expr

    def _handle_Expr_Load(self, expr):

        if hasattr(expr, 'variable') and expr.variable is not None:
            return CVariable(expr.variable)

        variable, offset = self._parse_load_addr(expr.addr)

        return CVariable(variable, offset=offset)

    def _handle_Expr_Tmp(self, expr):

        l.warning("FIXME: Leftover Tmp expressions are found.")
        return CVariable(SimTemporaryVariable(expr.tmp_idx))

    def _handle_Expr_Const(self, expr):

        return expr.value

    def _handle_Expr_UnaryOp(self, expr):

        return CUnaryOp(expr.op, self._handle(expr.operand),
                        referenced_variable=expr.referenced_variable if hasattr(expr, 'referenced_variable') else None
                        )

    def _handle_Expr_BinaryOp(self, expr):

        return CBinaryOp(expr.op, self._handle(expr.operands[0]), self._handle(expr.operands[1]),
                         referenced_variable=expr.referenced_variable if hasattr(expr, 'referenced_variable') else None
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
        else:
            raise UnsupportedNodeTypeError("Unsupported conversion bits %s." % expr.to_bits)

        return CTypeCast(None, dst_type, self._handle(expr.operand))

    def _handle_Expr_StackBaseOffset(self, expr):

        if hasattr(expr, 'referenced_variable') and expr.referenced_variable is not None:
            return CUnaryOp('Reference', expr, referenced_variable=expr.referenced_variable)

        return expr


register_analysis(StructuredCodeGenerator, 'StructuredCodeGenerator')
