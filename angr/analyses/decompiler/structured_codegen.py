
from ailment import Block

from .. import Analysis, register_analysis
from .region_identifier import MultiNode
from .structurer import SequenceNode, CodeNode, ConditionNode, ConditionalBreakNode, LoopNode

INDENT_DELTA = 4


class CConstruct(object):
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
            lines.append(indent_str + self.body.c_repr(indent=indent + INDENT_DELTA))
            lines.append(indent_str + '}')
        else:
            # while(cond)
            lines.append(indent_str + 'while(%s)' % repr(self.condition))
            lines.append(indent_str + '{')
            lines.append(indent_str + self.body.c_repr(indent=indent + INDENT_DELTA))
            lines.append(indent_str + '}')

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
            indent_str + "if (%s)" % self.condition,
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

        return indent_str + "%s = %s;" % (self.lhs, self.rhs)


class StructuredCodeGenerator(Analysis):
    def __init__(self, sequence):
        self._sequence = sequence

        self.text = None

        self._analyze()

    def _analyze(self):

        obj = self._handle(self._sequence)
        text = obj.c_repr()

        self.text = text

    #
    # Handlers
    #

    def _handle(self, node):

        if type(node) is SequenceNode:
            return self._handle_Sequence(node)
        elif type(node) is CodeNode:
            return self._handle_Code(node)
        elif type(node) is LoopNode:
            return self._handle_Loop(node)
        elif type(node) is ConditionNode:
            return self._handle_Condition(node)
        elif type(node) is ConditionalBreakNode:
            return self._handle_ConditionalBreak(node)
        elif type(node) is MultiNode:
            return self._handle_MultiNode(node)
        elif type(node) is Block:
            return self._handle_AILBlock(node)
        else:
            raise Exception("Node type %s is not supported yet." % type(node))

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
            return CWhileLoop(loop_node.condition,
                              self._handle(loop_node.sequence_node)
                              )
        elif loop_node.sort == 'do-while':
            # TODO: FIXME

            if loop_node.condition is None:
                raise NotImplementedError()
            else:
                lines.append('do')
                lines.append('{')
                lines.extend(self._handle(loop_node.sequence_node))
                lines.append('} while(%s);' % repr(loop_node.condition))

            return lines

        else:
            raise NotImplementedError()

    def _handle_Condition(self, condition_node):

        code = CIfElse(condition_node.condition,
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

    def _handle_AILBlock(self, node):  # pylint:disable=no-self-use

        return CStatements([ CAILBlock(node) ])

register_analysis(StructuredCodeGenerator, 'StructuredCodeGenerator')
