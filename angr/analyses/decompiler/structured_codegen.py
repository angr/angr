
from ailment import Block

from .. import Analysis, register_analysis
from .region_identifier import MultiNode
from .structurer import SequenceNode, CodeNode, ConditionNode, ConditionalBreakNode, LoopNode

INDENT_DELTA = 4


class StructuredCodeGenerator(Analysis):
    def __init__(self, sequence):
        self._sequence = sequence

        self.text = None

        self._analyze()

    def _analyze(self):

        text = "\n".join(self._handle(self._sequence))

        self.text = text

    @staticmethod
    def indent(indent_count):
        return " " * indent_count

    #
    # Handlers
    #

    def _handle(self, node, indent=0):

        if type(node) is SequenceNode:
            return self._handle_Sequence(node, indent)
        elif type(node) is CodeNode:
            return self._handle_Code(node, indent)
        elif type(node) is LoopNode:
            return self._handle_Loop(node, indent)
        elif type(node) is ConditionNode:
            return self._handle_Condition(node, indent)
        elif type(node) is ConditionalBreakNode:
            return self._handle_ConditionalBreak(node, indent)
        elif type(node) is MultiNode:
            return self._handle_MultiNode(node, indent)
        elif type(node) is Block:
            return self._handle_AILBlock(node, indent)
        else:
            raise Exception("Node type %s is not supported yet." % type(node))

    def _handle_Code(self, code, indent):

        return self._handle(code.node, indent=indent)

    def _handle_Sequence(self, seq, indent):

        lines = [ ]

        for node in seq.nodes:
            lines.extend(self._handle(node, indent=indent))

        return lines

    def _handle_Loop(self, loop_node, indent):

        lines = [ ]

        if loop_node.sort == 'while':
            if loop_node.condition == None:
                # while(true)
                lines.append('while(true)')
                lines.append('{')
                lines.extend(self._handle(loop_node.sequence_node, indent=INDENT_DELTA))
                lines.append('}')
            else:
                # while(cond)
                lines.append('while(%s)' % repr(loop_node.condition))
                lines.append('{')
                lines.extend(self._handle(loop_node.sequence_node, indent=INDENT_DELTA))
                lines.append('}')
        elif loop_node.sort == 'do-while':
            if loop_node.condition == None:
                raise NotImplementedError()
            else:
                lines.append('do')
                lines.append('{')
                lines.extend(self._handle(loop_node.sequence_node, indent=INDENT_DELTA))
                lines.append('} while(%s);' % repr(loop_node.condition))
        else:
            raise NotImplementedError()

        new_lines = [ self.indent(indent) + l for l in lines ]

        return new_lines

    def _handle_Condition(self, condition_node, indent):

        indent_str = self.indent(indent)

        lines = [
            "if (%s)" % condition_node.condition,
            "{",
        ]

        lines.extend(self._handle(condition_node.true_node, indent=INDENT_DELTA))
        lines.append("}")

        if condition_node.false_node is not None:
            lines += [
                'else',
                '{',
            ]
            lines.extend(self._handle(condition_node.false_node, indent=INDENT_DELTA))
            lines.append("}")

        new_lines = [ indent_str + l for l in lines ]

        return new_lines

    def _handle_ConditionalBreak(self, node, indent):

        lines = [
            self.indent(indent) + "if (" + str(node.condition) + ")",
            self.indent(indent + INDENT_DELTA) + "break;",
            self.indent(indent) + "}",
        ]

        return lines

    def _handle_MultiNode(self, node, indent):

        lines = [ ]

        for n in node.nodes:
            r = str(n)
            for l in r.split("\n"):
                lines.append(self.indent(indent) + l)

        return lines

    def _handle_AILBlock(self, node, indent):

        lines = [ ]

        r = str(node)

        for l in r.split("\n"):
            lines.append(self.indent(indent) + l)

        return lines

register_analysis(StructuredCodeGenerator, 'StructuredCodeGenerator')
