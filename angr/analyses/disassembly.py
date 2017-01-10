
from collections import defaultdict
import logging

from ..analysis import Analysis, register_analysis
from ..block import CapstoneInsn

from .disassembly_utils import decode_instruction

l = logging.getLogger('angr.analyses.disassembly')

class DisassemblyPiece(object):
    addr = None
    ident = float('nan')

    def render(self, formatting=None):
        x = self._render(formatting)
        if len(x) == 1:
            return [self.highlight(x[0], formatting)]
        else:
            return x

    def _render(self, formatting):
        raise NotImplementedError

    def getpiece(self, formatting, column):  # pylint:disable=unused-argument
        return self

    def width(self, formatting):
        r = self._render(formatting)
        if not r: return 0
        return max(len(x) for x in r)

    def height(self, formatting):
        return len(self._render(formatting))

    @staticmethod
    def color(string, coloring, formatting):
        try:
            return '%s%s%s' % (formatting['colors'][coloring][0], string, formatting['colors'][coloring][1])
        except KeyError:
            return string

    def highlight(self, string, formatting=None):
        try:
            if formatting is not None and self in formatting['highlight']:
                return self.color(string, 'highlight', formatting)
        except KeyError:
            pass
        return string

    def __eq__(self, other):
        return False

class FunctionStart(DisassemblyPiece):
    def __init__(self, func):
        """
        Constructor.

        :param angr.knowledge.Function func: The function instance.
        """

        self.addr = func.addr
        self.vars = []
        self.name = func.name
        self.is_simprocedure = func.is_simprocedure
        self.sim_procedure = None
        if self.is_simprocedure:
            self.sim_procedure = func._project.hooked_by(self.addr)

    def _render(self, formatting):
        # TODO: Make the individual elements be individual Pieces
        return ['%s = %#x' % (name, offset) for offset, name in self.vars]

    def height(self, formatting):
        return len(self.vars)

class Label(DisassemblyPiece):
    def __init__(self, addr, name):
        self.addr = addr
        self.name = name

    def _render(self, formatting):  # pylint:disable=unused-argument
        return [self.name + ':']

class BlockStart(DisassemblyPiece):
    def __init__(self, block, parentfunc, project):
        self.addr = block.addr
        self.size = block.size
        self.parentfunc = parentfunc
        self.project = project

    def _render(self, formatting):
        return []

class Hook(DisassemblyPiece):
    def __init__(self, addr, parentblock):
        self.addr = addr
        self.parentblock = parentblock
        self.name = str(parentblock.parentfunc.sim_procedure).split()[-1].strip("'<>")
        self.short_name = str(parentblock.parentfunc.sim_procedure).strip("'<>").split('.')[-1]

    def _render(self, formatting):
        return ['SimProcedure ' + self.short_name]

    def __eq__(self, other):
        return type(other) is Hook and self.name == other.name

class Instruction(DisassemblyPiece):
    def __init__(self, insn, parentblock):
        self.addr = insn.address
        self.insn = insn
        self.parentblock = parentblock
        self.project = parentblock.project
        self.format = ''
        self.components = ()
        self.operands = [ ]

        # the following members will be filled in after disecting the instruction
        self.type = None
        self.branch_type = None
        self.branch_target_operand = None

        self.disect_instruction()

        decode_instruction(self.project.arch, self)

    @property
    def mnemonic(self):
        return self.opcode

    def reload_format(self):
        self.insn = CapstoneInsn(next(self.project.arch.capstone.disasm(self.insn.bytes, self.addr)))
        self.disect_instruction()

    def disect_instruction(self):
        # perform a "smart split" of an operands string into smaller pieces
        insn_pieces = self.split_op_string(self.insn.op_str)
        self.operands = []
        cur_operand = None
        i = len(insn_pieces) - 1
        cs_op_num = -1

        # iterate over operands in reverse order
        while i >= 0:
            c = insn_pieces[i]
            if c == '':
                i -= 1
                continue

            if cur_operand is None:
                cur_operand = []
                self.operands.append(cur_operand)

            # check if this is a number or an identifier
            ordc = ord(c[0])
            # pylint:disable=too-many-boolean-expressions
            if (ordc >= 0x30 and ordc <= 0x39) or \
               (ordc >= 0x41 and ordc <= 0x5a) or \
               (ordc >= 0x61 and ordc <= 0x7a):

                # perform some basic classification
                intc = None
                reg = False
                try:
                    intc = int(c, 0)
                except ValueError:
                    reg = c in self.project.arch.registers

                # if this is a "live" piece, liven it up!
                # special considerations:
                # - registers should consolidate with a $ or % prefix
                # - integers should consolidate with a sign prefix

                if reg:
                    prefix = ''
                    if i > 0 and insn_pieces[i-1] in ('$', '%'):
                        prefix = insn_pieces[i-1]
                        insn_pieces[i-1] = ''
                    cur_operand.append(Register(c, prefix))
                elif intc is not None:
                    with_sign = False
                    if i > 0 and insn_pieces[i-1] in ('+', '-'):
                        with_sign = True
                        if insn_pieces[i-1] == '-':
                            intc = -intc
                        insn_pieces[i-1] = ''
                    cur_operand.append(Value(intc, with_sign))
                else:
                    # XXX STILL A HACK
                    cur_operand.append(c if c[-1] == ':' else c + ' ')

            elif c == ',':
                cs_op_num -= 1
                cur_operand = None
            elif c == ':': # XXX this is a hack! fix this later
                insn_pieces[i-1] += ':'
            else:
                if cur_operand is None:
                    cur_operand = [c]
                    self.operands.append(cur_operand)
                else:
                    cur_operand.append(c)

            i -= 1

        self.opcode = Opcode(self)
        self.operands.reverse()
        for i, o in enumerate(self.operands):
            o.reverse()
            self.operands[i] = Operand(i, o, self)

    @staticmethod
    def split_op_string(insn_str):
        pieces = []
        in_word = False
        for c in insn_str:
            ordc = ord(c)
            if ordc == 0x20:
                in_word = False
                continue
            # pylint:disable=too-many-boolean-expressions
            if (ordc >= 0x30 and ordc <= 0x39) or \
               (ordc >= 0x41 and ordc <= 0x5a) or \
               (ordc >= 0x61 and ordc <= 0x7a):
                if in_word:
                    pieces[-1] += c
                else:
                    in_word = True
                    pieces.append(c)
            elif c == '%':
                in_word = False
                pieces.append('%%')

            else:
                in_word = False
                pieces.append(c)

        return pieces

    def _render(self, formatting=None):
        return ['%s %s' % (self.opcode.render(formatting)[0], ', '.join(o.render(formatting)[0] for o in self.operands))]


class Opcode(DisassemblyPiece):
    def __init__(self, parentinsn):
        self.addr = parentinsn.addr
        self.insn = parentinsn.insn
        self.parentinsn = parentinsn
        self.opcode_string = self.insn.mnemonic
        self.ident = (self.addr, 'opcode')

    def _render(self, formatting=None):
        return [self.opcode_string.ljust(7)]

    def __eq__(self, other):
        return type(other) is Opcode and self.opcode_string == other.opcode_string


class Operand(DisassemblyPiece):
    def __init__(self, op_num, children, parentinsn):
        self.addr = parentinsn.addr
        self.children = children
        self.parentinsn = parentinsn
        self.op_num = op_num

        for i, c in enumerate(self.children):
            if type(c) not in (str, unicode):
                c.ident = (self.addr, 'operand piece', self.op_num, i)
                c.parentop = self

    @property
    def cs_operand(self):
        return self.parentinsn.insn.operands[self.op_num]

    def _render(self, formatting):
        return [''.join(x if type(x) in (str, unicode) else x.render(formatting)[0] for x in self.children)]


class OperandPiece(DisassemblyPiece): # pylint: disable=abstract-method
    # These get filled in later...
    addr = None
    parentop = None
    ident = None


class Register(OperandPiece):
    def __init__(self, reg, prefix):
        self.reg = reg
        self.prefix = prefix

    def _render(self, formatting):
        # TODO: register renaming
        return [self.prefix + self.reg]

    def __eq__(self, other):
        return type(other) is Register and self.reg == other.reg


class Value(OperandPiece):
    def __init__(self, val, render_with_sign):
        self.val = val
        self.render_with_sign = render_with_sign

    @property
    def project(self):
        return self.parentop.parentinsn.project

    def __eq__(self, other):
        return type(other) is Value and self.val == other.val

    def _render(self, formatting):
        if formatting is not None:
            try:
                style = formatting['int_styles'][self.ident]
                if style[0] == 'hex':
                    if self.render_with_sign:
                        return ['%#+x' % self.val]
                    else:
                        return ['%#x' % self.val]
                elif style[0] == 'dec':
                    if self.render_with_sign:
                        return ['%+d' % self.val]
                    else:
                        return [str(self.val)]
                elif style[0] == 'label':
                    labeloffset = style[1]
                    if labeloffset == 0:
                        return [self.project.kb.labels[self.val]]
                    return ['%s%s%#+x' % ('+' if self.render_with_sign else '', self.project.kb.labels[self.val + labeloffset], labeloffset)]
            except KeyError:
                pass

        # default case
        if self.val in self.project.kb.labels:
            return [('+' if self.render_with_sign else '') + self.project.kb.labels[self.val]]
        else:
            if self.render_with_sign:
                return ['%#+x' % self.val]
            else:
                return ['%#x' % self.val]


class Comment(DisassemblyPiece):
    def __init__(self, addr, text):
        self.addr = addr
        self.text = text.split('\n')

    def _render(self, formatting=None):
        return [self.text]

    def height(self, formatting):
        lines = len(self.text)
        return 0 if lines == 1 else lines


class FuncComment(DisassemblyPiece):
    def __init__(self, func):
        self.func = func

    def _render(self, formatting=None):
        return ['##', '## Function ' + self.func.name, '##']

class Disassembly(Analysis):
    def __init__(self, function=None, ranges=None):  # pylint:disable=unused-argument

        # TODO: support ranges

        self.raw_result = []
        self.raw_result_map = {
            'block_starts': {},
            'comments': {},
            'labels': {},
            'instructions': {},
            'hooks': {},
        }
        self.block_to_insn_addrs = defaultdict(list)
        self._func_cache = {}

        if function is not None:
            blocks = function.graph.nodes()
            # sort them by address, put hooks before nonhooks
            blocks.sort(key=lambda node: (node.addr, not node.is_hook))
            for block in blocks:
                self.parse_block(block)

    def func_lookup(self, block):
        try:
            return self._func_cache[block.function.addr]
        except AttributeError:
            return None
        except KeyError:
            f = FunctionStart(block.function)
            self._func_cache[f.addr] = f
            return f

    def parse_block(self, block):
        func = self.func_lookup(block)
        if func and func.addr == block.addr:
            self.raw_result.append(FuncComment(block.function))
            self.raw_result.append(func)
        bs = BlockStart(block, func, self.project)
        self.raw_result.append(bs)

        if block.is_hook:
            hook = Hook(block.addr, bs)
            self.raw_result.append(hook)
            self.raw_result_map['hooks'][block.addr] = hook

        else:
            cs = self.project.arch.capstone
            bytestr = ''.join(self.project.loader.memory.read_bytes(block.addr, block.size))
            self.block_to_insn_addrs[block.addr] = []
            for cs_insn in cs.disasm(bytestr, block.addr):
                if cs_insn.address in self.kb.labels:
                    label = Label(cs_insn.address, self.kb.labels[cs_insn.address])
                    self.raw_result.append(label)
                    self.raw_result_map['labels'][label.addr] = label
                if cs_insn.address in self.kb.comments:
                    comment = Comment(cs_insn.address, self.kb.comments[cs_insn.address])
                    self.raw_result.append(comment)
                    self.raw_result_map['comments'][comment.addr] = comment
                instruction = Instruction(CapstoneInsn(cs_insn), bs)
                self.raw_result.append(instruction)
                self.raw_result_map['instructions'][instruction.addr] = instruction
                self.block_to_insn_addrs[block.addr].append(cs_insn.address)

    def render(self, formatting=None):
        if formatting is None: formatting = {}
        return '\n'.join(sum((x.render(formatting) for x in self.raw_result), []))


register_analysis(Disassembly, 'Disassembly')
