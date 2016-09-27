from ..analysis import Analysis, register_analysis
from ..lifter import CapstoneInsn

import logging
l = logging.getLogger('angr.analyses.disassembly')

class DisassemblyPiece(object):
    addr = None
    ident = float('nan')

    def render(self, formatting):
        x = self._render(formatting)
        if len(x) == 1:
            return [self.highlight(x[0], formatting)]
        else:
            return x

    def _render(self, formatting):
        raise NotImplementedError

    def getpiece(self, formatting, column):
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

    def highlight(self, string, formatting):
        try:
            if self in formatting['highlight']:
                return self.color(string, 'highlight', formatting)
        except KeyError:
            pass
        return string

    def __eq__(self, other):
        return False

class FunctionStart(DisassemblyPiece):
    def __init__(self, func):
        self.addr = func.addr
        self.vars = []

    def _render(self, formatting):
        # TODO: Make the individual elements be individual Pieces
        return ['%s = %#x' % (name, offset) for offset, name in self.vars]

    def height(self, formatting):
        return len(self.vars)

class Label(DisassemblyPiece):
    def __init__(self, addr, name):
        self.addr = addr
        self.name = name

    def _render(self, formating):
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
        self.name = str(parentblock.sim_procedure).split()[-1].strip("'<>")
        self.short_name = str(a).strip("'<>").split('.')[-1]

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

        self.disect_instruction()

    def reload_format(self):
        self.insn = CapstoneInstruction(next(self.project.arch.capstone.disasm(self.insn.bytes, self.addr)))
        self.disect_instruction()

    def disect_instruction(self):
        insn_pieces = self.split_op_string(self.insn.op_str)
        live_pieces = []
        i = len(insn_pieces) - 1
        cs_op_num = -1
        serial = 0
        while i >= 0:
            c = insn_pieces[i]
            if c == '':
                i -= 1
                continue

            ordc = ord(c[0])
            if (ordc >= 0x30 and ordc <= 0x39) or \
               (ordc >= 0x41 and ordc <= 0x5a) or \
               (ordc >= 0x61 and ordc <= 0x7a):
                try:
                    intc = int(c, 0)
                except ValueError:
                    if c in self.project.arch.registers:
                        live_pieces.append(InstructionRegOperand(c, self, cs_op_num, serial))
                        serial += 1
                        insn_pieces[i] = '%s'
                        if i > 0 and insn_pieces[i-1] in ('$', '%'):
                            insn_pieces[i-1] = ''
                    else:
                        insn_pieces[i] += ' '
                else:
                    with_sign = False
                    if i > 0 and insn_pieces[i-1] in ('+', '-'):
                        with_sign = True
                        if insn_pieces[i-1] == '-':
                            intc = -intc
                        insn_pieces[i-1] = ''
                    live_pieces.append(InstructionValOperand(intc, self, with_sign, cs_op_num, serial))
                    serial += 1
                    insn_pieces[i] = '%s'
            elif c == ',':
                insn_pieces[i] = ', '
                cs_op_num -= 1
            elif c == ':':
                insn_pieces[i] = insn_pieces[i-1] + ':'
                insn_pieces[i-1] = ''

            i -= 1

        self.format = '%-7s ' + ''.join(insn_pieces)
        self.components = [InstructionOpcode(self)] + list(reversed(live_pieces))

    @staticmethod
    def split_op_string(insn_str):
        pieces = []
        in_word = False
        for c in insn_str:
            ordc = ord(c)
            if ordc == 0x20:
                in_word = False
                continue
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

    def render(self, formatting):
        return [self.format % tuple(x.render(formatting)[0] for x in self.components)]

class InstructionOpcode(DisassemblyPiece):
    def __init__(self, parentinsn):
        self.addr = parentinsn.addr
        self.insn = parentinsn.insn
        self.parentinsn = parentinsn
        self.opcode_string = self.insn.mnemonic
        self.ident = (self.addr, 'opcode')

    def _render(self, formatting):
        return [self.opcode_string]

    def __eq__(self, other):
        return type(other) is InstructionOpcode and self.opcode_string == other.opcode_string

class InstructionRegOperand(DisassemblyPiece):
    def __init__(self, reg, parentinsn, op_num, serial):
        self.addr = parentinsn.addr
        self.reg = reg
        self.op_num = op_num
        self.ident = (self.addr, 'operand', serial)

    def _render(self, formatting):
        # TODO: register renaming
        return [self.reg]

    def __eq__(self, other):
        return type(other) is InstructionRegOperand and self.reg == other.reg

class InstructionValOperand(DisassemblyPiece):
    def __init__(self, val, parentinsn, render_with_sign, op_num, serial):
        self.addr = parentinsn.addr
        self.val = val
        self.parentinsn = parentinsn
        self.render_with_sign = render_with_sign
        self.ident = (self.addr, 'operand', serial)
        self.project = parentinsn.project

    def __eq__(self, other):
        return type(other) is InstructionValOperand and self.val == other.val

    def _render(self, formatting):
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
        self.text = self.text.split('\n')

    def _render(self, formatting):
        return self.text

    def height(self, formatting):
        l = len(self.text)
        return 0 if l == 1 else l

class FuncComment(DisassemblyPiece):
    def __init__(self, func):
        self.func = func

    def _render(self, formatting):
        return ['##', '## Function ' + self.func.name, '##']

class Disassembly(Analysis):
    def __init__(self, function=None, ranges=None):
        self.raw_result = []
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
            self.raw_result.append(Hook(block.addr, bs))
        else:
            cs = self.project.arch.capstone
            bytestr = ''.join(self.project.loader.memory.read_bytes(block.addr, block.size))
            for cs_insn in cs.disasm(bytestr, block.addr):
                if cs_insn.address in self.kb.labels:
                    self.raw_result.append(Label(cs_insn.address, self.kb.labels[cs_insn.address]))
                if cs_insn.address in self.kb.comments:
                    self.raw_result.append(Comment(self.kb.comments[cs_insn.address]))
                self.raw_result.append(Instruction(CapstoneInsn(cs_insn), bs))

    def render(self, formatting=None):
        if formatting is None: formatting = {}
        return '\n'.join(sum((x.render(formatting) for x in self.raw_result), []))


register_analysis(Disassembly, 'Disassembly')
