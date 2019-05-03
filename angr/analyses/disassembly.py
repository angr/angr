
import logging
from collections import defaultdict

import pyvex
from angr.analyses import AnalysesHub

from ..block import Block, CapstoneInsn, SootBlockNode
from . import Analysis
from .disassembly_utils import decode_instruction

l = logging.getLogger(name=__name__)

# pylint: disable=unidiomatic-typecheck


class DisassemblyPiece(object):
    addr = None
    ident = float('nan')

    def render(self, formatting=None, **kwargs):
        x = self._render(formatting, **kwargs)
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
        if func.is_syscall:
            self.sim_procedure = func._project.simos.syscall_from_addr(self.addr)
        elif func.is_simprocedure:
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

    def _render(self, formatting, **kwargs):  # pylint:disable=unused-argument
        return [self.name + ':']


class BlockStart(DisassemblyPiece):
    def __init__(self, block, parentfunc, project):
        self.addr = block.addr
        self.size = block.size
        self.parentfunc = parentfunc
        self.project = project

    def _render(self, formatting, **kwargs):
        return []


class Hook(DisassemblyPiece):
    def __init__(self, addr, parentblock):
        self.addr = addr
        self.parentblock = parentblock
        if parentblock and parentblock.parentfunc:
            simproc_name = str(parentblock.parentfunc.sim_procedure)
        else:
            simproc_name = "Unknown"
        self.name = simproc_name.split()[-1].strip("'<>")
        self.short_name = simproc_name.strip("'<>").split('.')[-1]

    def _render(self, formatting):
        return ['SimProcedure ' + self.short_name]

    def __eq__(self, other):
        return type(other) is Hook and self.name == other.name


class Instruction(DisassemblyPiece):
    def __init__(self, insn, parentblock):
        self.addr = insn.address
        self.size = insn.size
        self.insn = insn
        self.parentblock = parentblock
        self.project = parentblock.project
        self.arch = parentblock.project.arch
        self.format = ''
        self.components = ()
        self.operands = [ ]

        # the following members will be filled in after disecting the instruction
        self.type = None
        self.branch_type = None
        self.branch_target_operand = None

        self.disect_instruction()

        decode_instruction(self.arch, self)

    @property
    def mnemonic(self):
        return self.opcode

    def reload_format(self):
        self.insn = CapstoneInsn(next(self.arch.capstone.disasm(self.insn.bytes, self.addr)))
        self.disect_instruction()

    def disect_instruction(self):
        # perform a "smart split" of an operands string into smaller pieces
        insn_pieces = self.split_op_string(self.insn.op_str)
        self.operands = []
        cur_operand = None
        i = len(insn_pieces) - 1
        cs_op_num = -1
        nested_mem = False

        # iterate over operands in reverse order
        while i >= 0:
            c = insn_pieces[i]
            if c == '':
                i -= 1
                continue

            if cur_operand is None:
                cur_operand = []
                self.operands.append(cur_operand)

            # Check if this is a number or an identifier.
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
                    reg = c in self.arch.registers

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
                            intc = -intc  # pylint: disable=invalid-unary-operand-type
                        insn_pieces[i-1] = ''
                    cur_operand.append(Value(intc, with_sign))
                else:
                    # XXX STILL A HACK
                    cur_operand.append(c if c[-1] == ':' else c + ' ')

            elif c == ',' and not nested_mem:
                cs_op_num -= 1
                cur_operand = None

            elif c == ':': # XXX this is a hack! fix this later
                insn_pieces[i-1] += ':'

            else:
                # Check if we are inside braces or parentheses. Do not forget
                # that we are iterating in reverse order!
                if c == ']' or c == ')':
                    nested_mem = True

                elif (c == '[' or c == '('):
                    nested_mem = False

                if cur_operand is None:
                    cur_operand = [c]
                    self.operands.append(cur_operand)
                else:
                    cur_operand.append(c if c[0] != ',' else c + ' ')

            i -= 1

        self.opcode = Opcode(self)
        self.operands.reverse()

        if len(self.operands) != len(self.insn.operands):
            l.error("Operand parsing failed for instruction %s. %d operands are parsed, while %d are expected.",
                    str(self.insn),
                    len(self.operands),
                    len(self.insn.operands)
                    )
            self.operands = [ ]
            return

        for i, o in enumerate(self.operands):
            o.reverse()
            self.operands[i] = Operand.build(
                self.insn.operands[i].type,
                i,
                o,
                self
            )

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
            else:
                in_word = False
                pieces.append(c)

        return pieces

    def _render(self, formatting=None):
        return ['%s %s' % (self.opcode.render(formatting)[0], ', '.join(o.render(formatting)[0] for o in self.operands))]


class SootExpression(DisassemblyPiece):
    def __init__(self, expr):
        self.expr = expr

    def _render(self, formatting=None):
        return [self.expr]


class SootExpressionTarget(SootExpression):
    def __init__(self, target_stmt_idx):
        super(SootExpressionTarget, self).__init__(target_stmt_idx)
        self.target_stmt_idx = target_stmt_idx

    def _render(self, formatting=None):
        return [ "Goto %d" % self.target_stmt_idx ]


class SootExpressionStaticFieldRef(SootExpression):
    def __init__(self, field):
        field_str = ".".join(field)
        super(SootExpressionStaticFieldRef, self).__init__(field_str)
        self.field = field
        self.field_str = field_str

    def _render(self, formatting=None):
        return [ self.field_str ]


class SootExpressionInvoke(SootExpression):

    Virtual = "virtual"
    Static = "static"
    Special = "special"

    def __init__(self, invoke_type, expr):

        super(SootExpressionInvoke, self).__init__(str(expr))

        self.invoke_type = invoke_type
        self.base = str(expr.base) if self.invoke_type in (self.Virtual, self.Special) else ""
        self.method_name = expr.method_name
        self.arg_str = expr.list_to_arg_str(expr.args)

    def _render(self, formatting=None):

        return [ "%s%s(%s) [%s]" % (self.base + "." if self.base else "",
                                    self.method_name,
                                    self.arg_str,
                                    self.invoke_type
                                    )
                 ]


class SootStatement(DisassemblyPiece):
    def __init__(self, block_addr, raw_stmt):
        self.addr = block_addr.copy()
        self.addr.stmt_idx = raw_stmt.label
        self.raw_stmt = raw_stmt

        self.components = [ ]

        self._parse()

    @property
    def stmt_idx(self):
        return self.addr.stmt_idx

    def _parse(self):

        func = "_parse_%s" % self.raw_stmt.__class__.__name__

        if hasattr(self, func):
            getattr(self, func)()
        else:
            # print func
            self.components += ["NotImplemented: %s" % func]

    def _expr(self, expr):

        func = "_handle_%s" % expr.__class__.__name__

        if hasattr(self, func):
            return getattr(self, func)(expr)
        else:
            # print func
            return SootExpression(str(expr))

    def _render(self, formatting=None):
        return [ " ".join([ component if type(component) is str
                            else component.render(formatting=formatting)[0]
                            for component in self.components
                            ]
                          )
                 ]

    #
    # Statement parsers
    #

    def _parse_AssignStmt(self):

        self.components += [
            SootExpression(str(self.raw_stmt.left_op)),
            "=",
            self._expr(self.raw_stmt.right_op),
        ]

    def _parse_InvokeStmt(self):

        self.components += [
            self._expr(self.raw_stmt.invoke_expr),
        ]

    def _parse_GotoStmt(self):

        self.components += [
            SootExpressionTarget(self.raw_stmt.target),
        ]

    def _parse_IfStmt(self):

        self.components += [
            "if (",
            SootExpression(str(self.raw_stmt.condition)),
            ")",
            SootExpressionTarget(self.raw_stmt.target),
        ]

    def _parse_ReturnVoidStmt(self):

        self.components += [
            "return",
        ]

    def _parse_IdentityStmt(self):

        self.components += [
            SootExpression(str(self.raw_stmt.left_op)),
            "<-",
            SootExpression(str(self.raw_stmt.right_op)),
        ]

    #
    # Expression handlers
    #

    def _handle_SootStaticFieldRef(self, expr):

        return SootExpressionStaticFieldRef(expr.field[::-1])

    def _handle_SootVirtualInvokeExpr(self, expr):

        return SootExpressionInvoke(SootExpressionInvoke.Virtual, expr)

    def _handle_SootStaticInvokeExpr(self, expr):

        return SootExpressionInvoke(SootExpressionInvoke.Static, expr)

    def _handle_SootSpecialInvokeExpr(self, expr):

        return SootExpressionInvoke(SootExpressionInvoke.Special, expr)

class VexPiece(DisassemblyPiece):
    def __init__(self, piece):
        self._piece = piece

    def _render(self, formatting=None, arch=None):
        str_tokens = []
        for piece in self._pieces(arch):
            if isinstance(piece, str):
                str_tokens.append(piece)
            elif isinstance(piece, int):
                str_tokens.append(str(piece))
            else:
                str_tokens.extend(piece._render(formatting=formatting, arch=arch))
        return ''.join(str_tokens)

    def _pieces(self, arch=None):
        return [self._piece.__str__(arch=arch)]

vex_expr_map = {}
def vex_expr(expr):
    if type(expr) not in vex_expr_map:
        return False
    return vex_expr_map[type(expr)](expr)

class VexGet(VexPiece):
    def __init__(self, pyvex_get_expr):
        self.pyvex_get_expr = pyvex_get_expr

    def _pieces(self, arch=None):
        return ['GET(',
               VexRegister(self.pyvex_get_expr),
               ')',
               ]

class VexLoad(VexPiece):
    def __init__(self, pyvex_load_expr):
        self.pyvex_load_expr = pyvex_load_expr

    def _pieces(self, arch=None):
        return ['LOAD(',
                vex_expr(self.pyvex_load_expr.addr),
                ')'
               ]


class VexRegister(VexPiece):
    def __init__(self, offset_or_expr, ty=None):
        if isinstance(offset_or_expr, pyvex.IRExpr.Get):
            self._offset = offset_or_expr.offset
            self._ty = offset_or_expr.ty
        else:
            self._offset = offset_or_expr
            if ty is None:
                raise ValueError('Cannot process VEX type None')
            self._ty = ty

    def _pieces(self, arch=None):
        reg_name = None
        if arch is not None:
            reg_name = arch.translate_register_name(self._offset, self._ty)

        if reg_name is not None:
            return [reg_name]
        else:
            return ['offset={}'.format(self._offset)]

class VexConstant(VexPiece):
    def __init__(self, value_or_expr, ty=None):
        if isinstance(value_or_expr, pyvex.IRExpr.Const):
            self._value = value_or_expr.con.value
            self._ty_width = value_or_expr.con.size
        else:
            self._value = value_or_expr
            self._ty_width = ty

    def _pieces(self, arch=None):
        if self._ty_width is not None:
            num_hex_digits = 1 + (self._ty_width - 1) // 8
            format_str = '0x%0{}x'.format(num_hex_digits)
            return [format_str % self._value]
        else:
            return ['0x%x' % self._value]

class VexIMarkConstant(VexConstant):
    pass

class VexTmp(VexPiece):
    def __init__(self, tmp_idx_or_expr):
        if isinstance(tmp_idx_or_expr, pyvex.IRExpr.RdTmp):
            self._tmp_idx = tmp_idx_or_expr._tmp
        else:
            self._tmp_idx = tmp_idx_or_expr

    def _pieces(self, arch=None):
        return ['t{}'.format(self._tmp_idx)]

vex_stmt_map = {
}

def vex_stmt(stmt, addr, stmt_idx, tyenv):
    if type(stmt) not in vex_stmt_map:
        return None
    return vex_stmt_map[type(stmt)](stmt, addr, stmt_idx, tyenv)


class VexOp(VexPiece):
    def __init__(self, expr):
        self._op = expr.op
        self._args = expr.args

    def _pieces(self, arch=None):
        arg_pieces = sum(([vex_expr(a), ', '] for a in self._args), [])[:-1]
        return [self._op[4:],
                '(',
                *arg_pieces,
                ')'
               ]

class VexStatement(VexPiece):
    def __init__(self, stmt=None, addr=None, stmt_idx=None, tyenv=None):
        self.stmt = stmt
        self.addr = addr
        self.stmt_idx = stmt_idx
        self.tyenv = tyenv

class VexNoOp(VexStatement):
    def _pieces(self, arch=None):
        return ['NoOp']

class VexJumpKind(VexPiece):
    def __init__(self, jumpkind_str):
        self.jumpkind_str = jumpkind_str

    def _pieces(self, arch=None):
        return [self.jumpkind_str]

class VexIMark(VexStatement):
    def _pieces(self, arch=None):
        return ['----- IMark(',
                VexIMarkConstant(self.stmt.addr),
                ', ',
                self.stmt.len,
                ', ',
                self.stmt.delta,
                ') -----',
                '\n']

class VexPut(VexStatement):
    def __init__(self, *args, **kwargs):
        self._offset = kwargs.pop('offset', None)
        self._data = kwargs.pop('data', None)
        super().__init__(*args, **kwargs)
        if self._offset is None:
            self._offset = self.stmt.offset
            self._data = self.stmt.data

    def _pieces(self, arch=None):
        if hasattr(self._data, 'type'):
            regty = self._data.type
        else:
            regty = self._data.result_type(self.tyenv)
        dataval = vex_expr(self._data)
        if dataval is None:
            if isinstance(dataval, int):
                dataval = VexConstant(dataval)
            elif isinstance(dataval, pyvex.IRConst.IRConst):
                dataval = VexConstant(dataval.value, ty=dataval.type)
        return ['PUT(',
                VexRegister(self._offset, regty),
                ') = ',
                dataval,
                '\n',
               ]

class VexWrTmp(VexStatement):
    def _pieces(self, arch=None):
        return [VexTmp(self.stmt.tmp),
                ' = ',
                vex_expr(self.stmt.data),
                '\n',
               ]

class VexStore(VexStatement):
    def _pieces(self, arch=None):
        return ['ST{}('.format(self.stmt.endness[-2:].lower()),
                VexConstant(self.addr),
                ') = ',
                vex_expr(self.stmt.data),
                '\n',
               ]

class VexExit(VexStatement):
    def _pieces(self, arch=None):
        return ['if (',
                vex_expr(self.stmt.guard),
                ') {',
                '\n',
                '  ',
                VexPut(offset=self.stmt.offsIP, data=self.stmt.dst, tyenv=self.tyenv),
                '}'
                ' ; ',
                VexJumpKind(self.stmt.jumpkind),
                '\n',
               ]

vex_stmt_map[pyvex.IRStmt.NoOp] = VexNoOp
vex_stmt_map[pyvex.IRStmt.IMark] = VexIMark
vex_stmt_map[pyvex.IRStmt.Store] = VexStore
vex_stmt_map[pyvex.IRStmt.Exit] = VexExit
vex_stmt_map[pyvex.IRStmt.Put] = VexPut
vex_stmt_map[pyvex.IRStmt.WrTmp] = VexWrTmp

vex_expr_map[pyvex.IRExpr.Const] = VexConstant
vex_expr_map[pyvex.IRExpr.Load] = VexLoad
vex_expr_map[pyvex.IRExpr.RdTmp] = VexTmp
vex_expr_map[pyvex.IRExpr.Get] = VexGet
vex_expr_map[pyvex.IRExpr.Unop] = VexOp
vex_expr_map[pyvex.IRExpr.Binop] = VexOp
vex_expr_map[pyvex.IRExpr.Triop] = VexOp
vex_expr_map[pyvex.IRExpr.Qop] = VexOp

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
        self.ident = (self.addr, 'operand', self.op_num)

        for i, c in enumerate(self.children):
            if type(c) not in (bytes, str):
                c.ident = (self.addr, 'operand piece', self.op_num, i)
                c.parentop = self

    @property
    def cs_operand(self):
        return self.parentinsn.insn.operands[self.op_num]

    def _render(self, formatting):
        return [''.join(x if type(x) is str else x.decode() if type(x) is bytes else x.render(formatting)[0] for x in self.children)]

    @staticmethod
    def build(operand_type, op_num, children, parentinsn):

        # Maps capstone operand types to operand classes
        MAPPING = {
            1: RegisterOperand,
            2: ConstantOperand,
            3: MemoryOperand,
            4: Operand,  # ARM FP
            64: Operand,  # ARM CIMM
            65: Operand,  # ARM PIMM
            66: Operand,  # ARM SETEND
            67: Operand,  # ARM SYSREG
        }

        cls = MAPPING.get(operand_type, None)
        if cls is None:
            raise ValueError('Unknown capstone operand type %s.' % operand_type)

        operand = cls(op_num, children, parentinsn)

        # Post-processing
        if cls is MemoryOperand and \
                parentinsn.arch.name in { 'AMD64' } and \
                len(operand.values) == 2:
            op0, op1 = operand.values
            if type(op0) is Register and op0.is_ip and type(op1) is Value:
                # Indirect addressing in x86_64
                # 400520  push [rip+0x200782] ==>  400520  push [0x600ca8]
                absolute_addr = parentinsn.addr + parentinsn.size + op1.val
                return MemoryOperand(1, ['[', Value(absolute_addr, False), ']'], parentinsn)

        return operand


class ConstantOperand(Operand):
    pass


class RegisterOperand(Operand):

    @property
    def register(self):
        return next((child for child in self.children if isinstance(child, Register)), None)

    def _render(self, formatting):
        custom_value_str = None
        if formatting is not None:
            try: custom_value_str = formatting['custom_values_str'][self.ident]
            except KeyError: pass

        if custom_value_str:
            return [custom_value_str]
        else:
            return super(RegisterOperand, self)._render(formatting)


class MemoryOperand(Operand):
    def __init__(self, op_num, children, parentinsn):
        super(MemoryOperand, self).__init__(op_num, children, parentinsn)

        # a typical "children" looks like the following:
        # [ 'dword', 'ptr', '[', Register, Value, ']' ]
        # or
        # [ '[', Register, ']' ]
        # or
        # [ Value, '(', Regsiter, ')' ]

        # it will be converted into more meaningful and Pythonic properties

        self.segment_selector = None
        self.prefix = [ ]
        self.values = [ ]

        try:
            if '[' in self.children:
                self._parse_memop_squarebracket()
            elif '(' in self.children:
                self._parse_memop_paren()
            else:
                raise ValueError()

        except ValueError:
            l.error("Failed to parse operand children %s. Please report to Fish.", self.children)

            # setup all dummy properties
            self.prefix = None
            self.values = None

    def _parse_memop_squarebracket(self):
        if self.children[0] != '[':
            try:
                square_bracket_pos = self.children.index('[')
            except ValueError:  #pylint: disable=try-except-raise
                raise

            self.prefix = self.children[ : square_bracket_pos]

            # take out segment selector
            if len(self.prefix) == 3:
                self.segment_selector = self.prefix[-1]
                self.prefix = self.prefix[ : -1]
            else:
                self.segment_selector = None

        else:
            # empty
            square_bracket_pos = 0
            self.prefix = [ ]
            self.segment_selector = None

        if self.children[-1] != ']':
            raise ValueError()

        self.values = self.children[square_bracket_pos + 1: len(self.children) - 1]

    def _parse_memop_paren(self):
        if self.children[0] != '(':
            try:
                paren_pos = self.children.index('(')
            except ValueError:  #pylint: disable=try-except-raise
                raise

            self.prefix = self.children[ : paren_pos]

        else:
            paren_pos = 0
            self.prefix = [ ]
            self.segment_selector = None

        self.values = self.children[paren_pos + 1 : len(self.children) - 1]

    def _render(self, formatting):
        if self.prefix is None:
            # we failed in parsing. use the default rendering
            return super(MemoryOperand, self)._render(formatting)
        else:
            values_style = "square"
            show_prefix = False
            custom_values_str = None

            if formatting is not None:
                try: values_style = formatting['values_style'][self.ident]
                except KeyError: pass

                try:
                    show_prefix_str = formatting['show_prefix'][self.ident]
                    if show_prefix_str in ('true', 'True'):
                        show_prefix = True
                except KeyError:
                    pass

                try: custom_values_str = formatting['custom_values_str'][self.ident]
                except KeyError: pass

            prefix_str = " ".join(self.prefix) + " " if show_prefix else ""
            if custom_values_str is not None:
                value_str = custom_values_str
            else:
                value_str = ''.join(
                    x.render(formatting)[0] if not isinstance(x, (bytes, str)) else x for x in self.values
                )

            segment_selector_str = "" if self.segment_selector is None else self.segment_selector

            if segment_selector_str and prefix_str:
                prefix_str += ' '

            if values_style == 'curly':
                return [ '%s%s{%s}' % (prefix_str, segment_selector_str, value_str) ]
            else:
                return [ '%s%s[%s]' % (prefix_str, segment_selector_str, value_str) ]


class OperandPiece(DisassemblyPiece): # pylint: disable=abstract-method
    # These get filled in later...
    addr = None
    parentop = None
    ident = None


class Register(OperandPiece):
    def __init__(self, reg, prefix):
        self.reg = reg
        self.prefix = prefix
        self.is_ip = self.reg in {"eip", "rip"}  # TODO: Support more architectures

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
    def __init__(self, function=None, ranges=None, **kwargs):  # pylint:disable=unused-argument

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

        kwargs['vex'] = True
        if function is not None:
            # sort them by address, put hooks before nonhooks
            blocks = sorted(function.graph.nodes(), key=lambda node: (node.addr, not node.is_hook))
            for block in blocks:
                self.parse_block(block, **kwargs)

    def func_lookup(self, block):
        try:
            return self._func_cache[block.function.addr]
        except AttributeError:
            return None
        except KeyError:
            f = FunctionStart(block.function)
            self._func_cache[f.addr] = f
            return f

    def parse_block(self, block, **kwargs):
        func = self.func_lookup(block)
        if func and func.addr == block.addr:
            self.raw_result.append(FuncComment(block.function))
            self.raw_result.append(func)
        bs = BlockStart(block, func, self.project)
        self.raw_result.append(bs)

        if 'vex' in kwargs and kwargs['vex']:
            vex_block = self.project.factory.block(block.addr, block.size)
            tyenv = vex_block.vex.tyenv
            if vex_block.thumb:
                aligned_block_addr = (vex_block.addr >> 1) << 1
            else:
                aligned_block_addr = vex_block.addr
            self.block_to_insn_addrs[block.addr] = []
            stmt_idx = None
            stmt_addr = None
            for stmt in vex_block.vex.statements:
                if type(stmt) is pyvex.IRStmt.IMark:
                    stmt_addr = stmt.addr
                    stmt_idx = 0
                    self.raw_result_map['instructions'][stmt_addr] = []
                    self.block_to_insn_addrs[block.addr].append(stmt_addr)
                    if stmt_addr in self.kb.labels:
                        label = Label(stmt_addr, self.kb.labels[stmt_addr])
                        self.raw_result.append(label)
                        self.raw_result_map['labels'][label.addr] = label
                    if stmt_addr in self.kb.comments:
                        comment = Comment(stmt_addr, self.kb.comments[stmt_addr])
                        self.raw_result.append(comment)
                        self.raw_result_map['comments'][stmt_addr] = comment
                stmt_idx += 1
                stmt = vex_stmt(stmt, stmt_addr, stmt_idx, tyenv)
                if stmt is not None:
                    self.raw_result.append(stmt)
                    self.raw_result_map['instructions'][stmt.addr].append(stmt)
        elif block.is_hook:
            hook = Hook(block.addr, bs)
            self.raw_result.append(hook)
            self.raw_result_map['hooks'][block.addr] = hook
        elif self.project.arch.capstone_support:
            if block.thumb:
                aligned_block_addr = (block.addr >> 1) << 1
                cs = self.project.arch.capstone_thumb
            else:
                aligned_block_addr = block.addr
                cs = self.project.arch.capstone
            if block.bytestr is None:
                bytestr = self.project.loader.memory.load(aligned_block_addr, block.size)
            else:
                bytestr = block.bytestr
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
        elif type(block) is SootBlockNode:
            for raw_stmt in block.stmts:
                stmt = SootStatement(block.addr, raw_stmt)
                self.raw_result.append(stmt)
                self.raw_result_map['instructions'][stmt.addr] = stmt
                self.block_to_insn_addrs[block.addr].append(stmt.addr)
        else:
            raise TypeError("")

    def render(self, formatting=None, **kwargs):
        if formatting is None: formatting = {}
        return ''.join(sum((x.render(formatting, **kwargs) for x in self.raw_result), []))


AnalysesHub.register_default('Disassembly', Disassembly)
