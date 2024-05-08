import logging
from collections import defaultdict
from typing import Union, Any
from collections.abc import Sequence

import pyvex
import archinfo
from angr.knowledge_plugins import Function

from . import Analysis

from ..errors import AngrTypeError
from ..utils.library import get_cpp_function_name
from ..utils.formatting import ansi_color_enabled, ansi_color, add_edge_to_buffer
from ..block import DisassemblerInsn, CapstoneInsn, SootBlockNode
from ..codenode import BlockNode
from .disassembly_utils import decode_instruction

try:
    from ..engines import pcode
    import pypcode

    IRSBType = Union[pyvex.IRSB, pcode.lifter.IRSB]
    IROpObjType = Union[pyvex.stmt.IRStmt, pypcode.PcodeOp]
except ImportError:
    pcode = None
    IRSBType = pyvex.IRSB
    IROpObjType = pyvex.stmt

l = logging.getLogger(name=__name__)

# pylint: disable=unidiomatic-typecheck


class DisassemblyPiece:
    addr = None
    ident = float("nan")

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
        if not r:
            return 0
        return max(len(x) for x in r)

    def height(self, formatting):
        return len(self._render(formatting))

    @staticmethod
    def color(string, coloring, formatting):
        try:
            return "{}{}{}".format(formatting["colors"][coloring][0], string, formatting["colors"][coloring][1])
        except KeyError:
            return string

    def highlight(self, string, formatting=None):
        try:
            if formatting is not None:
                if "format_callback" in formatting:
                    return formatting["format_callback"](self, string)
                if self in formatting["highlight"]:
                    return self.color(string, "highlight", formatting)
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
        return [f"{name} = {offset:#x}" for offset, name in self.vars]

    def height(self, formatting):
        return len(self.vars)


class Label(DisassemblyPiece):
    def __init__(self, addr, name):
        self.addr = addr
        self.name = name

    def _render(self, formatting):  # pylint:disable=unused-argument
        return [self.name + ":"]


class IROp(DisassemblyPiece):
    __slots__ = (
        "addr",
        "seq",
        "obj",
        "irsb",
    )

    addr: int
    seq: int
    obj: IROpObjType
    irsb: IRSBType

    def __init__(self, addr: int, seq: int, obj: IROpObjType, irsb: IRSBType):
        self.addr = addr
        self.seq = seq
        self.obj = obj
        self.irsb = irsb

    def __str__(self):
        if pcode and isinstance(self.obj, pypcode.PcodeOp):
            return pypcode.PcodePrettyPrinter.fmt_op(self.obj)
        return str(self.obj)

    def _render(self, formatting):  # pylint:disable=unused-argument
        return [str(self)]


class BlockStart(DisassemblyPiece):
    def __init__(self, block, parentfunc, project):
        self.addr = block.addr
        self.size = block.size
        self.parentfunc = parentfunc
        self.project = project

    def _render(self, formatting):
        return []


class Hook(DisassemblyPiece):
    def __init__(self, block):
        self.addr = block.addr
        simproc_name = str(block.sim_procedure)
        self.name = simproc_name.split()[-1].strip("'<>")
        self.short_name = simproc_name.strip("'<>").split(".")[-1]

    def _render(self, formatting):
        return ["SimProcedure " + self.short_name]

    def __eq__(self, other):
        return type(other) is Hook and self.name == other.name


class Instruction(DisassemblyPiece):
    def __init__(self, insn, parentblock, project=None):
        self.addr = insn.address
        self.size = insn.size
        self.insn = insn
        self.parentblock = parentblock
        self.project = parentblock.project if parentblock is not None else project
        self.arch = self.project.arch
        self.format = ""
        self.components = ()
        self.opcode = None
        self.operands = []

        # the following members will be filled in after dissecting the instruction
        self.type = None
        self.branch_type = None
        self.branch_target_operand = None

        self.dissect_instruction()

        if isinstance(insn, CapstoneInsn):
            decode_instruction(self.arch, self)

    @property
    def mnemonic(self):
        return self.opcode

    def reload_format(self):
        self.insn = CapstoneInsn(next(self.arch.capstone.disasm(self.insn.bytes, self.addr)))
        self.dissect_instruction()

    def dissect_instruction(self):
        if isinstance(
            self.arch,
            (archinfo.ArchAArch64, archinfo.ArchARM, archinfo.ArchARMEL, archinfo.ArchARMHF, archinfo.ArchARMCortexM),
        ):
            self.dissect_instruction_for_arm()
        else:
            # the default one works well for x86, add more arch-specific
            # code when you find it doesn't meet your need.
            self.dissect_instruction_by_default()

    def dissect_instruction_for_arm(self):
        self.opcode = Opcode(self)
        self.operands = []

        # We use capstone for arm64 disassembly, so this assertion must success
        assert hasattr(self.insn, "operands")

        op_str = self.insn.op_str
        dummy_operands = self.split_arm_op_string(op_str)

        for operand in dummy_operands:
            opr_pieces = self.split_op_string(operand)
            cur_operand = []

            if not (operand and opr_pieces):
                # opr_pieces may contain empty string when invalid disasm
                # result is generated by capstone
                l.error(f'Failed to parse insn "{self.insn}". Please report.')
                self.operands.clear()
                break

            if opr_pieces[0][0].isalpha() and opr_pieces[0] in self.arch.registers:
                cur_operand.append(Register(opr_pieces[0]))
                # handle register's suffix (e.g. "sp!", "d0[1]", "v0.16b")
                cur_operand.extend(opr_pieces[1:])
                self.operands.append(cur_operand)
                continue

            for i, p in enumerate(opr_pieces):
                if p[0].isnumeric():
                    if any(
                        (
                            i > 0 and opr_pieces[i - 1] == ".",
                            i > 1
                            and (
                                opr_pieces[i - 2] in ["lsl", "lsr", "asr", "ror", "msl"]
                                or opr_pieces[i - 2][:3] in ("uxt", "sxt")
                            ),
                        )
                    ):
                        cur_operand.append(p)
                        continue
                    # Always set False. I don't see any '+' sign appear
                    # in capstone's arm disasm result
                    with_sign = False
                    try:
                        v = int(p, 0)
                    except ValueError:
                        l.error("Failed to parse operand %s at %016x. Please report.", p, self.addr)
                        cur_operand.append(p)
                        continue
                    if i > 0 and opr_pieces[i - 1] == "-":
                        v = -v
                        cur_operand.pop()
                    cur_operand.append(Value(v, with_sign))
                elif p[0].isalpha() and p in self.arch.registers:
                    cur_operand.append(Register(p))
                else:
                    cur_operand.append(p)
            self.operands.append(cur_operand)

        for i, opr in enumerate(self.operands):
            if i < len(self.insn.operands):
                op_type = self.insn.operands[i].type
            else:
                # set extra dummy operand type to default 0
                op_type = 0
            self.operands[i] = Operand.build(op_type, i, opr, self)

        if len(self.operands) == 0 and len(self.insn.operands) != 0:
            l.error("Operand parsing failed for instruction %s at address %x", str(self.insn), self.insn.address)
            return

    @staticmethod
    def split_arm_op_string(op_str: str):
        # Split arm operand string with commas outside the square brackets
        pieces = []
        in_square_brackets = False
        cur_opr = ""
        for c in op_str:
            if c == "[":
                in_square_brackets = True
            if c == "]":
                in_square_brackets = False
            if c == "," and not in_square_brackets:
                pieces.append(cur_opr)
                cur_opr = ""
                continue
            if c == " ":
                continue
            cur_opr += c
        if cur_opr:
            pieces.append(cur_opr)
        return pieces

    def dissect_instruction_by_default(self):
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
            if c == "":
                i -= 1
                continue

            if cur_operand is None:
                cur_operand = []
                self.operands.append(cur_operand)

            # Check if this is a number or an identifier.
            ordc = ord(c[0])
            # pylint:disable=too-many-boolean-expressions
            if 0x30 <= ordc <= 0x39 or 0x41 <= ordc <= 0x5A or 0x61 <= ordc <= 0x7A:
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
                    prefix = ""
                    if i > 0 and insn_pieces[i - 1] in ("$", "%"):
                        prefix = insn_pieces[i - 1]
                        insn_pieces[i - 1] = ""
                    cur_operand.append(Register(c, prefix))
                elif intc is not None:
                    with_sign = False
                    if i > 0 and insn_pieces[i - 1] in ("+", "-"):
                        with_sign = True
                        if insn_pieces[i - 1] == "-":
                            intc = -intc  # pylint: disable=invalid-unary-operand-type
                        insn_pieces[i - 1] = ""
                    cur_operand.append(Value(intc, with_sign))
                else:
                    cur_operand.append(c)

            elif c == "," and not nested_mem:
                cs_op_num -= 1
                cur_operand = None

            elif c == ":":  # XXX this is a hack! fix this later
                insn_pieces[i - 1] += ":"

            else:
                # Check if we are inside braces or parentheses. Do not forget
                # that we are iterating in reverse order!
                if c == "]" or c == ")":
                    nested_mem = True

                elif c == "[" or c == "(":
                    nested_mem = False

                if cur_operand is None:
                    cur_operand = [c]
                    self.operands.append(cur_operand)
                else:
                    cur_operand.append(c if c[0] != "," else c + " ")

            i -= 1

        self.opcode = Opcode(self)
        self.operands.reverse()

        if not hasattr(self.insn, "operands"):
            # Not all disassemblers provide operands. Just use our smart split
            for i, o in enumerate(self.operands):
                o.reverse()
                self.operands[i] = Operand.build(1, i, o, self)
            return

        if len(self.operands) != len(self.insn.operands):
            l.error(
                "Operand parsing failed for instruction %s. %d operands are parsed, while %d are expected.",
                str(self.insn),
                len(self.operands),
                len(self.insn.operands),
            )
            self.operands = []
            return

        for i, o in enumerate(self.operands):
            o.reverse()
            self.operands[i] = Operand.build(self.insn.operands[i].type, i, o, self)

    @staticmethod
    def split_op_string(insn_str):
        pieces = []
        in_word = False
        for c in insn_str:
            if c.isspace():
                in_word = False
                continue
            if c.isalnum():
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
        return [
            "{} {}".format(self.opcode.render(formatting)[0], ", ".join(o.render(formatting)[0] for o in self.operands))
        ]


class SootExpression(DisassemblyPiece):
    def __init__(self, expr):
        self.expr = expr

    def _render(self, formatting=None):
        return [self.expr]


class SootExpressionTarget(SootExpression):
    def __init__(self, target_stmt_idx):
        super().__init__(target_stmt_idx)
        self.target_stmt_idx = target_stmt_idx

    def _render(self, formatting=None):
        return ["Goto %d" % self.target_stmt_idx]


class SootExpressionStaticFieldRef(SootExpression):
    def __init__(self, field):
        field_str = ".".join(field)
        super().__init__(field_str)
        self.field = field
        self.field_str = field_str

    def _render(self, formatting=None):
        return [self.field_str]


class SootExpressionInvoke(SootExpression):
    Virtual = "virtual"
    Static = "static"
    Special = "special"

    def __init__(self, invoke_type, expr):
        super().__init__(str(expr))

        self.invoke_type = invoke_type
        self.base = str(expr.base) if self.invoke_type in (self.Virtual, self.Special) else ""
        self.method_name = expr.method_name
        self.arg_str = expr.list_to_arg_str(expr.args)

    def _render(self, formatting=None):
        return [
            "{}{}({}) [{}]".format(
                self.base + "." if self.base else "", self.method_name, self.arg_str, self.invoke_type
            )
        ]


class SootStatement(DisassemblyPiece):
    def __init__(self, block_addr, raw_stmt):
        self.addr = block_addr.copy()
        self.addr.stmt_idx = raw_stmt.label
        self.raw_stmt = raw_stmt

        self.components = []

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
        return [
            " ".join(
                [
                    component if type(component) is str else component.render(formatting=formatting)[0]
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


class Opcode(DisassemblyPiece):
    def __init__(self, parentinsn):
        self.addr = parentinsn.addr
        self.insn = parentinsn.insn
        self.parentinsn = parentinsn
        self.opcode_string = self.insn.mnemonic
        self.ident = (self.addr, "opcode")

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
        self.ident = (self.addr, "operand", self.op_num)

        for i, c in enumerate(self.children):
            if type(c) not in (bytes, str):
                c.ident = (self.addr, "operand piece", self.op_num, i)
                c.parentop = self

    @property
    def cs_operand(self):
        return self.parentinsn.insn.operands[self.op_num]

    def _render(self, formatting):
        return [
            "".join(
                x if type(x) is str else x.decode() if type(x) is bytes else x.render(formatting)[0]
                for x in self.children
            )
        ]

    @staticmethod
    def build(operand_type, op_num, children, parentinsn):
        # Maps capstone operand types to operand classes
        MAPPING = {
            0: Operand,  # default type for operand that haven't been fully implemented
            1: RegisterOperand,
            2: ConstantOperand,
            3: MemoryOperand,
            4: Operand,  # ARM FP
            64: Operand,  # ARM CIMM
            65: Operand,  # ARM PIMM   | ARM64 REG_MRS
            66: Operand,  # ARM SETEND | ARM64 REG_MSR
            67: Operand,  # ARM SYSREG | ARM64 PSTATE
            68: Operand,  # ARM64 SYS
            69: Operand,  # ARM64 PREFETCH
            70: Operand,  # ARM64 BARRIER
        }

        cls = MAPPING.get(operand_type, None)
        if cls is None:
            raise ValueError("Unknown capstone operand type %s." % operand_type)

        operand = cls(op_num, children, parentinsn)

        # Post-processing
        if cls is MemoryOperand and parentinsn.arch.name in {"AMD64"} and len(operand.values) == 2:
            op0, op1 = operand.values
            if type(op0) is Register and op0.is_ip and type(op1) is Value:
                # Indirect addressing in x86_64
                # 400520  push [rip+0x200782] ==>  400520  push [0x600ca8]
                absolute_addr = parentinsn.addr + parentinsn.size + op1.val
                return MemoryOperand(1, operand.prefix + ["[", Value(absolute_addr, False), "]"], parentinsn)

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
            try:
                custom_value_str = formatting["custom_values_str"][self.ident]
            except KeyError:
                pass

        if custom_value_str:
            return [custom_value_str]
        else:
            return super()._render(formatting)


class MemoryOperand(Operand):
    def __init__(self, op_num, children, parentinsn):
        super().__init__(op_num, children, parentinsn)

        # a typical "children" looks like the following:
        # [ 'dword', 'ptr', '[', Register, Value, ']' ]
        # or
        # [ '[', Register, ']' ]
        # or
        # [ Value, '(', Regsiter, ')' ]

        # it will be converted into more meaningful and Pythonic properties

        self.segment_selector = None
        self.prefix = []
        self.suffix_str = ""  # could be arm pre index mark "!"
        self.values = []
        self.offset = []
        # offset_location
        # - prefix: -0xff00($gp)
        # - before_value: 0xff00+rax
        # - after_value: rax+0xff00
        self.offset_location = "after_value"
        # values_style
        # - square: [rax+0x10]
        # - curly: {rax+0x10}
        # - paren: (rax+0x10)
        self.values_style = "square"

        try:
            if "[" in self.children:
                self._parse_memop_squarebracket()
            elif "(" in self.children:
                self._parse_memop_paren()
            else:
                raise ValueError()

        except ValueError:
            l.error("Failed to parse operand children %s. Please report to Fish.", self.children)

            # setup all dummy properties
            self.prefix = None
            self.values = None

    def _parse_memop_squarebracket(self):
        if self.children[0] != "[":
            try:
                square_bracket_pos = self.children.index("[")
            except ValueError:  # pylint: disable=try-except-raise
                raise

            self.prefix = self.children[:square_bracket_pos]

            # take out segment selector
            if len(self.prefix) == 3:
                self.segment_selector = self.prefix[-1]
                self.prefix = self.prefix[:-1]
            else:
                self.segment_selector = None

        else:
            # empty
            square_bracket_pos = 0
            self.prefix = []
            self.segment_selector = None

        close_square_pos = len(self.children) - 1
        if self.children[-1] != "]":
            if self.children[-1] == "!" and self.children[-2] == "]":
                # arm64 pre index
                self.suffix_str = "!"
                close_square_pos -= 1
            else:
                raise ValueError()

        self.values = self.children[square_bracket_pos + 1 : close_square_pos]

    def _parse_memop_paren(self):
        offset = []
        self.values_style = "paren"

        if self.children[0] != "(":
            try:
                paren_pos = self.children.index("(")
            except ValueError:  # pylint: disable=try-except-raise
                raise

            if all(isinstance(item, str) for item in self.children[:paren_pos]):
                # parse prefix
                self.prefix = self.children[:paren_pos]
            elif all(isinstance(item, Value) for item in self.children[:paren_pos]):
                # parse offset
                # force each piece to be rendered with its sign (+/-)
                offset += self.children[:paren_pos]
                # offset appears before the left parenthesis
                self.offset_location = "prefix"

        else:
            paren_pos = 0
            self.prefix = []
            self.segment_selector = None

        self.values = self.children[paren_pos + 1 : len(self.children) - 1]
        self.offset = offset

    def _render(self, formatting):
        if self.prefix is None:
            # we failed in parsing. use the default rendering
            return super()._render(formatting)
        else:
            values_style = self.values_style
            show_prefix = True
            custom_values_str = None

            if formatting is not None:
                try:
                    values_style = formatting["values_style"][self.ident]
                except KeyError:
                    pass

                try:
                    show_prefix_str = formatting["show_prefix"][self.ident]
                    if show_prefix_str in ("false", "False"):
                        show_prefix = False
                except KeyError:
                    pass

                try:
                    custom_values_str = formatting["custom_values_str"][self.ident]
                except KeyError:
                    pass

            prefix_str = " ".join(self.prefix) + " " if show_prefix and self.prefix else ""
            if custom_values_str is not None:
                value_str = custom_values_str
            else:
                value_str = "".join(
                    x.render(formatting)[0] if not isinstance(x, (bytes, str)) else x for x in self.values
                )

            if values_style == "curly":
                left_paren, right_paren = "{", "}"
            elif values_style == "paren":
                left_paren, right_paren = "(", ")"
            else:  # square
                left_paren, right_paren = "[", "]"

            if self.offset:
                offset_str = "".join(
                    x.render(formatting)[0] if not isinstance(x, (bytes, str)) else x for x in self.offset
                )

                # combine values and offsets according to self.offset_location
                if self.offset_location == "prefix":
                    value_str = "".join([offset_str, left_paren, value_str, right_paren])
                elif self.offset_location == "before_value":
                    value_str = "".join([left_paren, offset_str, value_str, right_paren])
                else:  # after_value
                    value_str = "".join([left_paren, value_str, offset_str, right_paren])
            else:
                value_str = left_paren + value_str + right_paren

            segment_selector_str = "" if self.segment_selector is None else self.segment_selector

            if segment_selector_str and prefix_str:
                prefix_str += " "

            return [f"{prefix_str}{segment_selector_str}{value_str}{self.suffix_str}"]


class OperandPiece(DisassemblyPiece):  # pylint: disable=abstract-method
    # These get filled in later...
    addr = None
    parentop = None
    ident = None


class Register(OperandPiece):
    def __init__(self, reg, prefix=""):
        self.reg = reg
        self.prefix = prefix
        self.is_ip = self.reg in {"eip", "rip", "pc"}  # TODO: Support more architectures

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
                style = formatting["int_styles"][self.ident]
                if style[0] == "hex":
                    if self.render_with_sign:
                        return ["%#+x" % self.val]
                    else:
                        return ["%#x" % self.val]
                elif style[0] == "dec":
                    if self.render_with_sign:
                        return ["%+d" % self.val]
                    else:
                        return [str(self.val)]
                elif style[0] == "label":
                    labeloffset = style[1]
                    if labeloffset == 0:
                        lbl = self.project.kb.labels[self.val]
                        return [lbl]
                    return [
                        "{}{}{:#+x}".format(
                            "+" if self.render_with_sign else "",
                            self.project.kb.labels[self.val + labeloffset],
                            labeloffset,
                        )
                    ]
            except KeyError:
                pass

        # default case
        try:
            func = self.project.kb.functions.get_by_addr(self.val)
        except KeyError:
            func = None

        if self.val in self.project.kb.labels:
            lbl = self.project.kb.labels[self.val]
            if func is not None:
                # see if lbl == func.name and func.demangled_name != func.name. if so, we prioritize the
                # demangled name
                if lbl == func.name and func.name != func.demangled_name:
                    normalized_name = get_cpp_function_name(func.demangled_name, specialized=False, qualified=True)
                    return [normalized_name]
            return [("+" if self.render_with_sign else "") + lbl]
        elif func is not None:
            return [func.demangled_name]
        else:
            if self.render_with_sign:
                return ["%#+x" % self.val]
            else:
                return ["%#x" % self.val]


class Comment(DisassemblyPiece):
    def __init__(self, addr, text):
        self.addr = addr
        self.text = text.split("\n")

    def _render(self, formatting=None):
        return [self.text]

    def height(self, formatting):
        lines = len(self.text)
        return 0 if lines == 1 else lines


class FuncComment(DisassemblyPiece):
    def __init__(self, func):
        self.func = func

    def _render(self, formatting=None):
        return ["##", "## Function " + self.func.name, "##"]


class Disassembly(Analysis):
    """
    Produce formatted machine code disassembly.
    """

    def __init__(
        self,
        function: Function | None = None,
        ranges: Sequence[tuple[int, int]] | None = None,
        thumb: bool = False,
        include_ir: bool = False,
        block_bytes: bytes | None = None,
    ):
        self.raw_result = []
        self.raw_result_map = {
            "block_starts": {},
            "comments": {},
            "labels": {},
            "instructions": {},
            "hooks": {},
            "ir": defaultdict(list),
        }
        self.block_to_insn_addrs = defaultdict(list)
        self._func_cache = {}
        self._include_ir = include_ir
        self._block_bytes = block_bytes
        self._graph = None

        if function is not None:
            # sort them by address, put hooks before nonhooks
            self._graph = function.graph
            blocks = sorted(function.graph.nodes(), key=lambda node: (node.addr, not node.is_hook))
            for block in blocks:
                self.parse_block(block)
        elif ranges is not None:
            cfg = self.project.kb.cfgs.get_most_accurate()
            fallback = True
            if self._block_bytes is None and cfg is not None:
                try:
                    self._graph = cfg.graph
                    for start, end in ranges:
                        if start == end:
                            continue
                        assert start < end

                        # Grab all blocks that intersect target range
                        blocks = sorted(
                            [
                                n.to_codenode()
                                for n in self._graph.nodes()
                                if not (n.addr + (n.size or 1) <= start or n.addr >= end)
                            ],
                            key=lambda node: (node.addr, not node.is_hook),
                        )

                        # Trim blocks that are not within range
                        for i, block in enumerate(blocks):
                            if block.size and block.addr < start:
                                delta = start - block.addr
                                block_bytes = block.bytestr[delta:] if block.bytestr else None
                                blocks[i] = BlockNode(block.addr + delta, block.size - delta, block_bytes)
                        for i, block in enumerate(blocks):
                            real_block_addr = block.addr if not block.thumb else block.addr - 1
                            if block.size and real_block_addr + block.size > end:
                                delta = real_block_addr + block.size - end
                                block_bytes = block.bytestr[0:-delta] if block.bytestr else None
                                blocks[i] = BlockNode(block.addr, block.size - delta, block_bytes)

                        for block in blocks:
                            self.parse_block(block)
                    fallback = False
                except KeyError:
                    pass

            if fallback:
                # CFG not available, or the block cannot be found in the CFG (e.g., the block is dynamically
                # generated). Simply disassemble the code in the given regions. In the future we may want to handle
                # this case by automatically running CFG analysis on given ranges.
                for start, end in ranges:
                    self.parse_block(
                        BlockNode(
                            start,
                            end - start,
                            thumb=thumb,
                            bytestr=self._block_bytes if len(ranges) == 1 else None,
                        )
                    )

    def func_lookup(self, block):
        try:
            return self._func_cache[block.function.addr]
        except AttributeError:
            return None
        except KeyError:
            f = FunctionStart(block.function)
            self._func_cache[f.addr] = f
            return f

    def _add_instruction_to_results(self, block: BlockNode, insn: DisassemblerInsn, bs: BlockStart) -> None:
        """
        Add instruction to analysis results with associated labels and comments
        """
        if insn.address in self.kb.labels:
            label = Label(insn.address, self.kb.labels[insn.address])
            self.raw_result.append(label)
            self.raw_result_map["labels"][label.addr] = label
        if insn.address in self.kb.comments:
            comment = Comment(insn.address, self.kb.comments[insn.address])
            self.raw_result.append(comment)
            self.raw_result_map["comments"][comment.addr] = comment
        instruction = Instruction(insn, bs)
        self.raw_result.append(instruction)
        self.raw_result_map["instructions"][instruction.addr] = instruction
        self.block_to_insn_addrs[block.addr].append(insn.address)

    def _add_block_ir_to_results(self, block: BlockNode, irsb: IRSBType) -> None:
        """
        Add lifter IR for this block
        """
        addr_to_ops_map = self.raw_result_map["ir"]
        addr = block.addr
        ops = addr_to_ops_map[addr]

        if irsb.statements is not None:
            if pcode is not None and isinstance(self.project.factory.default_engine, pcode.HeavyPcodeMixin):
                addr = None
                stmt_idx = 0
                for op in irsb._ops:
                    if op.opcode == pypcode.OpCode.IMARK:
                        addr = op.inputs[0].offset
                    else:
                        addr_to_ops_map[addr].append(IROp(addr, stmt_idx, op, irsb))
                    stmt_idx += 1
            else:
                for seq, stmt in enumerate(irsb.statements):
                    if isinstance(stmt, pyvex.stmt.IMark):
                        addr = stmt.addr
                        ops = addr_to_ops_map[addr]
                    else:
                        ops.append(IROp(addr, seq, stmt, irsb))

    def parse_block(self, block: BlockNode) -> None:
        """
        Parse instructions for a given block node
        """
        func = self.func_lookup(block)
        if func and func.addr == block.addr:
            self.raw_result.append(FuncComment(block.function))
            self.raw_result.append(func)
        bs = BlockStart(block, func, self.project)
        self.raw_result.append(bs)

        if block.is_hook:
            hook = Hook(block)
            self.raw_result.append(hook)
            self.raw_result_map["hooks"][block.addr] = hook
        elif self.project.arch.capstone_support:
            # Prefer Capstone first, where we are able to extract a bit more
            # about the operands
            if block.thumb:
                aligned_block_addr = (block.addr >> 1) << 1
                cs = self.project.arch.capstone_thumb
            else:
                aligned_block_addr = block.addr
                cs = self.project.arch.capstone
            if block.bytestr is None:
                bytestr = self.project.factory.block(aligned_block_addr, block.size).bytes
            else:
                bytestr = block.bytestr
            self.block_to_insn_addrs[block.addr] = []
            for cs_insn in cs.disasm(bytestr, block.addr):
                self._add_instruction_to_results(block, CapstoneInsn(cs_insn), bs)
        elif pcode is not None and isinstance(self.project.factory.default_engine, pcode.HeavyPcodeMixin):
            # When using the P-code engine, we can fall back on its disassembly
            # in the event that Capstone does not support it
            self.block_to_insn_addrs[block.addr] = []
            b = self.project.factory.block(block.addr, size=block.size)
            for insn in b.disassembly.insns:
                self._add_instruction_to_results(block, insn, bs)
        elif type(block) is SootBlockNode:
            for raw_stmt in block.stmts:
                stmt = SootStatement(block.addr, raw_stmt)
                self.raw_result.append(stmt)
                self.raw_result_map["instructions"][stmt.addr] = stmt
                self.block_to_insn_addrs[block.addr].append(stmt.addr)
        else:
            raise AngrTypeError(
                f"Cannot disassemble block with architecture {self.project.arch} for block type {type(block)}"
            )

        if self._include_ir:
            b = self.project.factory.block(block.addr, size=block.size)
            self._add_block_ir_to_results(block, b.vex)

    def render(
        self,
        formatting=None,
        show_edges: bool = True,
        show_addresses: bool = True,
        show_bytes: bool = False,
        ascii_only: bool | None = None,
        color: bool = True,
    ) -> str:
        """
        Render the disassembly to a string, with optional edges and addresses.

        Color will be added by default, if enabled. To disable color pass an empty formatting dict.
        """
        max_bytes_per_line = 5
        bytes_width = max_bytes_per_line * 3 + 1
        a2ln = defaultdict(list)
        buf = []

        if formatting is None:
            formatting = {
                "colors": (
                    {
                        "address": "gray",
                        "bytes": "cyan",
                        "edge": "yellow",
                        Label: "bright_yellow",
                        ConstantOperand: "cyan",
                        MemoryOperand: "yellow",
                        Comment: "gray",
                        Hook: "green",
                    }
                    if ansi_color_enabled and color
                    else {}
                ),
                "format_callback": lambda item, s: ansi_color(s, formatting["colors"].get(type(item), None)),
            }

        def col(item: Any) -> str | None:
            try:
                return formatting["colors"][item]
            except KeyError:
                return None

        def format_address(addr: int, color: bool = True) -> str:
            if not show_addresses:
                return ""
            a, pad = f"{addr:x}", "  "
            return (ansi_color(a, col("address")) if color else a) + pad

        def format_bytes(data: bytes, color: bool = True) -> str:
            s = " ".join(f"{x:02x}" for x in data).ljust(bytes_width)
            return ansi_color(s, col("bytes")) if color else s

        def format_comment(text: str, color: bool = True) -> str:
            s = " ; " + text
            return ansi_color(s, col(Comment)) if color else s

        comment = None

        for item in self.raw_result:
            if isinstance(item, BlockStart):
                if len(buf) > 0:
                    buf.append("")
            elif isinstance(item, Label):
                pad = len(format_address(item.addr, False)) * " "
                if show_bytes:
                    pad += bytes_width * " "
                buf.append(pad + item.render(formatting)[0])
            elif isinstance(item, Comment):
                comment = item
            elif isinstance(item, Hook):
                a2ln[item.addr].append(len(buf))
                buf.append(format_address(item.addr) + item.render(formatting)[0])
            elif isinstance(item, Instruction):
                a2ln[item.addr].append(len(buf))
                lines = []

                # Chop instruction bytes into line segments
                p, insn_bytes = 0, []
                while show_bytes and p < len(item.insn.bytes):
                    s = item.insn.bytes[p : p + min(len(item.insn.bytes) - p, max_bytes_per_line)]
                    p += len(s)
                    insn_bytes.append(s)

                # Format the instruction's address, bytes, disassembly, and comment
                s_plain = format_address(item.addr, False)
                s = format_address(item.addr)
                if show_bytes:
                    bytes_column = len(s_plain)
                    s_plain += format_bytes(insn_bytes[0], False)
                    s += format_bytes(insn_bytes[0])
                s_plain += item.render()[0]
                s += item.render(formatting)[0]
                if comment is not None:
                    comment_column = len(s_plain)
                    s += format_comment(comment.text[0])
                lines.append(s)

                # Add additional lines of instruction bytes
                for i in range(1, len(insn_bytes)):
                    lines.append(" " * bytes_column + format_bytes(insn_bytes[i]))

                # Add additional lines of comments
                if comment is not None:
                    for i in range(1, len(comment.text)):
                        if len(lines) <= i:
                            lines.append(" " * comment_column)
                        lines[i] += format_comment(comment.text[i])
                    comment = None

                buf.extend(lines)
            else:
                buf.append("".join(item.render(formatting)))

        if self._graph is not None and show_edges and buf:
            edges_by_line = set()
            for edge in self._graph.edges.items():
                from_block, to_block = edge[0]
                if from_block.size is None:
                    continue
                if to_block.addr != from_block.addr + from_block.size:
                    from_addr = edge[1]["ins_addr"]
                    to_addr = to_block.addr
                    if not (from_addr in a2ln and to_addr in a2ln):
                        continue
                    for f in a2ln[from_addr]:
                        for t in a2ln[to_addr]:
                            edges_by_line.add((f, t))

            # Render block edges, to a reference buffer for tracking and output buffer for display
            edge_buf = ["" for _ in buf]
            ref_buf = ["" for _ in buf]
            edge_col = col("edge")
            for f, t in sorted(edges_by_line, key=lambda e: abs(e[0] - e[1])):
                add_edge_to_buffer(edge_buf, ref_buf, f, t, lambda s: ansi_color(s, edge_col), ascii_only=ascii_only)
                add_edge_to_buffer(ref_buf, ref_buf, f, t, ascii_only=ascii_only)
            max_edge_depth = max(map(len, ref_buf))

            # Justify edge and combine with disassembly
            for i, line in enumerate(buf):
                buf[i] = " " * (max_edge_depth - len(ref_buf[i])) + edge_buf[i] + line

        return "\n".join(buf)


from angr.analyses import AnalysesHub

AnalysesHub.register_default("Disassembly", Disassembly)
