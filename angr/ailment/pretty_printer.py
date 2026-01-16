"""
Pretty printer for AIL blocks, expressions, and statements.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

from rich.console import Console
from rich.text import Text

from .expression import (
    Const,
    Tmp,
    Register,
    VirtualVariable,
    VirtualVariableCategory,
    Phi,
    UnaryOp,
    Convert,
    Reinterpret,
    BinaryOp,
    Load,
    ITE,
    DirtyExpression,
    VEXCCallExpression,
    MultiStatementExpression,
    BasePointerOffset,
    StackBaseOffset,
)
from .statement import (
    Assignment,
    WeakAssignment,
    Store,
    Jump,
    ConditionalJump,
    Call,
    Return,
    DirtyStatement,
    Label,
)

if TYPE_CHECKING:
    from .block import Block
    from .expression import Expression
    from .statement import Statement


_BINARY_OP_SYMBOLS = {
    "Add": "+",
    "Sub": "-",
    "Mul": "*",
    "Div": "/",
    "DivMod": "/%",
    "And": "&",
    "Or": "|",
    "Xor": "^",
    "Shl": "<<",
    "Shr": ">>",
    "Sar": ">>a",
    "CmpEQ": "==",
    "CmpNE": "!=",
    "CmpLT": "<",
    "CmpLE": "<=",
    "CmpGT": ">",
    "CmpGE": ">=",
}


class AILPrettyPrinter:
    """
    Pretty printer for AIL blocks, expressions, and statements.
    """

    STYLE_CONST = "yellow"
    STYLE_TEMP = "blue"
    STYLE_REGISTER = "cyan"
    STYLE_STACK = "cyan"
    STYLE_MEMORY = "cyan"
    STYLE_KEYWORD = "magenta"
    STYLE_OPERATOR = "bright_white"
    STYLE_DELIMITER = "white"

    STYLE_BLOCK_HEADER = "bold cyan"
    STYLE_STMT_INDEX = "dim"
    STYLE_INS_ADDR = "dim"
    STYLE_SEPARATOR = "dim"

    def __init__(self):
        self.text: Text = Text()

    def _const(self, s: str) -> None:
        self.text.append(s, style=self.STYLE_CONST)

    def _temp(self, s: str) -> None:
        self.text.append(s, style=self.STYLE_TEMP)

    def _register(self, s: str) -> None:
        self.text.append(s, style=self.STYLE_REGISTER)

    def _stack(self, s: str) -> None:
        self.text.append(s, style=self.STYLE_STACK)

    def _memory(self, s: str) -> None:
        self.text.append(s, style=self.STYLE_MEMORY)

    def _keyword(self, s: str) -> None:
        self.text.append(s, style=self.STYLE_KEYWORD)

    def _operator(self, s: str) -> None:
        self.text.append(s, style=self.STYLE_OPERATOR)

    def _delimiter(self, s: str) -> None:
        self.text.append(s, style=self.STYLE_DELIMITER)

    def _plain(self, s: str) -> None:
        self.text.append(s)

    def _append_kwarg(self, name: str, first: bool = False) -> None:
        if not first:
            self._delimiter(", ")
        self._plain(name)
        self._operator("=")

    def format_statement(self, stmt: Statement) -> None:
        handler = getattr(self, f"_stmt_{type(stmt).__name__}", None)
        if handler:
            handler(stmt)
        else:
            self._plain(str(stmt))

    def format_expression(self, expr: Expression) -> None:
        handler = getattr(self, f"_expr_{type(expr).__name__}", None)
        if handler:
            handler(expr)
        else:
            self._plain(str(expr))

    def _expr_Const(self, expr: Const) -> None:
        if isinstance(expr.value, int):
            self._const(f"{expr.value:#x}<{expr.bits}>")
        elif isinstance(expr.value, float):
            self._const(f"{expr.value:f}<{expr.bits}>")
        else:
            self._const(f"{expr.value}<{expr.bits}>")

    def _expr_Tmp(self, expr: Tmp) -> None:
        self._temp(f"t{expr.tmp_idx}")

    def _expr_Register(self, expr: Register) -> None:
        reg_name = getattr(expr, "reg_name", None)
        if reg_name is not None:
            self._register(f"{reg_name}<{expr.bits // 8}>")
        elif expr.variable is None:
            self._register(f"reg_{expr.reg_offset}<{expr.bits // 8}>")
        else:
            self._register(f"{expr.variable.name!s}")

    def _expr_VirtualVariable(self, expr: VirtualVariable) -> None:
        if expr.category == VirtualVariableCategory.REGISTER:
            self._register(str(expr))
        elif expr.category == VirtualVariableCategory.STACK:
            self._stack(str(expr))
        elif expr.category == VirtualVariableCategory.MEMORY:
            self._memory(str(expr))
        elif expr.category == VirtualVariableCategory.TMP:
            self._temp(str(expr))
        else:
            self._plain(str(expr))

    def _expr_Phi(self, expr: Phi) -> None:
        self._keyword("Phi")
        self._delimiter("(")
        self._delimiter("[")
        for i, (src, vvar) in enumerate(expr.src_and_vvars):
            if i > 0:
                self._delimiter(", ")
            addr, idx = src
            if idx is None:
                self._const(f"{addr:#x}")
            else:
                self._const(f"{addr:#x}.{idx}")
            self._delimiter(": ")
            if vvar is not None:
                self.format_expression(vvar)
            else:
                self._plain("None")
        self._delimiter("]")
        self._delimiter(")")

    def _expr_UnaryOp(self, expr: UnaryOp) -> None:
        self._operator(expr.op)
        self._delimiter("(")
        self.format_expression(expr.operand)
        self._delimiter(")")

    def _expr_Convert(self, expr: Convert) -> None:
        from_type = "I" if expr.from_type == Convert.TYPE_INT else "F"
        to_type = "I" if expr.to_type == Convert.TYPE_INT else "F"
        self._keyword("Conv")
        self._delimiter("(")
        self._plain(f"{expr.from_bits}{from_type}")
        self._operator("->")
        if expr.is_signed:
            self._plain("s")
        self._plain(f"{expr.to_bits}{to_type}")
        self._delimiter(", ")
        self.format_expression(expr.operand)
        self._delimiter(")")

    def _expr_Reinterpret(self, expr: Reinterpret) -> None:
        self._keyword("Reinterpret")
        self._delimiter("(")
        self._plain(f"{expr.from_bits}")
        self._operator("->")
        self._plain(f"{expr.to_bits}")
        self._delimiter(", ")
        self.format_expression(expr.operand)
        self._delimiter(")")

    def _expr_BinaryOp(self, expr: BinaryOp) -> None:
        op_sym = _BINARY_OP_SYMBOLS.get(expr.op, expr.op)
        self._delimiter("(")
        self.format_expression(expr.operands[0])
        self._operator(f" {op_sym} ")
        self.format_expression(expr.operands[1])
        self._delimiter(")")

    def _expr_Load(self, expr: Load) -> None:
        self._keyword("Load")
        self._delimiter("(")
        self._append_kwarg("addr", first=True)
        self.format_expression(expr.addr)
        self._append_kwarg("size")
        self._const(str(expr.size))
        self._append_kwarg("endness")
        self._plain(str(expr.endness))
        self._delimiter(")")

    def _expr_ITE(self, expr: ITE) -> None:
        self._keyword("ITE")
        self._delimiter("(")
        self.format_expression(expr.cond)
        self._delimiter(", ")
        self.format_expression(expr.iftrue)
        self._delimiter(", ")
        self.format_expression(expr.iffalse)
        self._delimiter(")")

    def _expr_DirtyExpression(self, expr: DirtyExpression) -> None:
        self._keyword("DIRTY")
        self._delimiter("(")
        self._plain(str(expr))
        self._delimiter(")")

    def _expr_VEXCCallExpression(self, expr: VEXCCallExpression) -> None:
        self._keyword(expr.callee)
        self._delimiter("(")
        for i, operand in enumerate(expr.operands):
            if i > 0:
                self._delimiter(", ")
            self.format_expression(operand)
        self._delimiter(")")

    def _expr_MultiStatementExpression(self, expr: MultiStatementExpression) -> None:
        self._delimiter("{")
        for i, stmt in enumerate(expr.stmts):
            if i > 0:
                self._delimiter("; ")
            self.format_statement(stmt)
        self._operator(" => ")
        self.format_expression(expr.expr)
        self._delimiter("}")

    def _expr_StackBaseOffset(self, expr: StackBaseOffset) -> None:
        self._stack(str(expr))

    def _expr_BasePointerOffset(self, expr: BasePointerOffset) -> None:
        self._memory(str(expr))

    def _stmt_Assignment(self, stmt: Assignment) -> None:
        self.format_expression(stmt.dst)
        self._operator(" = ")
        self.format_expression(stmt.src)

    def _stmt_WeakAssignment(self, stmt: WeakAssignment) -> None:
        self.format_expression(stmt.dst)
        self._operator(" =w ")
        self.format_expression(stmt.src)

    def _stmt_Store(self, stmt: Store) -> None:
        self._keyword("Store")
        self._delimiter("(")
        self._append_kwarg("addr", first=True)
        self.format_expression(stmt.addr)
        self._append_kwarg("data")
        self.format_expression(stmt.data)
        self._append_kwarg("size")
        self._const(str(stmt.size))
        self._append_kwarg("endness")
        self._plain(str(stmt.endness))
        self._append_kwarg("guard")
        if stmt.guard is not None:
            self.format_expression(stmt.guard)
        else:
            self._plain("None")
        self._delimiter(")")

    def _stmt_Jump(self, stmt: Jump) -> None:
        self._keyword("Goto")
        self._delimiter("(")
        self.format_expression(stmt.target)
        self._delimiter(")")

    def _stmt_ConditionalJump(self, stmt: ConditionalJump) -> None:
        self._keyword("if")
        self._delimiter(" (")
        self.format_expression(stmt.condition)
        self._delimiter(") { ")
        if stmt.true_target is not None:
            self._keyword("Goto")
            self._plain(" ")
            self.format_expression(stmt.true_target)
            self._plain(" ")
        self._delimiter("} ")
        self._keyword("else")
        self._delimiter(" { ")
        if stmt.false_target is not None:
            self._keyword("Goto")
            self._plain(" ")
            self.format_expression(stmt.false_target)
            self._plain(" ")
        self._delimiter("}")

    def _stmt_Call(self, stmt: Call) -> None:
        self._keyword("Call")
        self._delimiter("(")
        if isinstance(stmt.target, str):
            self._keyword(stmt.target)
        else:
            self.format_expression(stmt.target)
        self._delimiter(", ")
        if stmt.calling_convention is not None:
            self._plain(str(stmt.calling_convention))
        else:
            self._plain("Unknown CC")
        self._delimiter(", ")
        self._plain("ret")
        self._delimiter(": ")
        if stmt.ret_expr is not None:
            self.format_expression(stmt.ret_expr)
        else:
            self._plain("None")
        self._delimiter(", ")
        self._plain("fp_ret")
        self._delimiter(": ")
        if stmt.fp_ret_expr is not None:
            self.format_expression(stmt.fp_ret_expr)
        else:
            self._plain("no-fp-ret-value")
        self._delimiter(")")

    def _stmt_Return(self, stmt: Return) -> None:
        self._keyword("return")
        if stmt.ret_exprs:
            self._plain(" ")
            for i, expr in enumerate(stmt.ret_exprs):
                if i > 0:
                    self._delimiter(", ")
                self.format_expression(expr)
        self._delimiter(";")

    def _stmt_DirtyStatement(self, stmt: DirtyStatement) -> None:
        self._keyword("DIRTY")
        self._delimiter("(")
        self._plain(str(stmt.dirty))
        self._delimiter(")")

    def _stmt_Label(self, stmt: Label) -> None:
        self._keyword(f"LABEL {stmt.name}")
        self._delimiter(":")

    def format_block(self, block: Block, show_ins_addr: bool = True, color: bool = True) -> None:
        console = Console(no_color=not color, highlight=False)

        header = f"## Block {block.addr:#x}"
        if block.idx:
            header += f".{block.idx}"
        console.print(header, style=self.STYLE_BLOCK_HEADER)

        for i, stmt in enumerate(block.statements):
            self.text = Text()
            self.text.append(f"{i:02d}", style=self.STYLE_STMT_INDEX)
            self.text.append(" | ", style=self.STYLE_SEPARATOR)

            if show_ins_addr:
                ins_addr = stmt.tags.get("ins_addr", 0) if hasattr(stmt, "tags") else 0
                self.text.append(f"{ins_addr:#x}", style=self.STYLE_INS_ADDR)
                self.text.append(" | ", style=self.STYLE_SEPARATOR)

            self.format_statement(stmt)
            console.print(self.text)
