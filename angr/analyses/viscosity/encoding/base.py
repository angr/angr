from typing import List

from pyvex.stmt import IRStmt, IMark, WrTmp, Exit, Store, Put
from pyvex.expr import IRExpr, Binop, Unop, Triop, Load, RdTmp, Const, Get


class VEXStatementsSkeleton:
    """
    Describes a "skeleton" of a list of VEX statements.
    """
    def __init__(self, skeleton):
        self.skeleton: List[str] = skeleton

    @classmethod
    def from_block(cls, vex_block) -> 'VEXStatementsSkeleton':
        fallthrough_addr = vex_block.addr + vex_block.size
        return cls.from_statements(vex_block.statements, fallthrough_addr)

    @classmethod
    def from_statements(cls, stmts: List[IRStmt], fallthrough_addr: int) -> 'VEXStatementsSkeleton':
        skeleton: List[str] = []
        for stmt in stmts:
            s = cls._handle_stmt(stmt, fallthrough_addr)
            skeleton.append(s)
        return cls(skeleton)

    def __eq__(self, other):
        return isinstance(other, VEXStatementsSkeleton) and other.skeleton == self.skeleton

    def __hash__(self):
        return hash(";".join(self.skeleton))

    @classmethod
    def _handle_stmt(cls, stmt: IRStmt, fallthrough_addr: int) -> str:
        _mapping = {
            IMark: cls._handle_imark,
            WrTmp: cls._handle_wrtmp,
            Exit: cls._handle_exit,
            Store: cls._handle_store,
            Put: cls._handle_put,
        }

        handler = _mapping.get(type(stmt), None)
        if handler is None:
            return ""
        return handler(stmt, fallthrough_addr)

    @classmethod
    def _handle_imark(cls, stmt: IMark, fallthrough_addr: int) -> str:
        return "imark"

    @classmethod
    def _handle_wrtmp(cls, stmt: WrTmp, fallthrough_addr: int) -> str:
        return "t = {}".format(cls._handle_expr(stmt.data))

    @classmethod
    def _handle_exit(cls, stmt: Exit, fallthrough_addr: int) -> str:
        if stmt.dst.value == fallthrough_addr:
            return "exit-fallthrough"
        else:
            return "exit-elsewhere"

    @classmethod
    def _handle_store(cls, stmt: Store, fallthrough_addr: int) -> str:
        return "store(t) {}= {}".format(stmt.endness, cls._handle_expr(stmt.data))

    @classmethod
    def _handle_put(cls, stmt: Put, fallthrough_addr: int) -> str:
        return "put({}) = {}".format(stmt.offset, cls._handle_expr(stmt.data))

    @classmethod
    def _handle_expr(cls, expr: IRExpr) -> str:
        _mapping = {
            Unop: cls._handle_unop,
            Binop: cls._handle_binop,
            Load: cls._handle_load,
            RdTmp: cls._handle_rdtmp,
            Const: cls._handle_const,
            Get: cls._handle_get,
        }
        handler = _mapping.get(type(expr), None)
        if handler is None:
            return ""
        return handler(expr)

    @classmethod
    def _handle_unop(cls, expr: Unop) -> str:
        return "{}({})".format(expr.op[4:], cls._handle_expr(expr.args[0]))

    @classmethod
    def _handle_binop(cls, expr: Binop) -> str:
        return "{}({},{})".format(expr.op[4:], cls._handle_expr(expr.args[0]), cls._handle_expr(expr.args[1]))

    @classmethod
    def _handle_load(cls, expr: Load) -> str:
        return "load({},{})".format(expr.ty[4:], cls._handle_expr(expr.addr))

    @classmethod
    def _handle_rdtmp(cls, expr: RdTmp) -> str:
        return "t"

    @classmethod
    def _handle_const(cls, expr: Const) -> str:
        return "con"

    @classmethod
    def _handle_get(cls, expr: Get) -> str:
        return "get({},{})".format(expr.offset, expr.ty[4:])


class InstructionEncoding:
    """
    Describes how an instruction is translated to its VEX IR equivalence.
    """
    def __init__(self, instr: bytes, instr_mask: bytes, instr_text: str, vex_skeleton: VEXStatementsSkeleton):
        self.instr = instr
        self.instr_mask = instr_mask
        self.instr_text = instr_text
        self.vex_skeleton = vex_skeleton
