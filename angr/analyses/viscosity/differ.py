from typing import List, Tuple, Optional

from pyvex.stmt import IRStmt, IMark, WrTmp, Exit, Store, Put
from pyvex.expr import IRExpr, Unop, Binop, Load, RdTmp, Const, Get


DiffType = Tuple[int,int,Optional[int],Optional[int]]  # stmt_idx, expr_idx, old_val, new_val


class VEXBlockDiffer:
    """
    Given two structurally equivalent VEX blocks, return a list of data differences.
    """
    def __init__(self, stmts0, stmts1, different_statements: Optional[List[int]]=None):
        self.stmts0 = stmts0
        self.stmts1 = stmts1
        self._different_statements = different_statements

        self.diffs = None

        if len(self.stmts0) != len(self.stmts1):
            raise ValueError("The two VEX blocks are not structurally equivalent.")

        self.diffs: List[DiffType] = [ ]
        for idx, (stmt0, stmt1) in enumerate(zip(self.stmts0, self.stmts1)):
            if not self._different_statements or idx in self._different_statements:
                self.diffs += self._handle_stmt(idx, stmt0, stmt1)

    def _handle_stmt(self, stmt_idx: int, stmt0: IRStmt, stmt1: IRStmt) -> List[DiffType]:
        _mapping = {
            IMark: self._handle_imark,
            WrTmp: self._handle_wrtmp,
            Exit: self._handle_exit,
            Store: self._handle_store,
            Put: self._handle_put,
        }

        if type(stmt0) is not type(stmt1):
            raise ValueError("The two VEX blocks are not structurally equivalent.")

        handler = _mapping.get(type(stmt0), None)
        if handler is None:
            return [ ]
        return handler(stmt_idx, stmt0, stmt1)

    def _handle_imark(self, stmt_idx: int, stmt0: IMark, stmt1: int) -> List[DiffType]:
        return [ ]

    def _handle_wrtmp(self, stmt_idx: int, stmt0: WrTmp, stmt1: WrTmp) -> List[DiffType]:
        return self._handle_expr(stmt_idx, 0, stmt0.data, stmt1.data)

    def _handle_exit(self, stmt_idx: int, stmt0: Exit, stmt1: Exit) -> List[DiffType]:
        if stmt0.dst.value == stmt1.dst.value:
            return [ ]
        else:
            return [(stmt_idx, 0, stmt0.dst.value, stmt1.dst.value)]

    def _handle_store(self, stmt_idx: int, stmt0: Store, stmt1: Store) -> List[DiffType]:
        lst = [ ]
        lst += self._handle_expr(stmt_idx, 0, stmt0.addr, stmt1.addr)
        lst += self._handle_expr(stmt_idx, 1, stmt0.data, stmt1.data)
        return lst

    def _handle_put(self, stmt_idx: int, stmt0: Put, stmt1: Put) -> List[DiffType]:
        lst = [ ]
        if stmt0.offset != stmt1.offset:
            # TODO: handle register differences properly
            lst.append((stmt_idx, 0, stmt0.offset, stmt1.offset))
        lst += self._handle_expr(stmt_idx, 1, stmt0.data, stmt1.data)
        return lst

    def _handle_expr(self, stmt_idx: int, expr_idx: int, expr0: IRExpr, expr1: IRExpr) -> List[DiffType]:
        _mapping = {
            Unop: self._handle_unop,
            Binop: self._handle_binop,
            Load: self._handle_load,
            RdTmp: self._handle_rdtmp,
            Const: self._handle_const,
            Get: self._handle_get,
        }

        if type(expr0) is not type(expr1):
            return [(stmt_idx, expr_idx, None, None)]

        handler = _mapping.get(type(expr0), None)
        if handler is None:
            return [ ]
        return handler(stmt_idx, expr_idx, expr0, expr1)

    def _handle_unop(self, stmt_idx: int, expr_idx: int, expr0: Unop, expr1: Unop) -> List[DiffType]:
        return self._handle_expr(stmt_idx, expr_idx, expr0.args[0], expr1.args[0])

    def _handle_binop(self, stmt_idx: int, expr_idx: int, expr0: Binop, expr1: Binop) -> List[DiffType]:
        lst = [ ]
        lst += self._handle_expr(stmt_idx, expr_idx + 0, expr0.args[0], expr1.args[0])
        lst += self._handle_expr(stmt_idx, expr_idx + 1, expr0.args[1], expr1.args[1])
        return lst

    def _handle_load(self, stmt_idx: int, expr_idx: int, expr0: Load, expr1: Load) -> List[DiffType]:
        return self._handle_expr(stmt_idx, expr_idx, expr0.addr, expr1.addr)

    def _handle_rdtmp(self, stmt_idx: int, expr_idx: int, expr0: RdTmp, expr1: RdTmp) -> List[DiffType]:
        return [ ]

    def _handle_const(self, stmt_idx: int, expr_idx: int, expr0: Const, expr1: Const) -> List[DiffType]:
        if expr0.con.value != expr1.con.value:
            return [(stmt_idx, expr_idx, expr0.con.value, expr1.con.value)]
        return [ ]

    def _handle_get(self, stmt_idx: int, expr_idx: int, expr0: Get, expr1: Get) -> List[DiffType]:
        # TODO: handle register differences properly
        return self._handle_expr(stmt_idx, expr_idx, expr0.offset, expr1.offset)
