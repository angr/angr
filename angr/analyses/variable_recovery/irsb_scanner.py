# pylint:disable=no-self-use,unused-argument
from typing import Set, Dict

import pyvex

from angr.engines.light import SimEngineLightVEXMixin


class VEXIRSBScanner(SimEngineLightVEXMixin):
    """
    Scan the VEX IRSB to determine if any argument-passing registers should be narrowed by detecting cases of loading
    the whole register and immediately narrowing the register before writing to the tmp.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # the following variables are for narrowing argument-passing register on 64-bit architectures. they are
        # initialized before processing each block.
        self.tmps_with_64bit_regs: Set[int] = set()  # tmps that store 64-bit register values
        self.tmps_converted_to_32bit: Set[int] = set()  # tmps that store the 64-to-32-bit converted values
        self.tmps_assignment_stmtidx: Dict[int, int] = {}  # statement IDs for the assignment of each tmp
        self.stmts_to_lower: Set[int] = set()

    def _process_Stmt(self, whitelist=None):
        self.tmps_with_64bit_regs = set()
        self.tmps_assignment_stmtidx = {}
        self.tmps_converted_to_32bit = set()

        super()._process_Stmt(whitelist=whitelist)

        self.stmts_to_lower = {self.tmps_assignment_stmtidx[i] for i in self.tmps_converted_to_32bit}

    def _handle_Put(self, stmt):
        pass

    def _handle_Load(self, expr):
        pass

    def _handle_Store(self, stmt):
        pass

    def _handle_LoadG(self, stmt):
        pass

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        pass

    def _handle_StoreG(self, stmt):
        pass

    def _handle_WrTmp(self, stmt):
        if isinstance(stmt.data, pyvex.IRExpr.Get) and stmt.data.result_size(self.tyenv) == 64:
            self.tmps_with_64bit_regs.add(stmt.tmp)
        self.tmps_assignment_stmtidx[stmt.tmp] = self.stmt_idx

        super()._handle_WrTmp(stmt)

    def _handle_Get(self, expr):
        pass

    def _handle_RdTmp(self, expr):
        if expr.tmp in self.tmps_converted_to_32bit:
            self.tmps_converted_to_32bit.remove(expr.tmp)

    def _handle_Conversion(self, expr: pyvex.IRExpr.Unop):
        if expr.op == "Iop_64to32" and isinstance(expr.args[0], pyvex.IRExpr.RdTmp):
            # special handling for t11 = GET:I64(rdi); t4 = 64to32(t11) style of code in x86-64 (and other 64-bit
            # architectures as well)
            tmp_src = expr.args[0].tmp
            if tmp_src in self.tmps_with_64bit_regs:
                self.tmps_converted_to_32bit.add(tmp_src)

    def _handle_CCall(self, expr):
        pass

    def _handle_function(self, func_addr):
        pass
