# pylint:disable=no-self-use,unused-argument
from typing import Set, Tuple

import pyvex

from angr.engines.light import SimEngineLightVEXMixin


class IRSBRegisterCollector(SimEngineLightVEXMixin):
    """
    Scan the VEX IRSB to collect all registers that are read.
    """

    def __init__(self, block, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.block = block
        self.reg_reads: Set[Tuple[int, int]] = set()

    def process(self):
        self.tmps = {}
        self.tyenv = self.block.vex.tyenv

        self._process_Stmt()

        self.stmt_idx = None
        self.ins_addr = None

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
        super()._handle_WrTmp(stmt)

    def _handle_Get(self, expr: pyvex.IRExpr.Get):
        self.reg_reads.add((expr.offset, expr.result_size(self.tyenv)))

    def _handle_RdTmp(self, expr):
        pass

    def _handle_Conversion(self, expr: pyvex.IRExpr.Unop):
        pass

    def _handle_16HLto32(self, expr):
        pass

    def _handle_Cmp_v(self, expr, _vector_size, _vector_count):
        pass

    _handle_CmpEQ_v = _handle_Cmp_v
    _handle_CmpNE_v = _handle_Cmp_v
    _handle_CmpLE_v = _handle_Cmp_v
    _handle_CmpLT_v = _handle_Cmp_v
    _handle_CmpGE_v = _handle_Cmp_v
    _handle_CmpGT_v = _handle_Cmp_v

    def _handle_ExpCmpNE64(self, expr):
        pass

    def _handle_CCall(self, expr):
        pass

    def _handle_function(self, func_addr):
        pass
