# pylint:disable=no-self-use,unused-argument

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
        self.tmps_with_64bit_regs: set[int] = set()  # tmps that store 64-bit register values
        self.tmps_converted_to_32bit: set[int] = set()  # tmps that store the 64-to-32-bit converted values
        self.tmps_assignment_stmtidx: dict[int, int] = {}  # statement IDs for the assignment of each tmp
        self.stmts_to_lower: set[int] = set()

        # the following variables are for recognizing redundant argument register reads in gcc(?) -O0 binaries.
        # e.g.,
        #    mov rdi, r9
        #    mov rdi, rax
        #
        # we will not create a variable for the register read in the first instruction (read from r9) in this case.
        self.tmp_with_reg_as_value: dict[int, int] = {}
        self.reg_with_reg_as_value: dict[int, int] = {}
        self.reg_read_stmt_id: dict[int, int] = {}
        self.reg_read_stmts_to_ignore: set[int] = set()

    def _top(self, size: int):
        return None

    def _is_top(self, expr) -> bool:
        return True

    def _process_Stmt(self, whitelist=None):
        self.tmps_with_64bit_regs = set()
        self.tmps_assignment_stmtidx = {}
        self.tmps_converted_to_32bit = set()

        super()._process_Stmt(whitelist=whitelist)

        self.stmts_to_lower = {self.tmps_assignment_stmtidx[i] for i in self.tmps_converted_to_32bit}

    def _handle_Put(self, stmt):
        if isinstance(stmt.data, pyvex.IRExpr.RdTmp) and stmt.data.tmp in self.tmp_with_reg_as_value:
            if (
                stmt.offset in self.reg_with_reg_as_value
                and self.reg_with_reg_as_value[stmt.offset] != self.tmp_with_reg_as_value[stmt.data.tmp]
            ):
                # we are overwriting an existing register with a value from another register, before this register is
                # ever used...
                # in this case, we should ignore the previous register read
                old_reg_offset = self.reg_with_reg_as_value[stmt.offset]
                self.reg_read_stmts_to_ignore.add(self.reg_read_stmt_id[old_reg_offset])
            self.reg_with_reg_as_value[stmt.offset] = self.tmp_with_reg_as_value[stmt.data.tmp]

    def _handle_PutI(self, stmt):
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

        if isinstance(stmt.data, pyvex.IRExpr.Get) and stmt.data.result_size(self.tyenv) == 64:
            self.tmp_with_reg_as_value[stmt.tmp] = stmt.data.offset

        super()._handle_WrTmp(stmt)

    def _handle_Get(self, expr):
        self.reg_read_stmt_id[expr.offset] = self.stmt_idx
        if expr.offset in self.reg_with_reg_as_value:
            del self.reg_with_reg_as_value[expr.offset]

    def _handle_GetI(self, expr):
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
