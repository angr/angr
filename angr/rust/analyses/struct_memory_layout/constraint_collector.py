import logging

from angr.rust.sim_type import RustSimTypeReference
from angr.rust.analyses.struct_memory_layout.constraints import IsNotConstraint
from angr.rust.utils.ail import extract_vvar_and_offset
from angr.analyses.decompiler import Clinic
from angr.rust.mixins import SRDAMixin
from angr.ailment import AILBlockWalkerBase, Block, Statement
from angr.ailment.statement import Store
from angr.ailment.expression import Const, BinaryOp, VirtualVariable, Load

l = logging.getLogger(__name__)


class ConstraintCollector(AILBlockWalkerBase):

    def __init__(self):
        super().__init__()

        self.arg_vvar = None
        self.constraints = set()

        self._srda: SRDAMixin | None = None

    def _is_target_vvar(self, expr):
        if isinstance(expr, VirtualVariable):
            vvar = self._srda.get_terminal_vvar(expr)
            return vvar.likes(self.arg_vvar)
        return False

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        vvar, offset = extract_vvar_and_offset(stmt.addr)
        if self._is_target_vvar(vvar):
            if isinstance(stmt.data, Const) and stmt.data.value == 0:
                # self.constraints[offset].add(IsNotConstraint(offset, stmt.data.size, RustSimTypeReference))
                self.constraints.add(IsNotConstraint(offset, stmt.data.size, RustSimTypeReference))
                l.info(f"Collect constraint from {stmt}")
        super()._handle_Store(stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        op0, op1 = expr.operands
        if isinstance(op0, VirtualVariable):
            op0 = self._srda.get_terminal_vvar_value(op0)
        if isinstance(op0, Load):
            vvar, offset = extract_vvar_and_offset(op0.addr)
            if self._is_target_vvar(vvar) and expr.op != "Add":
                if not expr.op.startswith("Cmp") or (
                    expr.op.startswith("Cmp") and isinstance(op1, Const) and op1.value == 0
                ):
                    self.constraints.add(IsNotConstraint(offset, vvar.size, RustSimTypeReference))
                    l.info(f"Collect constraint from {expr}")
        super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def collect(self, clinic: Clinic, arg_vvar):
        self.arg_vvar = arg_vvar
        self._srda = SRDAMixin(clinic.function, clinic.graph, clinic.project)

        for block in clinic.graph.nodes:
            self.walk(block)
