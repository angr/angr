import logging

from angr.rust.sim_type import RustSimTypeReference
from angr.rust.analyses.struct_memory_layout.constraints import IsNotConstraint, IsConstraint
from angr.rust.utils.ail import extract_vvar_and_offset
from angr.analyses.decompiler import Clinic
from angr.rust.mixins import SRDAMixin
from angr.ailment import AILBlockWalkerBase, Block, Statement
from angr.ailment.statement import Store, Call
from angr.ailment.expression import Const, BinaryOp, VirtualVariable, Load

l = logging.getLogger(__name__)


class ConstraintCollector(AILBlockWalkerBase):

    def __init__(self):
        super().__init__()

        self.arg_vvar = None
        self.constraints = []

        self._srda: SRDAMixin | None = None
        self._func = None
        self._project = None

    def _is_target_vvar(self, expr):
        if isinstance(expr, VirtualVariable):
            vvar = self._srda.get_terminal_vvar(expr)
            return vvar.likes(self.arg_vvar)
        return False

    # def _handle_call(self, expr: Call):
    #     func = None
    #     if isinstance(expr.target, Const) and expr.target.value in self._project.kb.functions:
    #         func = self._project.kb.functions[expr.target.value]
    #     for arg in expr.args:
    #         if isinstance(arg, Load):
    #             vvar, offset = extract_vvar_and_offset(arg.addr)
    #             if self._is_target_vvar(vvar):
    #                 pass
    #                 # import ipdb
    #                 #
    #                 # ipdb.set_trace()
    #         else:
    #             vvar, offset = extract_vvar_and_offset(arg)
    #             if self._is_target_vvar(vvar) and func:
    #                 print(func.prototype)
    #                 import ipdb
    #
    #                 ipdb.set_trace()
    #
    # def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
    #     self._handle_call(expr)
    #     super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)
    #
    # def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
    #     self._handle_call(stmt)
    #     super()._handle_Call(stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        vvar, offset = extract_vvar_and_offset(stmt.addr)
        if self._is_target_vvar(vvar):
            if isinstance(stmt.data, Const) and stmt.data.value == 0:
                constraint = IsNotConstraint(offset, self._project.arch.bytes, RustSimTypeReference)
                self.constraints.append(constraint)
                l.info(f"Collect constraint {constraint} from {stmt} in {self._func.demangled_name}")
        super()._handle_Store(stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        addr = expr.addr
        while isinstance(addr, BinaryOp) and addr.op == "Add":
            addr = addr.operands[0]
        if isinstance(addr, VirtualVariable):
            addr = self._srda.get_terminal_vvar_value(addr)
        if isinstance(addr, Load) and addr.size == self._project.arch.bytes:
            vvar, offset = extract_vvar_and_offset(addr.addr)
            if self._is_target_vvar(vvar):
                constraint = IsConstraint(offset, addr.size, RustSimTypeReference)
                self.constraints.append(constraint)
                l.info(f"Collect constraint {constraint} from {expr} in {self._func.demangled_name}")
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        op0, op1 = expr.operands
        if isinstance(op0, VirtualVariable):
            op0 = self._srda.get_terminal_vvar_value(op0)
        if isinstance(op0, Load):
            vvar, offset = extract_vvar_and_offset(op0.addr)
            if self._is_target_vvar(vvar) and expr.op != "Add":
                constraint = IsNotConstraint(offset, self._project.arch.bytes, RustSimTypeReference)
                # if not expr.op.startswith("Cmp") or (expr.op.startswith("Cmp") and isinstance(op1, Const)):
                if expr.op.startswith("Cmp"):
                    self.constraints += [constraint] * 10
                else:
                    self.constraints.append(constraint)
                l.info(f"Collect constraint {constraint} from {expr} in {self._func.demangled_name}")
        super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def collect(self, clinic: Clinic, arg_vvar):
        self.arg_vvar = arg_vvar
        self._srda = SRDAMixin(clinic.function, clinic.graph, clinic.project)
        self._func = clinic.function
        self._project = clinic.project

        for block in clinic.graph.nodes:
            self.walk(block)
