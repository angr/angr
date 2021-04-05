from typing import List, Dict, Tuple, Union, Optional

import pyvex
import claripy

from ..analysis import Analysis, AnalysesHub
from .apis import CauseBase, InstrOperandCause, InstrOpcodeCause, DataItemCause


OP_TYPE_IMM = 2  # from capstone


class RootCauseAnalysis(Analysis):
    def __init__(self, arch, block_addr: int, stmt_idx: int, constraint=None, cross_insn_opt=False,
                 expression_source: Optional[Dict[claripy.ast.BV,Tuple[int,int]]]=None,
                 config_vars: Optional[Dict[claripy.ast.BV,Tuple[str,int,str,int]]]=None):
        self.arch = arch
        self.block_addr = block_addr
        self.stmt_idx = stmt_idx
        self.constraint = constraint
        self.cross_insn_opt = cross_insn_opt
        self.expression_source = expression_source
        self.config_vars = config_vars  # Each value tuple is config_var_name,address,type,size

        self.causes = self.analyze()

    def analyze(self):
        block = self.project.factory.block(self.block_addr, cross_insn_opt=self.cross_insn_opt)
        stmt = block.vex.statements[self.stmt_idx]

        causes: List[CauseBase] = [ ]

        # handle the most simple case: where the constraint was enforced
        if self.constraint is not None and self.constraint.op in ('__eq__', '__ne__'):
            # comparison. we report both the comparison itself and the constant (if there is any)
            if not self.constraint.args[1].symbolic:
                # find its source
                for ins in reversed(block.capstone.insns):
                    # iterate in its operands
                    for idx, operand in enumerate(ins.operands):
                        if operand.type == OP_TYPE_IMM and operand.value.imm == self.constraint.args[1].args[0]:
                            # found it!
                            cause = InstrOperandCause(ins.address, idx, operand.value.imm)
                            causes.append(cause)
                    # x86
                    if self.arch.name in ("X86", "AMD64") and \
                            ins.mnemonic in {'cmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'jae', 'jbe'}:
                        # report it
                        cause = InstrOpcodeCause(ins.address, ins.mnemonic)
                        causes.append(cause)

        if self.constraint is not None:
            causes += self._root_cause_expr_tree(self.constraint)

        return causes

    def _root_cause_expr_tree(self, expr: claripy.ast.Base) -> List[CauseBase]:
        """
        Traverse the expression tree and root-cause each expression in the tree.

        :param expr:    The expression tree to root cause.
        :return:
        """

        causes = [ ]

        r = self._expr_root_cause(expr)
        if r is not None:
            type_, src = r
            if type_ == "config_var":
                # Identified a configuration variable
                config_var_name, data_addr, data_type, data_size = src
                cause = DataItemCause(data_addr, data_type, data_size, name=config_var_name)
                causes.append(cause)
            elif type_ == "expr":
                # Identified an expression creation location
                bbl_addr, stmt_idx = src
                block = self.project.factory.block(bbl_addr, cross_insn_opt=self.cross_insn_opt)
                ins_addr = None
                ins_ctr = -1
                for idx_, stmt in enumerate(block.vex.statements):
                    if isinstance(stmt, pyvex.IRStmt.IMark):
                        ins_addr = stmt.addr + stmt.delta
                        ins_ctr += 1
                    if stmt_idx == idx_:
                        break
                else:
                    ins_addr = None

                if ins_addr is not None:
                    cause = InstrOpcodeCause(ins_addr, block.capstone.insns[ins_ctr].mnemonic)
                    causes.append(cause)

        # traverse its children
        for operand in expr.args:
            if isinstance(operand, claripy.ast.Base):
                causes += self._root_cause_expr_tree(operand)

        return causes

    def _expr_root_cause(self, expr: claripy.ast.BV) -> Optional[Tuple[str,Union[Tuple[str,int,str,int],Tuple[int,int]]]]:
        """
        For each expression, find where it is constructed in the program.

        :param expr:    The expression to root cause.
        :return:
        """

        # if it's a configuration variable, return the location of the configuration variable
        if expr.op in ('BVS', 'FPS') and expr in self.config_vars:
            return "config_var", self.config_vars[expr]

        # try to determine where the expression is created
        if self.expression_source is None or expr not in self.expression_source:
            # cannot determine
            return None

        return "expr", self.expression_source[expr]


AnalysesHub.register_default('RootCause', RootCauseAnalysis)
