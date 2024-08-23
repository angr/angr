from __future__ import annotations
from typing import TYPE_CHECKING
import logging

import claripy
import pyvex

from ....utils.constants import DEFAULT_STATEMENT
from ....code_location import CodeLocation
from ....blade import Blade
from ...propagator import vex_vars
from .resolver import IndirectJumpResolver
from .propagator_utils import PropagatorLoadCallback

if TYPE_CHECKING:
    from angr import Block

_l = logging.getLogger(name=__name__)


def exists_in_replacements(replacements, block_loc, tmp_var):
    exists = False
    for rep in replacements:
        if rep == block_loc:
            exists = True
            break

    if not exists:
        return False

    exists = False
    for var in replacements[block_loc]:
        if var == tmp_var:
            exists = True
            break

    return exists


class ConstantResolver(IndirectJumpResolver):
    """
    Resolve an indirect jump by running a constant propagation on the entire function and check if the indirect jump can
    be resolved to a constant value. This resolver must be run after all other more specific resolvers.
    """

    def __init__(self, project):
        super().__init__(project, timeless=False)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        # we support both an indirect call and jump since the value can be resolved
        return jumpkind in {"Ijk_Boring", "Ijk_Call"}

    def resolve(  # pylint:disable=unused-argument
        self, cfg, addr: int, func_addr: int, block: Block, jumpkind: str, func_graph_complete: bool = True, **kwargs
    ):
        """
        This function does the actual resolve. Our process is easy:
        Propagate all values inside the function specified, then extract
        the tmp_var used for the indirect jump from the basic block.
        Use the tmp var to locate the constant value stored in the replacements.
        If not present, returns False tuple.

        :param cfg:         CFG with specified function
        :param addr:        Address of indirect jump
        :param func_addr:   Address of function of indirect jump
        :param block:       Block of indirect jump (Block object)
        :param jumpkind:    VEX jumpkind (Ijk_Boring or Ijk_Call)
        :return:            Bool tuple with replacement address
        """
        if not cfg.functions.contains_addr(func_addr):
            #  the function does not exist
            return False, []

        func = cfg.functions.get_by_addr(func_addr)

        vex_block = block.vex
        if isinstance(vex_block.next, pyvex.expr.RdTmp):
            # what does the jump rely on? slice it back and see
            b = Blade(
                cfg.graph,
                addr,
                -1,
                cfg=cfg,
                project=self.project,
                ignore_bp=False,
                ignore_sp=False,
                max_level=3,
                stop_at_calls=True,
                cross_insn_opt=True,
            )
            stmt_loc = addr, DEFAULT_STATEMENT
            preds = list(b.slice.predecessors(stmt_loc))
            while preds:
                if len(preds) == 1:
                    # skip all IMarks
                    pred_addr, stmt_idx = preds[0]
                    if stmt_idx != DEFAULT_STATEMENT:
                        block = self.project.factory.block(pred_addr, cross_insn_opt=True).vex
                        if isinstance(block.statements[stmt_idx], pyvex.IRStmt.IMark):
                            preds = list(b.slice.predecessors(preds[0]))
                            continue

                for pred_addr, stmt_idx in preds:
                    block = self.project.factory.block(pred_addr, cross_insn_opt=True).vex
                    if stmt_idx != DEFAULT_STATEMENT:
                        stmt = block.statements[stmt_idx]
                        if isinstance(stmt, pyvex.IRStmt.WrTmp) and isinstance(stmt.data, pyvex.IRExpr.Load):
                            # loading from memory - unsupported
                            return False, []
                break

            _l.debug("ConstantResolver: Propagating for %r at %#x.", func, addr)
            prop = self.project.analyses.Propagator(
                func=func,
                only_consts=True,
                do_binops=True,
                vex_cross_insn_opt=False,
                completed_funcs=cfg._completed_functions,
                load_callback=PropagatorLoadCallback(self.project).propagator_load_callback,
                cache_results=True,
                key_prefix="cfg_intermediate",
            )

            replacements = prop.replacements
            if replacements:
                block_loc = CodeLocation(block.addr, None)
                tmp_var = vex_vars.VEXTmp(vex_block.next.tmp)

                if exists_in_replacements(replacements, block_loc, tmp_var):
                    resolved_tmp = replacements[block_loc][tmp_var]

                    if (
                        isinstance(resolved_tmp, claripy.ast.Base)
                        and resolved_tmp.op == "BVV"
                        and self._is_target_valid(cfg, resolved_tmp.args[0])
                    ):
                        return True, [resolved_tmp.args[0]]

        return False, []
