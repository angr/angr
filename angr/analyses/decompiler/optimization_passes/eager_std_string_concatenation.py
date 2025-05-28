# pylint:disable=too-many-boolean-expressions,unused-argument
from __future__ import annotations
from typing import TYPE_CHECKING
import logging
import re

from archinfo import Endness

from angr.ailment.constant import UNDETERMINED_SIZE
from angr.ailment.statement import Assignment, WeakAssignment
from angr.ailment.expression import VirtualVariable, BinaryOp, Const, Load

from .optimization_pass import OptimizationPass, OptimizationPassStage

if TYPE_CHECKING:
    from angr.analyses.s_reaching_definitions import SRDAModel


_l = logging.getLogger(name=__name__)


class EagerStdStringConcatenationPass(OptimizationPass):
    """
    TODO: Unfinished
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Condense multiple constant std::string creation calls into one when possible"
    DESCRIPTION = __doc__.strip()  # type: ignore

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        # TODO: ensure func calls std::string::operator+ and std::string::operator=
        return False, {}

    def _analyze(self, cache=None):
        rd = self.project.analyses.SReachingDefinitions(subject=self._func, func_graph=self._graph).model
        cfg = self.kb.cfgs.get_most_accurate()
        assert cfg is not None

        # update each block
        for key in list(self.blocks_by_addr_and_idx):
            block = self.blocks_by_addr_and_idx[key]
            new_block = None
            for idx, stmt in enumerate(block.statements):
                if (
                    isinstance(stmt, Assignment)
                    and hasattr(stmt, "type")
                    and "dst" in stmt.type
                    and "src" in stmt.type
                    and isinstance(stmt.dst, VirtualVariable)
                    and isinstance(stmt.src, BinaryOp)
                    and stmt.src.op == "Add"
                ):
                    dst_ty, src_ty = stmt.type["dst"], stmt.type["src"]
                    if self._is_std_string_type(dst_ty.c_repr()) and self._is_std_string_type(src_ty.c_repr()):
                        op0, op1 = stmt.src.operands
                        if isinstance(op1, VirtualVariable) and isinstance(op0, Load):
                            op0, op1 = op1, op0
                        if (
                            isinstance(op0, VirtualVariable)
                            and isinstance(op1, Load)
                            and isinstance(op1.addr, Const)
                            and isinstance(op1.addr.value, int)
                            # is op1 a constant string?
                            and op1.addr.value in cfg.memory_data
                            and cfg.memory_data[op1.addr.value].sort == "string"
                        ):
                            op1_str = cfg.memory_data[op1.addr.value].content
                            # is op0 also an std::string?
                            op0_str = self._get_vvar_def_string(op0.varid, rd, cfg, block.addr, block.idx)
                            if op0_str is not None and op1_str is not None:
                                # let's create a new string
                                final_str = op0_str + op1_str
                                str_id = self.kb.custom_strings.allocate(final_str)
                                # replace the assignment with a new assignment
                                new_stmt = WeakAssignment(
                                    stmt.idx,
                                    stmt.dst,
                                    Load(
                                        None,
                                        Const(None, None, str_id, self.project.arch.bits, custom_string=True),
                                        UNDETERMINED_SIZE,
                                        Endness.BE,
                                    ),
                                    **stmt.tags,
                                )
                                new_block = block.copy() if new_block is None else new_block
                                new_block.statements[idx] = new_stmt
            if new_block is not None:
                self._update_block(block, new_block)

    def _get_vvar_def_string(self, vvar_id: int, rd: SRDAModel, cfg, block_addr, block_idx) -> bytes | None:
        # search for the closest weak definition of the specified variable
        # TODO: Optimize this logic in the future

        starting_block = self.blocks_by_addr_and_idx[(block_addr, block_idx)]
        queue = [starting_block]
        visited = set()
        while queue:
            block = queue.pop(0)
            if block in visited:
                continue
            visited.add(block)

            if not (block.addr == block_addr and block.idx == block_idx):
                for stmt in block.statements:
                    if (
                        isinstance(stmt, WeakAssignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and stmt.dst.varid == vvar_id
                    ):
                        if (
                            isinstance(stmt.src, Load)
                            and isinstance(stmt.src.addr, Const)
                            and stmt.src.addr.value in cfg.memory_data
                        ):
                            if cfg.memory_data[stmt.src.addr.value].sort == "string":
                                return cfg.memory_data[stmt.src.addr.value].content
                        elif (
                            isinstance(stmt.src, Const)
                            and hasattr(stmt.src, "custom_string")
                            and stmt.src.custom_string
                        ):
                            return self.kb.custom_strings.get(stmt.src.value)

            preds = list(self._graph.predecessors(block))
            if len(preds) == 1:
                queue.append(preds[0])

        return None

    @staticmethod
    def _is_std_string_type(type_str: str) -> bool:
        type_str = type_str.removeprefix("const ")
        return (
            re.match(
                r"class std::basic_string<char a\d+, struct std::char_traits<char> a\d+, class std::allocator<char>>",
                type_str,
            )
            is not None
        )

        # pcreg_offset = self.project.arch.registers[getpc_reg][0]


#
# old_block = self.blocks_by_addr_and_idx[block_key]
# block = old_block.copy()
# old_stmt = block.statements[stmt_idx]
# block.statements[stmt_idx] = ailment.Stmt.Assignment(
#     old_stmt.idx,
#     ailment.Expr.Register(None, None, pcreg_offset, 32, reg_name=getpc_reg),
#     ailment.Expr.Const(None, None, getpc_reg_value, 32),
#     **old_stmt.tags,
# )
# # remove the statement that pushes return address onto the stack
# if stmt_idx > 0 and isinstance(block.statements[stmt_idx - 1], ailment.Stmt.Store):
#     block.statements = block.statements[: stmt_idx - 1] + block.statements[stmt_idx:]
# self._update_block(old_block, block)
