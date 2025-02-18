from __future__ import annotations
import contextlib
from typing import TYPE_CHECKING
import logging

from angr import sim_options as o
from angr import BP, BP_AFTER
from angr.errors import (
    AngrUnsupportedSyscallError,
    SimOperationError,
    SimError,
)

from .resolver import IndirectJumpResolver
from .constant_value_manager import ConstantValueManager

if TYPE_CHECKING:
    from angr import Block
    from angr.engines import SimSuccessors
    from angr.sim_state import SimState
    from angr.sim_procedure import SimProcedure


_l = logging.getLogger(name=__name__)


class SyscallResolver(IndirectJumpResolver):
    """
    Resolve syscalls to SimProcedures.
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        return jumpkind.startswith("Ijk_Sys")

    def resolve(  # pylint:disable=unused-argument
        self, cfg, addr: int, func_addr: int, block: Block, jumpkind: str, func_graph_complete: bool = True, **kwargs
    ):
        stub = self._resolve_syscall_to_stub(cfg, addr, func_addr, block)
        return (True, [stub.addr]) if stub else (False, [])

    def _resolve_syscall_to_stub(self, cfg, addr: int, func_addr: int, block: Block) -> SimProcedure | None:
        if not cfg.functions.contains_addr(func_addr):
            return None
        func = cfg.functions.get_by_addr(func_addr)

        cv_manager = ConstantValueManager(self.project, cfg.kb, func, addr)
        constant_value_reg_read_bp = BP(when=BP_AFTER, enabled=True, action=cv_manager.reg_read_callback)

        state = self.project.factory.blank_state(
            mode="fastpath",
            addr=block.addr,
            add_options={o.SYMBOL_FILL_UNCONSTRAINED_MEMORY, o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
        )
        state.inspect.add_breakpoint("reg_read", constant_value_reg_read_bp)

        successors = self._simulate_block_with_resilience(state)
        if successors:
            state = self._get_syscall_state_from_successors(successors)
            if state:
                with contextlib.suppress(AngrUnsupportedSyscallError):
                    return self.project.simos.syscall(state)
        return None

    def _simulate_block_with_resilience(self, state: SimState) -> SimSuccessors | None:
        """
        Execute a basic block with "On Error Resume Next". Give up when there is no way moving forward.
        """

        stmt_idx = 0
        successors = None  # make PyCharm's linting happy

        while True:
            try:
                successors = self.project.factory.successors(state, skip_stmts=stmt_idx)
                break
            except SimOperationError:
                stmt_idx += 1
                continue
            except SimError:
                return None

        return successors

    @staticmethod
    def _get_syscall_state_from_successors(successors: SimSuccessors) -> SimState | None:
        for state in successors.flat_successors:
            if state.history.jumpkind and state.history.jumpkind.startswith("Ijk_Sys"):
                return state
        return None
