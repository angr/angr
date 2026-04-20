from __future__ import annotations
import logging

from angr import ailment
from angr.utils.types import dereference_simtype_by_lib
from angr.sim_type import SimTypeBottom
from angr.calling_conventions import SimRegArg, SimLyingRegArg
from .ailgraph_walker import AILGraphWalker

l = logging.getLogger(__name__)


class ReturnMaker(AILGraphWalker):
    """
    Traverse the AILBlock graph of a function and update .ret_exprs of all return statements.
    """

    def __init__(self, ail_manager, arch, function, ail_graph):
        super().__init__(ail_graph, self._handler, replace_nodes=True)
        self.ail_manager = ail_manager
        self.arch = arch
        self.function = function

        self.walk()

    def _next_atom(self) -> int:
        return self.ail_manager.next_atom()

    def _resolve_return_register(self, ret_val: SimRegArg) -> tuple[int, int] | None:
        """Resolve the return register to a concrete (offset, size) pair.

        For normal registers (e.g. eax, xmm0), this is a direct lookup.
        For x87 SimLyingRegArg ("st0"), compute from the calling convention:
        ftop=0 at entry, ftop=-1 at return -> st0 = fpreg[7] = mm7.
        """
        # Normal register: direct lookup
        if ret_val.reg_name in self.arch.registers:
            return self.arch.registers[ret_val.reg_name]

        # SimLyingRegArg ("st0"): resolve from the calling convention.
        # x86 cdecl initializes ftop=0; returning via ST0 decrements ftop by 1,
        # so at the return site st0 = fpreg[(-1 % 8)] = fpreg[7] = mm7.
        if isinstance(ret_val, SimLyingRegArg):
            fpreg = self.arch.registers.get("fpreg")
            if fpreg is not None:
                fp_ret_offset = fpreg[0] + ((-1 % 8) << 3)
                return (fp_ret_offset, ret_val.size)

        l.warning("Cannot resolve return register %s to a concrete offset.", ret_val.reg_name)
        return None

    def _handle_Return(self, stmt_idx: int, stmt: ailment.Stmt.Return, block: ailment.Block | None):  # pylint:disable=unused-argument
        if (
            block is not None
            and not stmt.ret_exprs
            and self.function.prototype is not None
            and self.function.prototype.returnty is not None
            and type(self.function.prototype.returnty) is not SimTypeBottom
        ):
            new_stmt = stmt.copy()
            returnty = (
                dereference_simtype_by_lib(self.function.prototype.returnty, self.function.prototype_libname)
                if self.function.prototype_libname
                else self.function.prototype.returnty
            )
            ret_val = self.function.calling_convention.return_val(returnty)
            if isinstance(ret_val, SimRegArg):
                reg = self._resolve_return_register(ret_val)
                if reg is not None:
                    new_stmt.ret_exprs.append(
                        ailment.Expr.Register(
                            self._next_atom(),
                            None,
                            reg[0],
                            ret_val.size * self.arch.byte_width,
                            reg_name=self.arch.translate_register_name(reg[0], ret_val.size),
                            ins_addr=stmt.tags["ins_addr"],
                        )
                    )
            else:
                l.warning("Unsupported type of return expression %s.", type(ret_val))
            return new_stmt
        return stmt

    def _handler(self, block):
        # we don't need to handle any statement besides Returns
        walker = ailment.AILBlockRewriter(
            update_block=False, expr_handlers={}, stmt_handlers={ailment.statement.Return: self._handle_Return}
        )

        result = walker.walk(block)
        if result is block:
            return None
        return result
