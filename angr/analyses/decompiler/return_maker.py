from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr import ailment
from angr.calling_conventions import SimComboArg, SimRegArg
from angr.sim_type import SimTypeBottom
from angr.utils.types import dereference_simtype_by_lib

from .ailgraph_walker import AILGraphWalker

if TYPE_CHECKING:
    from angr.calling_conventions import SimFunctionArgument
    from angr.knowledge_plugins.functions import Function

l = logging.getLogger(__name__)


def return_value_location(function: Function) -> SimFunctionArgument | None:
    """
    Where the function leaves its return value, for the return type its prototype currently carries.

    Returns None when the function has no prototype, no calling convention, or returns nothing.
    """
    if function.prototype is None or function.calling_convention is None:
        return None
    returnty = function.prototype.returnty
    if returnty is None or type(returnty) is SimTypeBottom:
        return None
    if function.prototype_libname:
        returnty = dereference_simtype_by_lib(returnty, function.prototype_libname)
    return function.calling_convention.return_val(returnty)


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

    def _handle_Return(self, stmt_idx: int, stmt: ailment.Stmt.Return, block: ailment.Block | None):  # pylint:disable=unused-argument
        ret_val = return_value_location(self.function) if block is not None and not stmt.ret_exprs else None
        if ret_val is not None:
            new_stmt = stmt.copy()
            new_ret_exprs = list(new_stmt.ret_exprs)
            if isinstance(ret_val, SimRegArg):
                reg = self.arch.registers[ret_val.reg_name]
                new_ret_exprs.append(
                    ailment.Expr.Register(
                        self._next_atom(),
                        reg[0],
                        ret_val.size * self.arch.byte_width,
                        reg_name=self.arch.translate_register_name(reg[0], ret_val.size),
                        ins_addr=stmt.tags.get("ins_addr"),  # pyright: ignore[reportTypedDictNotRequiredAccess]
                    )
                )
            elif isinstance(ret_val, SimComboArg):
                # TODO: we currently only support the first register in the combo, but we should support all of them
                # ret_val = ret_val.locations[0]
                # reg = self.arch.registers[ret_val.reg_name]
                # new_stmt.ret_exprs.append(
                #     ailment.Expr.Register(
                #         self._next_atom(),
                #         None,
                #         reg[0],
                #         ret_val.size * self.arch.byte_width,
                #         reg_name=self.arch.translate_register_name(reg[0], ret_val.size),
                #         ins_addr=stmt.tags["ins_addr"],
                #     )
                # )
                for ret_val_loc in ret_val.locations:
                    if isinstance(ret_val_loc, SimRegArg):
                        reg = self.arch.registers[ret_val_loc.reg_name]
                        new_ret_exprs.append(
                            ailment.Expr.Register(
                                self._next_atom(),
                                reg[0],
                                ret_val_loc.size * self.arch.byte_width,
                                reg_name=self.arch.translate_register_name(reg[0], ret_val_loc.size),
                                ins_addr=stmt.tags.get("ins_addr"),  # pyright: ignore[reportTypedDictNotRequiredAccess]
                            )
                        )
                    else:
                        l.warning("Unsupported type of return expression %s.", type(ret_val_loc))
            else:
                l.warning("Unsupported type of return expression %s.", type(ret_val))
            new_stmt.ret_exprs = new_ret_exprs
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
