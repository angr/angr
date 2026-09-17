from __future__ import annotations

import logging

from angr import ailment
from angr.calling_conventions import SimComboArg, SimReferenceArgument, SimRegArg, SimStructArg
from angr.sim_type import SimTypeBottom
from angr.utils.types import dereference_simtype_by_lib

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

    def _handle_Return(self, stmt_idx: int, stmt: ailment.Stmt.Return, block: ailment.Block | None):  # pylint:disable=unused-argument
        if (
            block is not None
            and not stmt.ret_exprs
            and self.function.prototype is not None
            and self.function.prototype.returnty is not None
            and type(self.function.prototype.returnty) is not SimTypeBottom
        ):
            new_stmt = stmt.copy()
            new_ret_exprs = list(new_stmt.ret_exprs)
            returnty = (
                dereference_simtype_by_lib(self.function.prototype.returnty, self.function.prototype_libname)
                if self.function.prototype_libname
                else self.function.prototype.returnty
            )
            ret_val = self.function.calling_convention.return_val(returnty, perspective_returned=True)
            deref_size = None
            if isinstance(ret_val, SimReferenceArgument):
                # This one comes back through memory: the callee leaves a pointer to the value in the return
                # register and the caller reads the value through it. perspective_returned above is what makes
                # ptr_loc that return register, rather than the register the caller passed the pointer in.
                deref_size = (
                    ret_val.main_loc.struct.size // self.arch.byte_width
                    if isinstance(ret_val.main_loc, SimStructArg)
                    else ret_val.main_loc.size
                )
                ret_val = ret_val.ptr_loc
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
            if deref_size is not None:
                new_ret_exprs = [
                    ailment.Expr.Load(
                        self._next_atom(),
                        ret_expr,
                        deref_size,
                        self.arch.memory_endness,
                        ins_addr=stmt.tags.get("ins_addr"),  # pyright: ignore[reportTypedDictNotRequiredAccess]
                    )
                    for ret_expr in new_ret_exprs
                ]
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
