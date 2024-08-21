import logging

import ailment

from angr.sim_type import SimTypeBottom
from angr.calling_conventions import SimRegArg
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
        self._new_block = None

        self.walk()

    def _next_atom(self) -> int:
        return self.ail_manager.next_atom()

    def _handle_Return(
        self, stmt_idx: int, stmt: ailment.Stmt.Return, block: ailment.Block | None
    ):  # pylint:disable=unused-argument
        if (
            block is not None
            and not stmt.ret_exprs
            and self.function.prototype is not None
            and self.function.prototype.returnty is not None
            and type(self.function.prototype.returnty) is not SimTypeBottom
        ):
            new_stmt = stmt.copy()
            ret_val = self.function.calling_convention.return_val(self.function.prototype.returnty)
            if isinstance(ret_val, SimRegArg):
                reg = self.arch.registers[ret_val.reg_name]
                new_stmt.ret_exprs.append(
                    ailment.Expr.Register(
                        self._next_atom(),
                        None,
                        reg[0],
                        ret_val.size * self.arch.byte_width,
                        reg_name=self.arch.translate_register_name(reg[0], ret_val.size),
                    )
                )
            else:
                l.warning("Unsupported type of return expression %s.", type(ret_val))
            new_statements = block.statements[::]
            new_statements[stmt_idx] = new_stmt
            self._new_block = block.copy(statements=new_statements)

    def _handler(self, block):
        walker = ailment.AILBlockWalker()
        # we don't need to handle any statement besides Returns
        walker.stmt_handlers.clear()
        walker.expr_handlers.clear()
        walker.stmt_handlers[ailment.Stmt.Return] = self._handle_Return

        self._new_block = None
        walker.walk(block)

        if self._new_block is not None:
            return self._new_block
        return None
