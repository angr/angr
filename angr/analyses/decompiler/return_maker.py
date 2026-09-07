from __future__ import annotations

import logging

from angr import ailment
from angr.calling_conventions import (
    SimArrayArg,
    SimComboArg,
    SimLyingRegArg,
    SimReferenceArgument,
    SimRegArg,
    SimStackArg,
    SimStructArg,
)
from angr.knowledge_plugins.plugin import DEFAULT_FLAVOR
from angr.sim_type import SimTypeBottom
from angr.utils.types import dereference_simtype_by_lib

from .ailgraph_walker import AILGraphWalker

l = logging.getLogger(__name__)


class ReturnMaker(AILGraphWalker):
    """
    Traverse the AILBlock graph of a function and update .ret_exprs of all return statements.
    """

    def __init__(self, ail_manager, arch, function, ail_graph, flavor: str = DEFAULT_FLAVOR):
        super().__init__(ail_graph, self._handler, replace_nodes=True)
        self.ail_manager = ail_manager
        self.arch = arch
        self.function = function
        self.flavor = flavor

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
        # ftop is 0 at the entry; the callee pops its x87 arguments and pushes the return value, so at the return
        # site st0 = fpreg[(x87_args - 1) % 8] (mm7 without x87 arguments).
        if isinstance(ret_val, SimLyingRegArg):
            fpreg = self.arch.registers.get("fpreg")
            if fpreg is not None:
                fp_ret_offset = fpreg[0] + (((self.function.calling_convention.x87_args - 1) % 8) << 3)
                return (fp_ret_offset, ret_val.size)

        l.warning("Cannot resolve return register %s to a concrete offset.", ret_val.reg_name)
        return None

    def _handle_Return(self, stmt_idx: int, stmt: ailment.Stmt.Return, block: ailment.Block | None):  # pylint:disable=unused-argument
        prototype = self.function.get_prototype(self.flavor)
        if (
            block is not None
            and not stmt.ret_exprs
            and prototype is not None
            and prototype.returnty is not None
            and type(prototype.returnty) is not SimTypeBottom
        ):
            new_stmt = stmt.copy()
            new_ret_exprs = list(new_stmt.ret_exprs)
            returnty = (
                dereference_simtype_by_lib(prototype.returnty, self.function.prototype_libname)
                if self.function.prototype_libname
                else prototype.returnty
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
            elif isinstance(ret_val, (SimStructArg, SimArrayArg)):
                # struct-shaped results (e.g. Go's multiple results) span several registers
                ret_val = SimComboArg(self._flatten_locs(ret_val))
            if isinstance(ret_val, SimRegArg):
                reg = self._resolve_return_register(ret_val)
                if reg is not None:
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
                for ret_val_loc in ret_val.locations:
                    if isinstance(ret_val_loc, SimRegArg):
                        reg = self._resolve_return_register(ret_val_loc)
                        if reg is not None:
                            new_ret_exprs.append(
                                ailment.Expr.Register(
                                    self._next_atom(),
                                    reg[0],
                                    ret_val_loc.size * self.arch.byte_width,
                                    reg_name=self.arch.translate_register_name(reg[0], ret_val_loc.size),
                                    ins_addr=stmt.tags.get("ins_addr"),  # pyright: ignore[reportTypedDictNotRequiredAccess]
                                )
                            )
                    elif isinstance(ret_val_loc, SimStackArg):
                        new_ret_exprs.append(self._stack_load(ret_val_loc, stmt))
                    else:
                        l.warning("Unsupported type of return expression %s.", type(ret_val_loc))
            elif isinstance(ret_val, SimStackArg):
                new_ret_exprs.append(self._stack_load(ret_val, stmt))
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

    def _stack_load(self, loc: SimStackArg, stmt) -> ailment.Expr.Load:
        """A result the callee leaves in the caller's frame (Go's ABI0): read it back from the stack slot."""
        addr = ailment.Expr.StackBaseOffset(self._next_atom(), self.arch.bits, loc.stack_offset)
        return ailment.Expr.Load(
            self._next_atom(), addr, loc.size, self.arch.memory_endness, ins_addr=stmt.tags.get("ins_addr")
        )

    @classmethod
    def _flatten_locs(cls, loc) -> list:
        if isinstance(loc, SimStructArg):
            return [x for sub in loc.locs.values() for x in cls._flatten_locs(sub)]
        if isinstance(loc, SimArrayArg):
            return [x for sub in loc.locs for x in cls._flatten_locs(sub)]
        if isinstance(loc, SimComboArg):
            return [x for sub in loc.locations for x in cls._flatten_locs(sub)]
        return [loc]

    def _handler(self, block):
        # we don't need to handle any statement besides Returns
        walker = ailment.AILBlockRewriter(
            update_block=False, expr_handlers={}, stmt_handlers={ailment.statement.Return: self._handle_Return}
        )

        result = walker.walk(block)
        if result is block:
            return None
        return result
