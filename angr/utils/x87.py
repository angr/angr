from __future__ import annotations

from typing import TYPE_CHECKING

from pyvex import IRSB
from pyvex.expr import Binop, Const, Get, GetI, RdTmp, Unop
from pyvex.stmt import Dirty, Put, WrTmp

from angr.calling_conventions import SimLyingRegArg, SimRegArg
from angr.sim_type import SimTypeFloat

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.functions import Function
    from angr.project import Project


# functions larger than this are not scanned for their net x87 stack effect
MAX_FUNCTION_BLOCKS = 256


class X87Tracker:
    """
    Forward-tracks the x87 stack pointer ``ftop`` through the statements of one VEX block, together with the tmps
    derived from it. Values are 32-bit masked; ``ftop`` becomes None once it cannot be determined.
    """

    def __init__(self, irsb: IRSB, ftop: int, ftop_off: int, ftop_size: int, array_bases: tuple[int, ...] = ()):
        self.irsb = irsb
        self.ftop: int | None = ftop
        self._ftop_off = ftop_off
        self._ftop_size = ftop_size
        self._array_bases = array_bases
        self._tmps: dict[int, int] = {}
        # tmps holding an unknown 1Uto32(cond)
        self._flag_tmps: set[int] = set()
        # number of caller-pushed x87 slots read (st(0)..st(n-1) at the function entry)
        self.incoming_depth = 0

    def eval(self, expr) -> int | None:
        if isinstance(expr, RdTmp):
            return self._tmps.get(expr.tmp)
        if isinstance(expr, Const):
            return expr.con.value
        if isinstance(expr, Get):
            return self.ftop if expr.offset == self._ftop_off else None
        if isinstance(expr, Binop) and expr.op in ("Iop_Add32", "Iop_Sub32"):
            a, b = self.eval(expr.args[0]), self.eval(expr.args[1])
            if (
                a is not None
                and b is None
                and expr.op == "Iop_Sub32"
                and isinstance(expr.args[1], RdTmp)
                and expr.args[1].tmp in self._flag_tmps
            ):
                # VEX fptan: ftop - 1Uto32(in_range). Assume the push happened; the out-of-range case only sets
                # C2 and leaves the stack alone, which compiled code never relies on without testing C2.
                b = 1
            if a is None or b is None:
                return None
            return (a + b if expr.op == "Iop_Add32" else a - b) & 0xFFFFFFFF
        return None

    def step(self, stmt) -> bool:
        """Process one statement; False once ftop is unknown."""
        if isinstance(stmt, WrTmp):
            if isinstance(stmt.data, GetI) and stmt.data.descr.base in self._array_bases:
                self._check_incoming(stmt.data)
            v = self.eval(stmt.data)
            if v is None:
                self._tmps.pop(stmt.tmp, None)
            else:
                self._tmps[stmt.tmp] = v
            if isinstance(stmt.data, Unop) and stmt.data.op == "Iop_1Uto32":
                self._flag_tmps.add(stmt.tmp)
        elif isinstance(stmt, Put):
            if (
                stmt.offset < self._ftop_off + self._ftop_size
                and self._ftop_off < stmt.offset + stmt.data.result_size(self.irsb.tyenv) // 8
            ):
                self.ftop = self.eval(stmt.data)
                return self.ftop is not None
        elif isinstance(stmt, Dirty):
            # FLDENV/FRSTOR/FXRSTOR reload the x87 state; F(N)SAVE and FINIT reinitialize it (empty stack)
            name = stmt.cee.name
            if "RSTOR" in name or "FLDENV" in name:
                self.ftop = None
                return False
            if "FSAVE" in name or "FNSAVE" in name or "FINIT" in name:
                self.ftop = 0
        return True

    def _check_incoming(self, get: GetI) -> None:
        # ftop is 0 at the function entry: slots 0-3 hold the caller's values, the function pushes into 7, 6, ...
        ix = self.eval(get.ix)
        if ix is None or self.ftop is None:
            return
        slot = (ix + get.bias) % 8
        if slot < 4:
            self.incoming_depth = max(self.incoming_depth, slot + 1)


class X87StackModel:
    """
    Net effects of functions and calls on the x87 stack pointer ``ftop`` (0 at a function entry), obtained by
    forward-tracking ``ftop`` through VEX blocks. A callee's effect comes from its prototype (an x87 FP return
    pushes one value) or, failing that, from its own code.

    :ivar assume_balanced:  Treat a callee whose effect cannot be determined as leaving the stack balanced.
    """

    def __init__(
        self,
        project: Project,
        kb: KnowledgeBase,
        callee_deltas: dict[int, int | None] | None = None,
        max_blocks: int = MAX_FUNCTION_BLOCKS,
        max_callee_blocks: int = MAX_FUNCTION_BLOCKS,
        assume_balanced: bool = False,
    ):
        self.project = project
        self.kb = kb
        self.assume_balanced = assume_balanced
        self._ftop: tuple[int, int] | None = project.arch.registers.get("ftop")
        self._max_blocks = max_blocks
        self._max_callee_blocks = max_callee_blocks
        self._callee_deltas: dict[int, int | None] = callee_deltas if callee_deltas is not None else {}
        self._callee_x87_args_cache: dict[int, int] = {}

    @staticmethod
    def prototype_returns_x87(func: Function) -> bool:
        if func.prototype is None or not isinstance(func.prototype.returnty, SimTypeFloat):
            return False
        cc = func.calling_convention
        # a concrete (non-lying) FP return register means the value is not returned on the x87 stack
        return cc is None or not isinstance(cc.FP_RETURN_VAL, SimRegArg) or isinstance(cc.FP_RETURN_VAL, SimLyingRegArg)

    @staticmethod
    def prototype_delta(func: Function) -> int | None:
        """The net effect on ftop declared by the function's prototype (x87 arguments popped, x87 return pushed)."""
        cc = func.calling_convention
        x87_args = cc.x87_args if cc is not None else 0
        returns_x87 = X87StackModel.prototype_returns_x87(func)
        if not x87_args and not returns_x87:
            return None
        return x87_args - (1 if returns_x87 else 0)

    def callee_delta(self, callee_addr: int) -> int | None:
        """
        The callee's net effect on ftop (-1: returns a value on the x87 stack; +1: pops its x87 argument), or None
        when it cannot be determined.
        """
        if callee_addr in self._callee_deltas:
            return self._callee_deltas[callee_addr]
        self._callee_deltas[callee_addr] = None  # recursion guard
        result: int | None = None
        callee = self.kb.functions.function(addr=callee_addr)
        if callee is not None:
            result = self.prototype_delta(callee)
            if result is None and not callee.is_simprocedure and not callee.is_plt and callee.block_addrs_set:
                result = self.function_delta(callee, self._max_callee_blocks)
        self._callee_deltas[callee_addr] = result
        return result

    def function_delta(self, func: Function, max_blocks: int | None = None) -> int | None:
        """The function's net effect on ftop, or None if unknown or path-dependent."""
        ret_ftops = self.ret_ftops(func, max_blocks)
        if ret_ftops is None or len(set(ret_ftops.values())) != 1:
            return None
        value = next(iter(ret_ftops.values()))
        if value is None:
            return None
        return value - 8 if value > 4 else value

    @staticmethod
    def classify_x87_args(ret_ftops: dict[int, int | None] | None, depth: int) -> tuple[int, bool] | None:
        """
        Values the function takes on the x87 stack (MSVC _CI* helpers take st(0); _ftol takes and pops st(0)), under
        the convention that the callee pops all of them, from the result of scan.

        :return: The number of x87 arguments and whether the function returns a value in st(0) (in place of its
                 popped arguments), or None when it takes no x87 arguments or its stack effect is inconsistent.
        """
        if not depth or not ret_ftops:
            return None
        values = set(ret_ftops.values())
        if len(values) != 1:
            return None
        ftop = next(iter(values))
        if ftop == depth % 8:
            return depth, False
        if ftop == (depth - 1) % 8:
            return depth, True
        return None

    def ret_ftops(self, func: Function, max_blocks: int | None = None) -> dict[int, int | None] | None:
        """
        ftop at each return site of the function (keyed by block address; None where unknown), or None when the
        function is too large to scan.
        """
        return self.scan(func, max_blocks)[0]

    def _apply_callee(self, target: int | None, ftop: int) -> int | None:
        delta = self.callee_delta(target) if isinstance(target, int) else None
        if delta is None and self.assume_balanced:
            delta = 0
        return None if delta is None else (ftop + delta) % 8

    def _callee_x87_args(self, target: int) -> int:
        if target in self._callee_x87_args_cache:
            return self._callee_x87_args_cache[target]
        self._callee_x87_args_cache[target] = 0  # recursion guard
        n = 0
        callee = self.kb.functions.function(addr=target)
        if callee is not None:
            if callee.calling_convention is not None and callee.prototype is not None:
                n = callee.calling_convention.x87_args
            elif not callee.is_simprocedure and not callee.is_plt and callee.block_addrs_set:
                r = self.classify_x87_args(*self.scan(callee, self._max_callee_blocks))
                n = r[0] if r is not None else 0
        self._callee_x87_args_cache[target] = n
        return n

    def _passed_incoming_depth(self, target: int, ftop: int) -> int:
        """How many of our own incoming x87 slots a callee takes as its x87 arguments."""
        depth = 0
        for i in range(self._callee_x87_args(target)):
            slot = (ftop + i) % 8
            if slot < 4:
                depth = max(depth, slot + 1)
        return depth

    def _tail_call_target(self, func: Function, node) -> int | None:
        for _, dst, data in func.transition_graph.out_edges(node, data=True):
            if (
                data.get("type") == "transition"
                and data.get("outside", False)
                and dst.addr != func.addr
                and self.kb.functions.contains_addr(dst.addr)
            ):
                return dst.addr
        return None

    def scan(self, func: Function, max_blocks: int | None = None) -> tuple[dict[int, int | None] | None, int]:
        """
        :return: ftop at each return site (see ret_ftops), and how many x87 slots the function reads that it did not
                 push (values passed on the x87 stack, as by MSVC's _CI* and _ftol helpers).
        """
        if self._ftop is None:
            return None, 0
        if len(func.block_addrs_set) > (self._max_blocks if max_blocks is None else max_blocks):
            return None, 0
        ftop_off, ftop_size = self._ftop
        array_bases = tuple(
            self.project.arch.registers[name][0] for name in ("fpreg", "fptag") if name in self.project.arch.registers
        )
        graph = func.graph
        entry_node = func.get_node(func.addr)
        if entry_node is None:
            return None, 0
        incoming_depth = 0

        # entry/exit ftop per block address; a block absent from `entry` is unvisited, None means unknown
        entry: dict[int, int | None] = {entry_node.addr: 0}
        exit_vals: dict[int, int | None] = {}
        ret_vals: dict[int, int | None] = {}
        worklist = [entry_node]
        while worklist:
            node = worklist.pop(0)
            ftop = entry[node.addr]
            try:
                irsb = self.project.factory.block(node.addr, size=node.size).vex
            except Exception:  # pylint:disable=broad-exception-caught
                irsb = None
            if irsb is None:
                ftop = None
            else:
                if ftop is not None:
                    tracker = X87Tracker(irsb, ftop, ftop_off, ftop_size, array_bases)
                    for stmt in irsb.statements:
                        if not tracker.step(stmt):
                            break
                    incoming_depth = max(incoming_depth, tracker.incoming_depth)
                    ftop = None if tracker.ftop is None else tracker.ftop % 8
                if irsb.jumpkind == "Ijk_Ret":
                    ret_vals[node.addr] = ftop
                elif irsb.jumpkind == "Ijk_Call" and ftop is not None:
                    target = func.get_call_target(node.addr)
                    if isinstance(target, int):
                        incoming_depth = max(incoming_depth, self._passed_incoming_depth(target, ftop))
                    ftop = self._apply_callee(target, ftop)
                elif irsb.jumpkind == "Ijk_Boring":
                    tail_target = self._tail_call_target(func, node)
                    if tail_target is not None:
                        # a (possibly conditional) tail call returns to our caller
                        tail_ftop = None
                        if ftop is not None:
                            incoming_depth = max(incoming_depth, self._passed_incoming_depth(tail_target, ftop))
                            tail_ftop = self._apply_callee(tail_target, ftop)
                        ret_vals[node.addr] = tail_ftop
            if node.addr in exit_vals and exit_vals[node.addr] == ftop:
                continue
            exit_vals[node.addr] = ftop
            for succ in graph.successors(node):
                if succ.addr not in entry:
                    entry[succ.addr] = ftop
                    worklist.append(succ)
                elif entry[succ.addr] is not None and entry[succ.addr] != ftop:
                    entry[succ.addr] = None
                    worklist.append(succ)
        return ret_vals, incoming_depth
