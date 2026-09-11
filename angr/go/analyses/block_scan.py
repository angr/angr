"""
Raw-AIL block scanning shared by the project-level Go analyses: lift blocks straight from VEX (no SSA, no
simplification) and track which constants and call results the machine registers hold.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING

from angr import ailment
from angr.ailment.expression import BinaryOp, Call, Const, Convert, Load, Register, Tmp
from angr.ailment.statement import Assignment, Return
from angr.utils.go_runtime import normalize_go_func_name

if TYPE_CHECKING:
    from angr.project import Project

l = logging.getLogger(__name__)

# value kinds held by a register: a constant, word ``k`` of an ``n``-word typed value, the closure context + off,
# the stack pointer + off
CONST = "c"
TYPED = "ty"
CTX = "ctx"
SP = "sp"

# (Go function name, index of the type descriptor argument) of the allocators; the descriptor gives the type
_ALLOCATORS = {
    "runtime.newobject": ("*", 0),
    "runtime.mallocgc": ("*", 1),
    "runtime.makeslice": ("[]", 0),
    "runtime.makeslicecopy": ("[]", 0),
    "runtime.makechan": ("", 0),
    "runtime.makechan64": ("", 0),
    "runtime.makemap": ("", 0),
    "runtime.makemap64": ("", 0),
    "runtime.makemap_small": ("", None),
}


def lift_ail(project: Project, addr: int, size: int | None = None, manager=None) -> list:
    """The raw AIL statements of the block at ``addr``, or [] when it cannot be lifted."""
    try:
        block = project.factory.block(addr, size=size)
        ail_block = ailment.IRSBConverter.convert(block.vex, manager or ailment.Manager())
    except Exception:  # pylint:disable=broad-exception-caught
        l.debug("Cannot lift %#x", addr, exc_info=True)
        return []
    return list(ail_block.statements)


def block_successors(project: Project, addr: int, size: int | None = None) -> list[int]:
    """Direct successors of a block: its exits and, after a call, the return address."""
    try:
        vex = project.factory.block(addr, size=size).vex
    except Exception:  # pylint:disable=broad-exception-caught
        return []
    out = []
    for stmt in vex.statements:
        if stmt.tag == "Ist_Exit" and stmt.jumpkind == "Ijk_Boring":
            out.append(stmt.dst.value)
    if vex.jumpkind == "Ijk_Boring" and hasattr(vex.next, "con"):
        out.append(vex.next.con.value)
    elif vex.jumpkind == "Ijk_Call":
        out.append(vex.addr + vex.size)
    return out


def function_blocks(project: Project, addr: int, limit: int = 4096) -> tuple[list[int], dict[int, list[int]]]:
    """
    Block addresses of the function at ``addr`` with their successor lists: the CFG's function graph when the
    function is known, else a bounded walk over direct jumps from the entry.
    """
    functions = project.kb.functions
    if functions.contains_addr(addr):
        func = functions.get_by_addr(addr)
        graph = func.graph
        nodes = [n for n in graph.nodes if getattr(n, "size", None) is not None and n.addr in func.block_addrs_set]
        succs = {n.addr: [s.addr for s in graph.successors(n) if s.addr in func.block_addrs_set] for n in nodes}
        # the function graph does not carry the fall-through after a call
        for n in nodes:
            if not succs[n.addr] and n.addr in func._call_sites:
                ret = func.get_call_return(n.addr)
                if ret is not None and ret in succs:
                    succs[n.addr] = [ret]
        return [n.addr for n in nodes], succs
    text = project.loader.main_object.sections_map.get(".text")
    order: list[int] = []
    succs = {}
    worklist = [addr]
    seen = set()
    while worklist and len(order) < limit:
        a = worklist.pop(0)
        if a in seen:
            continue
        seen.add(a)
        if text is not None and not text.contains_addr(a):
            continue
        order.append(a)
        succs[a] = block_successors(project, a)
        worklist.extend(s for s in succs[a] if s not in seen)
    return order, succs


class RegisterEnv:
    """
    What the machine registers (and VEX temporaries) hold inside one block: constants, typed call results and
    closure-context offsets. Keys are ``("r", offset)`` / ``("t", index)``.
    """

    __slots__ = ("arch", "values")

    def __init__(self, arch, values: dict | None = None):
        self.arch = arch
        self.values: dict[tuple, tuple] = dict(values) if values else {}
        if not values:
            self.values[("r", arch.sp_offset)] = (SP, 0)

    def copy(self) -> RegisterEnv:
        return RegisterEnv(self.arch, self.values)

    def merge(self, other: RegisterEnv) -> RegisterEnv:
        """Meet of two environments: only agreeing register values survive (temporaries are block-local)."""
        out = {}
        for key, value in self.values.items():
            if key[0] in ("r", "s") and other.values.get(key) == value:
                out[key] = value
        return RegisterEnv(self.arch, out)

    def registers(self) -> dict[int, tuple]:
        return {key[1]: value for key, value in self.values.items() if key[0] == "r"}

    def eval(self, expr):
        """The value of ``expr``, or None."""
        if isinstance(expr, Const):
            return (CONST, expr.value) if isinstance(expr.value, int) else None
        if isinstance(expr, Register):
            return self.values.get(("r", expr.reg_offset)) if expr.bits == self.arch.bits else None
        if isinstance(expr, Tmp):
            return self.values.get(("t", expr.tmp_idx))
        if isinstance(expr, Convert):
            return self.eval(expr.operand) if expr.from_bits == expr.to_bits else None
        if isinstance(expr, Load) and expr.size == self.arch.bytes:
            slot = self.eval(expr.addr)
            return self.values.get(("s", slot[1])) if slot is not None and slot[0] == SP else None
        if isinstance(expr, BinaryOp) and expr.op in ("Add", "Sub"):
            a, b = expr.operands
            va, vb = self.eval(a), self.eval(b)
            if vb is not None and vb[0] == CONST:
                delta = vb[1] if expr.op == "Add" else -vb[1]
                if va is not None and va[0] in (CONST, CTX, SP):
                    return (va[0], va[1] + delta)
            if expr.op == "Add" and va is not None and va[0] == CONST and vb is not None and vb[0] in (CONST, CTX, SP):
                return (vb[0], vb[1] + va[1])
        return None

    def store(self, addr_expr, data_expr, size: int) -> None:
        """Remember a word stored into a stack slot."""
        if size != self.arch.bytes:
            return
        slot = self.eval(addr_expr)
        if slot is None or slot[0] != SP:
            return
        value = self.eval(data_expr)
        if value is None:
            self.values.pop(("s", slot[1]), None)
        else:
            self.values[("s", slot[1])] = value

    def assign(self, stmt: Assignment) -> None:
        dst = stmt.dst
        if isinstance(dst, Register):
            if dst.bits != self.arch.bits:
                self.values.pop(("r", dst.reg_offset), None)
                return
            key = ("r", dst.reg_offset)
        elif isinstance(dst, Tmp):
            key = ("t", dst.tmp_idx)
        else:
            return
        value = self.eval(stmt.src)
        if value is None:
            self.values.pop(key, None)
        else:
            self.values[key] = value

    def clear_call_clobbers(self, keep: Iterable[int] = ()) -> None:
        """Forget every register except the stack pointer and ``keep`` (offsets), and every temporary."""
        keep = set(keep) | {self.arch.sp_offset}
        self.values = {k: v for k, v in self.values.items() if k[0] == "s" or (k[0] == "r" and k[1] in keep)}


def call_target(stmt) -> int | None:
    if isinstance(stmt, Call) and isinstance(stmt.target, Const) and isinstance(stmt.target.value, int):
        return stmt.target.value
    return None


def callee_name(project: Project, addr: int) -> str | None:
    functions = project.kb.functions
    if functions.contains_addr(addr):
        return normalize_go_func_name(functions.get_by_addr(addr).name)
    sym = project.loader.find_symbol(addr)
    return normalize_go_func_name(sym.name) if sym is not None else None


def is_function_addr(project: Project, addr: int) -> bool:
    """``addr`` starts a function known to the CFG or to the (pclntab-derived) symbol table."""
    if project.kb.functions.contains_addr(addr):
        return True
    sym = project.loader.find_symbol(addr)
    return sym is not None and sym.is_function and sym.rebased_addr == addr


def is_return(stmt) -> bool:
    return isinstance(stmt, Return)


def loads_in(expr, out: list) -> None:
    """Collect every Load below ``expr`` (depth first)."""
    if isinstance(expr, Load):
        out.append(expr)
        loads_in(expr.addr, out)
    elif isinstance(expr, BinaryOp):
        for op in expr.operands:
            loads_in(op, out)
    elif isinstance(expr, Convert):
        loads_in(expr.operand, out)
    elif isinstance(expr, Call):
        for arg in expr.args or ():
            loads_in(arg, out)


def allocator(name: str | None) -> tuple[str, int | None] | None:
    """``(type prefix, descriptor argument index)`` for a runtime allocator, else None."""
    if name is None:
        return None
    if name.startswith("runtime.mallocgc"):
        return _ALLOCATORS["runtime.mallocgc"]
    return _ALLOCATORS.get(name)


__all__ = [
    "CONST",
    "CTX",
    "SP",
    "TYPED",
    "RegisterEnv",
    "allocator",
    "block_successors",
    "call_target",
    "callee_name",
    "function_blocks",
    "is_function_addr",
    "is_return",
    "lift_ail",
    "loads_in",
]
