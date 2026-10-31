"""
Store-to-load forwarding for the global context of a virtual machine in a devirtualized function.

Themida keeps its VM registers, the saved host registers, the VM frame pointer and an entry spin-lock in a writable data
area inside its own section. The devirtualized function stores host values there and reads them back a few statements
later, so the decompiled body is full of ``g_X = v; ... v' = g_X`` pairs. This module forwards such loads to the stored
values; the global store liveness pass then removes the stores, and the lock operations, once nothing reads them.

Provenance: the protector's section is a writable and executable image section that holds the lock word a VM entry
spins on (an atomic compare-exchange of 0 -> 1 on a constant address whose result is unused); program data sections are
never executable. The VM context is the span of the data the function addresses by constant inside that section.

Aliasing: the context is the VM's register file. The VM itself reads context bytes after calls and after re-acquiring
its lock that it wrote before them, so it requires that neither a callee nor another thread changes them in between;
atomics therefore write only their own operand. Whether a callee or a pointer may reach the context at all is decided
by an escape analysis (``VMContext``): if no context address escapes, only calls handed one may; otherwise library calls
write through their pointer arguments and every other call or unknown pointer may write anything.

Forwarding is a must-reaching-store dataflow over context bytes. Only stores of memory-free values (constants, virtual
variables, stack addresses, and pure operations on them) are forwarded; in SSA form every path to the load passes the
store after the last execution of each variable's definition, so the value is the one stored.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

import networkx

from angr.ailment import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    DirtyExpression,
    Expression,
    FunctionLikeMacro,
    Load,
    Phi,
    Register,
    StackBaseOffset,
    Tmp,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import (
    CAS,
    Assignment,
    ConditionalJump,
    DirtyStatement,
    Jump,
    Return,
    SideEffectStatement,
    Statement,
    Store,
)
from angr.utils.ail import dirty_has_side_effects

from .block_walkers import PURE_INTRINSIC_CALLS
from .dead_global_stores import CallGlobalReads
from .peephole_optimizations.cas_intrinsics import _INTRINSICS_NAMES

if TYPE_CHECKING:
    from angr.project import Project

l = logging.getLogger(name=__name__)

_ATOMIC_INTRINSICS = frozenset(name for names in _INTRINSICS_NAMES.values() for name in names.values())
_CMPXCHG_INTRINSICS = frozenset(
    name for mnemonic, names in _INTRINSICS_NAMES.items() if mnemonic.startswith("cmpxchg") for name in names.values()
)

# IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE
_SCN_EXECUTE = 0x20000000
_SCN_WRITE = 0x80000000


def _const_value(expr) -> int | None:
    if isinstance(expr, Const) and isinstance(expr.value, int):
        return expr.value
    return None


#
# Provenance
#


def image_sections(project: Project) -> list[tuple[int, int, bool, bool]]:
    """
    (start, end, writable, executable) of every section of the loaded images. An image loaded as a raw blob (a memory
    dump of a protected process) has no sections in CLE; its own PE section table, which is part of the dump, is used.
    """
    sections: list[tuple[int, int, bool, bool]] = []
    for obj in project.loader.all_objects:
        obj_sections = list(getattr(obj, "sections", None) or ())
        if obj_sections:
            for sec in obj_sections:
                if sec.memsize:
                    sections.append(
                        (sec.vaddr, sec.vaddr + sec.memsize, bool(sec.is_writable), bool(sec.is_executable))
                    )
            continue
        sections += _pe_header_sections(project, obj)
    return sections


def _pe_header_sections(project: Project, obj) -> list[tuple[int, int, bool, bool]]:
    base = getattr(obj, "mapped_base", None)
    if base is None:
        return []
    try:
        header = project.loader.memory.load(base, 0x1000)
    except KeyError:
        return []
    if header[:2] != b"MZ":
        return []
    import pefile  # pylint:disable=import-outside-toplevel

    try:
        pe = pefile.PE(data=bytes(header), fast_load=True)
    except pefile.PEFormatError:
        return []
    return [
        (
            base + sec.VirtualAddress,
            base + sec.VirtualAddress + sec.Misc_VirtualSize,
            bool(sec.Characteristics & _SCN_WRITE),
            bool(sec.Characteristics & _SCN_EXECUTE),
        )
        for sec in pe.sections
        if sec.Misc_VirtualSize
    ]


def _block_const(expr, defs: dict, depth: int = 0) -> int | None:
    """
    The constant an expression evaluates to through earlier block-local tmp and register definitions, if any.
    """
    if depth > 8:
        return None
    if isinstance(expr, Const) and isinstance(expr.value, int):
        return expr.value
    if isinstance(expr, Convert) and expr.from_type == Convert.TYPE_INT and expr.to_type == Convert.TYPE_INT:
        value = _block_const(expr.operand, defs, depth + 1)
        return None if value is None else value & ((1 << expr.to_bits) - 1)
    key = _def_key(expr)
    if key is not None and key in defs:
        return _block_const(defs[key], defs, depth + 1)
    return None


def _def_key(expr) -> tuple | None:
    if isinstance(expr, Tmp):
        return "tmp", expr.tmp_idx
    if isinstance(expr, VirtualVariable):
        return "vvar", expr.varid
    if isinstance(expr, Register):
        return "reg", expr.reg_offset, expr.bits
    return None


def spin_lock_words(graph: networkx.DiGraph) -> set[int]:
    """
    Constant addresses that the function acquires as a spin-lock: a compare-exchange of 0 -> 1 whose old value is
    unused (the spin loop has been resolved by deobfuscation). Operands are resolved through earlier definitions in the
    same block.
    """
    vvar_defs = {}
    for block in graph:
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                vvar_defs[("vvar", stmt.dst.varid)] = stmt.src
    words = set()
    for block in graph:
        defs = dict(vvar_defs)
        for stmt in block.statements:
            if isinstance(stmt, CAS):
                if (
                    stmt.old_hi is None
                    and _block_const(stmt.expd_lo, defs) == 0
                    and _block_const(stmt.data_lo, defs) == 1
                    and _block_const(stmt.addr, defs) is not None
                ):
                    words.add(_block_const(stmt.addr, defs))
            elif isinstance(stmt, SideEffectStatement) and stmt.ret_expr is None and isinstance(stmt.expr, Call):
                call = stmt.expr
                if (
                    isinstance(call.target, str)
                    and call.target in _CMPXCHG_INTRINSICS
                    and call.args is not None
                    and len(call.args) == 3
                    and _block_const(call.args[1], defs) == 1
                    and _block_const(call.args[2], defs) == 0
                    and _block_const(call.args[0], defs) is not None
                ):
                    words.add(_block_const(call.args[0], defs))
            elif isinstance(stmt, Assignment):
                key = _def_key(stmt.dst)
                if key is not None:
                    defs[key] = stmt.src
    return words


class _ConstAccesses(AILBlockViewer):
    """
    (address, size) of every memory access through a constant address.
    """

    def __init__(self):
        super().__init__()
        self.accesses: list[tuple[int, int]] = []

    def _add(self, addr_expr, size: int) -> None:
        addr = _const_value(addr_expr)
        if addr is not None and size > 0:
            self.accesses.append((addr, size))

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        self._add(expr.addr, expr.size)
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx, stmt, block):
        self._add(stmt.addr, stmt.size)
        super()._handle_Store(stmt_idx, stmt, block)

    def _handle_CAS(self, stmt_idx, stmt, block):
        self._add(stmt.addr, stmt.data_lo.size)
        super()._handle_CAS(stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.target, str) and expr.target in _ATOMIC_INTRINSICS and expr.args and expr.bits:
            self._add(expr.args[0], expr.bits // 8)
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


class VMContextLayout:
    """
    Where a devirtualized function's VM keeps its context.

    :ivar sections: The protector's sections: writable and executable image sections holding a VM spin-lock word.
    :ivar regions:  The context proper: in each such section, the span of the data the function addresses by constant.
    """

    __slots__ = ("regions", "sections")

    def __init__(self, sections: list[tuple[int, int]], regions: list[tuple[int, int]]):
        self.sections = sections
        self.regions = regions

    def __bool__(self) -> bool:
        return bool(self.regions)

    def in_region(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self.regions)

    def in_section(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self.sections)


def find_vm_context_layout(
    project: Project, graph: networkx.DiGraph, lock_words: set[int] | None = None
) -> VMContextLayout:
    """
    A writable and executable image section that contains a VM spin-lock word is the protector's own section; the VM
    context is the span of the data the function addresses by constant inside it.

    :param lock_words:  Spin-lock words found at an earlier stage, in addition to the ones still in the graph.
    """
    words = spin_lock_words(graph) | (lock_words or set())
    sections = sorted(
        {
            (lo, hi)
            for lo, hi, writable, executable in image_sections(project)
            if writable and executable and any(lo <= w < hi for w in words)
        }
    )
    if not sections:
        return VMContextLayout([], [])
    walker = _ConstAccesses()
    for block in graph:
        walker.walk(block)
    regions = []
    for lo, hi in sections:
        inside = [(a, size) for a, size in walker.accesses if lo <= a and a + size <= hi]
        if inside:
            regions.append((min(a for a, _ in inside), max(a + size for a, size in inside)))
    return VMContextLayout(sections, regions)


#
# Forwarding helpers
#


class _Purity(AILBlockViewer):
    """
    Whether an expression reads no memory and no mutable state, so it evaluates the same wherever its operands are
    defined.
    """

    def __init__(self):
        super().__init__()
        self.pure = True

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        self.pure = False

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        self.pure = False

    def _handle_Tmp(self, expr_idx, expr, stmt_idx, stmt, block):
        self.pure = False

    def _handle_Register(self, expr_idx, expr, stmt_idx, stmt, block):
        self.pure = False

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self.pure = False

    def _handle_FunctionLikeMacro(self, expr_idx, expr, stmt_idx, stmt, block):
        self.pure = False

    def _handle_MultiStatementExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self.pure = False


def _is_pure(expr: Expression) -> bool:
    if isinstance(expr, (Const, VirtualVariable, StackBaseOffset)):
        return True
    if isinstance(expr, (Load, Call, Tmp, Register, Phi)):
        return False
    viewer = _Purity()
    viewer.walk_expression(expr)
    return viewer.pure


class _StmtFacts(AILBlockViewer):
    """
    Calls, loads, and other barriers inside one statement.
    """

    def __init__(self):
        super().__init__()
        self.calls: list[Call] = []
        self.barrier = False
        self.loads: list[Load] = []

    def reset(self):
        self.calls = []
        self.barrier = False
        self.loads = []

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        self.loads.append(expr)
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if not (isinstance(expr.target, str) and expr.target in PURE_INTRINSIC_CALLS):
            self.calls.append(expr)
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        if dirty_has_side_effects(expr):
            self.barrier = True
        super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_FunctionLikeMacro(self, expr_idx, expr, stmt_idx, stmt, block):
        self.barrier = True
        super()._handle_FunctionLikeMacro(expr_idx, expr, stmt_idx, stmt, block)


def _top_level_call(stmt: Statement) -> Call | None:
    if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
        return stmt.expr
    if isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
        return stmt.src
    return None


#
# Escape analysis
#

# Tainted context bytes at a program point: (top, addrs). top False: addrs are the tainted bytes; top True: every byte
# is tainted except addrs.
SlotTaint = tuple[bool, frozenset[int]]
_ALL_TAINTED: SlotTaint = (True, frozenset())


def _taint_join(a: SlotTaint, b: SlotTaint) -> SlotTaint:
    a_top, a_set = a
    b_top, b_set = b
    if not a_top and not b_top:
        return False, a_set | b_set
    if a_top and b_top:
        return True, a_set & b_set
    return (True, a_set - b_set) if a_top else (True, b_set - a_set)


def _taint_set(state: SlotTaint, addrs: range, tainted: bool) -> SlotTaint:
    top, s = state
    if top:
        return top, (s - frozenset(addrs)) if tainted else (s | frozenset(addrs))
    return top, (s | frozenset(addrs)) if tainted else (s - frozenset(addrs))


def _taint_any(state: SlotTaint, addrs: range) -> bool:
    top, s = state
    if top:
        return any(b not in s for b in addrs)
    return any(b in s for b in addrs)


class _Taint(AILBlockViewer):
    """
    Whether an expression may carry an address inside the VM context.
    """

    def __init__(self, ctx: VMContext, loc):
        super().__init__()
        self.ctx = ctx
        self.loc = loc
        self.hit = False

    def check(self, expr: Expression) -> bool:
        self.hit = False
        self.walk_expression(expr)
        return self.hit

    def _handle_Const(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.value, int) and self.ctx.layout.in_region(expr.value):
            self.hit = True

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.varid in self.ctx.tainted_vvars:
            self.hit = True

    def _handle_Tmp(self, expr_idx, expr, stmt_idx, stmt, block):
        if self.loc is None or (self.loc[0], expr.tmp_idx) in self.ctx.tainted_tmps:
            self.hit = True

    def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op.startswith("Cmp"):
            # a truth value
            return
        if expr.op == "Sub":
            left = _Taint(self.ctx, self.loc).check(expr.operands[0])
            right = _Taint(self.ctx, self.loc).check(expr.operands[1])
            # the distance between two context addresses is an offset
            if left != right:
                self.hit = True
            return
        super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        # condition-code helpers yield flags
        return

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        if self.ctx.load_tainted(expr, self.loc):
            self.hit = True


class SlotValues:
    """
    What the store forwarder knows about context bytes before each statement: the per-byte tokens of its must-analysis.
    Two loads of the same bytes with the same token read the same value: a token stands for the latest execution of
    one statement (a store of a memory-free value, or a load, which then reads the same thing until the bytes are
    written), it reaches a load only if that statement dominates the load, and so (strict SSA) the latest execution
    before any use dominated by both loads is the same one.
    """

    __slots__ = ("origins", "states", "stores")

    def __init__(self, stores: dict):
        self.stores = stores
        self.states: dict[tuple, dict[int, tuple]] = {}
        # (loc, base, size) -> the token a load there creates
        self.origins: dict[tuple, tuple] = {}

    def token(self, loc, base: int, size: int, endness: str):
        """
        The token describing a load of these bytes at this statement, if any, and the value it has if any.
        """
        state = self.states.get(loc)
        token = None
        if state is not None:
            tokens = {state.get(b) for b in range(base, base + size)}
            if len(tokens) == 1:
                token = tokens.pop()
        if token is None:
            token = self.origins.get((loc, base, size))
            if token is None:
                return None
        t_base, t_size, t_endness, value = self.stores[token]
        if (t_base, t_size, t_endness) != (base, size, endness):
            return None
        return token, value


_LINEAR_OPS = frozenset({"Add", "Sub", "Neg", "Mul", "Shl"})


class _Budget(Exception):
    pass


class _Normalizer:
    """
    A canonical form of an expression for deciding taint: Add/Sub/Neg/Mul-by-constant chains become sums of terms with
    coefficients and Xor chains become sets of terms with odd multiplicity, through the definitions of virtual variables
    (SSA: a variable equals its definition evaluated where it is defined). Terms that cancel do not contribute to the
    value, so neither can their taint. Constants inside the VM context are kept as terms of their own, so they never
    fold into other constants.
    """

    MAX_DEPTH = 8
    MAX_NODES = 4000

    def __init__(self, ctx: VMContext):
        self.ctx = ctx
        self.nodes = 0
        self._vvar_keys: dict[int, tuple] = ctx._nf_memo

    def key(self, expr: Expression, loc, depth: int = 0) -> tuple:
        self.nodes += 1
        if self.nodes > self.MAX_NODES:
            raise _Budget
        if isinstance(expr, Const):
            if not isinstance(expr.value, int):
                return ("o", str(expr))
            if self.ctx.layout.in_region(expr.value):
                return ("lin", expr.bits, frozenset({(("C", expr.value), 1)}), 0)
            return ("lin", expr.bits, frozenset(), expr.value & ((1 << expr.bits) - 1))
        if isinstance(expr, VirtualVariable):
            return self._vvar(expr, depth)
        if isinstance(expr, Tmp) and loc is not None:
            return self._tmp(expr, loc, depth)
        if isinstance(expr, BinaryOp):
            if expr.op.startswith("Cmp"):
                return ("cmp", expr.op, tuple(self.key(o, loc, depth) for o in expr.operands))
            if expr.op in _LINEAR_OPS or expr.op == "Xor":
                return self._chain(expr, loc, depth)
            return ("op", expr.op, expr.bits, tuple(self.key(o, loc, depth) for o in expr.operands))
        if isinstance(expr, UnaryOp):
            if expr.op == "Neg":
                return self._chain(expr, loc, depth)
            return ("op", expr.op, expr.bits, (self.key(expr.operand, loc, depth),))
        if isinstance(expr, Convert):
            return ("conv", expr.from_bits, expr.to_bits, expr.is_signed, self.key(expr.operand, loc, depth))
        if isinstance(expr, Load):
            return self._load(expr, loc, depth)
        return ("leaf", expr, loc)

    def _vvar(self, expr: VirtualVariable, depth: int) -> tuple:
        varid = expr.varid
        if varid in self._vvar_keys:
            return self._vvar_keys[varid]
        src = self.ctx._stack_defs.get(varid)
        key = ("V", varid)
        if src is not None and depth < self.MAX_DEPTH and _is_pure_or_loads(src, tmps=True):
            key = self.key(src, self.ctx._def_locs.get(varid), depth + 1)
        self._vvar_keys[varid] = key
        return key

    def _tmp(self, expr: Tmp, loc, depth: int) -> tuple:
        # a temporary is defined once, earlier in its block
        found = self.ctx._tmp_defs.get((loc[0], expr.tmp_idx))
        if found is None or depth >= self.MAX_DEPTH or found[1] >= loc or not _is_pure_or_loads(found[0], tmps=True):
            return ("leaf", expr, loc)
        return self.key(found[0], found[1], depth + 1)

    def _load(self, load: Load, loc, depth: int) -> tuple:
        addr = _const_value(load.addr)
        if addr is not None and self.ctx.layout.in_region(addr):
            values = self.ctx.slot_values
            found = None if values is None or loc is None else values.token(loc, addr, load.size, load.endness)
            if found is not None:
                token, value = found
                if value is not None and token != loc:
                    return self.key(value, loc, depth + 1)
                return ("R", token, addr, load.size)
            return ("S", addr, load.size, loc)
        return ("L", self.key(load.addr, loc, depth), load.size, load, loc)

    def _chain(self, expr, loc, depth) -> tuple:
        bits = expr.bits
        mask = (1 << bits) - 1
        if isinstance(expr, BinaryOp) and expr.op == "Xor":
            terms: dict = {}
            const = 0
            for operand in expr.operands:
                k = self.key(operand, loc, depth)
                if k[0] == "xor" and k[1] == bits:
                    for t in k[2]:
                        terms[t] = terms.get(t, 0) ^ 1
                    const ^= k[3]
                elif k[0] == "lin" and k[1] == bits and not k[2]:
                    const ^= k[3]
                else:
                    terms[k] = terms.get(k, 0) ^ 1
            return ("xor", bits, frozenset(t for t, odd in terms.items() if odd), const & mask)
        terms = {}
        const = 0

        def add(k, coeff):
            nonlocal const
            if k[0] == "lin" and k[1] == bits:
                for t, c in k[2]:
                    terms[t] = (terms.get(t, 0) + c * coeff) & mask
                const = (const + k[3] * coeff) & mask
            else:
                terms[k] = (terms.get(k, 0) + coeff) & mask

        if isinstance(expr, UnaryOp):
            add(self.key(expr.operand, loc, depth), mask)
        elif expr.op in {"Add", "Sub"}:
            add(self.key(expr.operands[0], loc, depth), 1)
            add(self.key(expr.operands[1], loc, depth), 1 if expr.op == "Add" else mask)
        else:
            # Mul or Shl by a constant scales; anything else is a single term
            left = self.key(expr.operands[0], loc, depth)
            right = self.key(expr.operands[1], loc, depth)
            scale = None
            if right[0] == "lin" and not right[2] and (expr.op == "Mul" or right[3] < bits):
                scale = right[3] if expr.op == "Mul" else 1 << right[3]
                other = left
            elif expr.op == "Mul" and left[0] == "lin" and not left[2]:
                scale, other = left[3], right
            if scale is None:
                return ("op", expr.op, bits, (left, right))
            add(other, scale & mask)
        terms = {t: c for t, c in terms.items() if c}
        if not const and len(terms) == 1:
            ((term, coeff),) = terms.items()
            if coeff == 1 and (term[0] == "V" or (term[0] == "xor" and term[1] == bits)):
                # v + 0 is v
                return term
        return ("lin", bits, frozenset(terms.items()), const)

    def tainted(self, key: tuple) -> bool:
        kind = key[0]
        if kind == "xor":
            return any(self._term_tainted(t) for t in key[2])
        if kind == "lin":
            # context constants whose coefficients sum to zero form a distance between context addresses: an offset
            mask = (1 << key[1]) - 1
            if sum(c for t, c in key[2] if t[0] == "C") & mask == 0:
                return any(self._term_tainted(t) for t, _ in key[2] if t[0] != "C")
            return any(self._term_tainted(t) for t, _ in key[2])
        return self._term_tainted(key)

    def _term_tainted(self, key: tuple) -> bool:
        kind = key[0]
        if kind == "C":
            return True
        if kind == "V":
            return key[1] in self.ctx.tainted_vvars
        if kind == "cmp":
            return False
        if kind in ("lin", "xor"):
            return self.tainted(key)
        if kind == "op":
            return any(self.tainted(k) for k in key[3])
        if kind == "conv":
            return self.tainted(key[4])
        if kind == "S":
            state = self.ctx._states.get(key[3], _ALL_TAINTED)
            return _taint_any(state, range(key[1], key[1] + key[2]))
        if kind == "R":
            # what the token's load read
            origin = key[1][1] if key[1][0] == "read" else key[1]
            state = self.ctx._states.get(origin, _ALL_TAINTED)
            return _taint_any(state, range(key[2], key[2] + key[3]))
        if kind == "L":
            _, addr_key, _, load, loc = key
            if self.tainted(addr_key):
                return True
            return self.ctx.stack_load_tainted(load, loc)
        if kind == "leaf":
            return _Taint(self.ctx, key[2]).check(key[1])
        return True


class _PurityWithLoads(_Purity):
    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

    def _handle_Phi(self, expr_idx, expr, stmt_idx, stmt, block):
        self.pure = False


class _PurityWithLoadsAndTmps(_PurityWithLoads):
    def _handle_Tmp(self, expr_idx, expr, stmt_idx, stmt, block):
        pass


def _is_pure_or_loads(expr: Expression, tmps: bool = False) -> bool:
    """
    No calls, phis, registers, side effects or (unless allowed) temporaries: the value is fixed by its operands and
    the memory it reads.
    """
    if isinstance(expr, (Const, VirtualVariable, StackBaseOffset)):
        return True
    if isinstance(expr, Phi):
        return False
    viewer = _PurityWithLoadsAndTmps() if tmps else _PurityWithLoads()
    viewer.walk_expression(expr)
    return viewer.pure


class VMContext:
    """
    Which values may carry an address inside the VM context, and whether such an address escapes.

    A value carries a context address if it is derived from a constant inside the context, or loaded from the
    protector's own memory outside the context, from a context slot or stack location that such a value may have been
    stored to on some path (a flow-sensitive dataflow; slots hold anything on entry), or through a pointer that carries
    one. Flags, comparisons and the distance between two context addresses carry none. The context escapes if such a
    value is stored to memory outside the protector's section and the stack, returned, or used as a jump target.
    Otherwise the protected program holds no pointer into the context: a call can reach it only through an argument
    that carries a context address or points to a stack object one was stored to (``call_may_access``), and a pointer
    that carries none cannot address it -- the reasoning a compiler applies to an alloca whose address does not escape.
    """

    MAX_ROUNDS = 8

    def __init__(self, layout: VMContextLayout, slot_values: SlotValues | None = None):
        self.layout = layout
        self.slot_values = slot_values
        self.tainted_vvars: set[int] = set()
        self.tainted_tmps: set[tuple] = set()
        # stack offsets a context address was stored to, or all of the stack if one was stored to an unknown offset
        self.tainted_stack: set[tuple[int, int]] = set()
        self.stack_tainted = False
        self.escapes = False
        # slot taint before each statement, keyed by ((block addr, block idx), stmt idx)
        self._states: dict[tuple, SlotTaint] = {}
        self._stack_defs: dict[int, Expression] = {}
        self._def_locs: dict[int, tuple] = {}
        # (block key, tmp idx) -> (definition, its location)
        self._tmp_defs: dict[tuple, tuple] = {}
        self._nf_memo: dict[int, tuple] = {}

    @property
    def private(self) -> bool:
        return bool(self.layout) and not self.escapes

    def tainted(self, expr: Expression, loc=None) -> bool:
        """
        :param loc: ((block addr, block idx), stmt idx) of the statement the expression is evaluated in; None for an
                    unknown point, where every slot may be tainted.
        """
        if not _Taint(self, loc).check(expr):
            return False
        normalizer = _Normalizer(self)
        try:
            return normalizer.tainted(normalizer.key(expr, loc))
        except (_Budget, RecursionError):
            return True

    def load_tainted(self, load: Load, loc=None) -> bool:
        addr = _const_value(load.addr)
        if addr is not None:
            if self.layout.in_region(addr):
                state = self._states.get(loc, _ALL_TAINTED)
                return _taint_any(state, range(addr, addr + load.size))
            # other protector data may hold context addresses
            return self.layout.in_section(addr)
        if self.tainted(load.addr, loc):
            return True
        return self.stack_load_tainted(load, loc)

    def stack_load_tainted(self, load: Load, loc=None) -> bool:
        """
        Whether a load through an untainted address may read a context address the function stored to the stack.
        """
        if not self.is_stack_address(load.addr):
            return False
        offset = self.stack_offset(load.addr)
        if self.stack_tainted or (offset is None and self.tainted_stack):
            return True
        return offset is not None and any(lo < offset + load.size and offset < hi for lo, hi in self.tainted_stack)

    def is_stack_address(self, expr: Expression, depth: int = 0) -> bool:
        if depth > 8:
            return False
        if isinstance(expr, StackBaseOffset):
            return True
        if isinstance(expr, UnaryOp) and expr.op == "Reference":
            return isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack
        if isinstance(expr, BinaryOp) and expr.op in {"Add", "Sub"}:
            left = self.is_stack_address(expr.operands[0], depth + 1)
            right = self.is_stack_address(expr.operands[1], depth + 1)
            return left != right if expr.op == "Add" else left and not right
        if isinstance(expr, Convert):
            return self.is_stack_address(expr.operand, depth + 1)
        if isinstance(expr, VirtualVariable):
            src = self._stack_defs.get(expr.varid)
            return src is not None and self.is_stack_address(src, depth + 1)
        return False

    def stack_offset(self, expr: Expression, depth: int = 0) -> int | None:
        if depth > 8:
            return None
        if isinstance(expr, StackBaseOffset):
            return expr.offset
        if isinstance(expr, UnaryOp) and expr.op == "Reference":
            operand = expr.operand
            return operand.stack_offset if isinstance(operand, VirtualVariable) and operand.was_stack else None
        if isinstance(expr, BinaryOp) and expr.op in {"Add", "Sub"}:
            const = _const_value(expr.operands[1])
            if const is None and expr.op == "Add":
                const, other = _const_value(expr.operands[0]), expr.operands[1]
            else:
                other = expr.operands[0]
            base = None if const is None else self.stack_offset(other, depth + 1)
            if base is None:
                return None
            bits = expr.bits
            const = const - (1 << bits) if const >= 1 << (bits - 1) else const
            return base + const if expr.op == "Add" else base - const
        if isinstance(expr, Convert):
            return self.stack_offset(expr.operand, depth + 1)
        if isinstance(expr, VirtualVariable):
            src = self._stack_defs.get(expr.varid)
            return None if src is None else self.stack_offset(src, depth + 1)
        return None

    def call_may_access(self, call: Call, loc=None) -> bool:
        """
        Whether a call may read or write the context: only through an argument (or target) carrying its address, or a
        stack object a context address was stored to.
        """
        if not self.private:
            return True
        if not isinstance(call.target, str) and self.tainted(call.target, loc):
            return True
        for arg in call.args or ():
            if self.tainted(arg, loc):
                return True
            if (self.stack_tainted or self.tainted_stack) and self.is_stack_address(arg):
                # the callee may access the stack object the argument points to, which lies at or above it
                offset = self.stack_offset(arg)
                if self.stack_tainted or offset is None or any(hi > offset for _, hi in self.tainted_stack):
                    return True
        return False

    def private_bytes(self, addrs) -> frozenset[int]:
        return frozenset(b for b in addrs if self.layout.in_region(b)) if self.private else frozenset()

    @classmethod
    def analyze(
        cls,
        graph: networkx.DiGraph,
        layout: VMContextLayout,
        blocks: dict | None = None,
        slot_values: SlotValues | None = None,
    ) -> VMContext:
        """
        :param blocks:      Maps graph nodes to their up-to-date blocks, if any.
        :param slot_values: The store forwarder's knowledge of context bytes, which lets taint cancel between loads.
        """
        ctx = cls(layout, slot_values)
        if not layout:
            return ctx
        current = (lambda node: blocks.get(node, node)) if blocks else (lambda node: node)
        for node in graph:
            block = current(node)
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    ctx._stack_defs[stmt.dst.varid] = stmt.src
                    ctx._def_locs[stmt.dst.varid] = ((block.addr, block.idx), idx)
                elif isinstance(stmt, Assignment) and isinstance(stmt.dst, Tmp):
                    key = (block.addr, block.idx)
                    ctx._tmp_defs[(key, stmt.dst.tmp_idx)] = (stmt.src, (key, idx))
        facts = _StmtFacts()

        def summary():
            return (
                len(ctx.tainted_vvars),
                len(ctx.tainted_tmps),
                ctx.stack_tainted,
                len(ctx.tainted_stack),
                ctx.escapes,
            )

        for _ in range(cls.MAX_ROUNDS):
            before = summary()
            ctx._dataflow(graph, current, facts)
            if ctx.escapes:
                return ctx
            if before == summary():
                return ctx
        ctx.escapes = True
        return ctx

    def _dataflow(self, graph: networkx.DiGraph, current, facts: _StmtFacts) -> None:
        out_states: dict = {}
        heads = [n for n in graph if graph.in_degree(n) == 0]
        worklist = list(heads) + [n for n in graph if n not in set(heads)]
        in_worklist = set(worklist)
        while worklist:
            node = worklist.pop(0)
            in_worklist.discard(node)
            state = self._in_state(graph, node, out_states)
            block = current(node)
            key = (block.addr, block.idx)
            for idx, stmt in enumerate(block.statements):
                self._states[(key, idx)] = state
                state = self._visit(stmt, (key, idx), state, facts)
                if self.escapes:
                    return
            if out_states.get(node) == state:
                continue
            out_states[node] = state
            for succ in graph.successors(node):
                if succ not in in_worklist:
                    worklist.append(succ)
                    in_worklist.add(succ)

    @staticmethod
    def _in_state(graph, node, out_states) -> SlotTaint:
        preds = list(graph.predecessors(node))
        if not preds:
            # slots hold whatever earlier code left there
            return _ALL_TAINTED
        state = None
        for pred in preds:
            if pred in out_states:
                state = out_states[pred] if state is None else _taint_join(state, out_states[pred])
        return state if state is not None else (False, frozenset())

    def _write(self, addr: Expression, data: Expression, size: int, loc, state: SlotTaint) -> SlotTaint:
        tainted = self.tainted(data, loc)
        base = _const_value(addr)
        if base is not None:
            if self.layout.in_region(base):
                return _taint_set(state, range(base, base + size), tainted)
            if tainted and not self.layout.in_section(base):
                self.escapes = True
            return state
        if not tainted:
            return state
        if self.tainted(addr, loc):
            return _ALL_TAINTED
        if self.is_stack_address(addr):
            offset = self.stack_offset(addr)
            if offset is None:
                self.stack_tainted = True
            else:
                self.tainted_stack.add((offset, offset + size))
            return state
        self.escapes = True
        return state

    def _visit(self, stmt: Statement, loc, state: SlotTaint, facts: _StmtFacts) -> SlotTaint:
        facts.reset()
        facts.walk_statement(stmt)
        if facts.barrier:
            viewer = _Taint(self, loc)
            viewer.walk_statement(stmt)
            if viewer.hit:
                self.escapes = True
                return state
        new_state = state
        for call in facts.calls:
            args = list(call.args or ())
            if isinstance(call.target, str) and call.target in _ATOMIC_INTRINSICS and args:
                for arg in args[1:]:
                    new_state = self._write(args[0], arg, max(call.bits // 8, 1), loc, new_state)
            elif self.call_may_access(call, loc):
                # the callee may store anything into the context
                new_state = _ALL_TAINTED
        if isinstance(stmt, Assignment):
            if self.tainted(stmt.src, loc):
                if isinstance(stmt.dst, VirtualVariable):
                    self.tainted_vvars.add(stmt.dst.varid)
                elif isinstance(stmt.dst, Tmp):
                    self.tainted_tmps.add((loc[0], stmt.dst.tmp_idx))
                else:
                    self.escapes = True
        elif isinstance(stmt, Store):
            new_state = self._write(stmt.addr, stmt.data, stmt.size, loc, new_state)
        elif isinstance(stmt, CAS):
            for data in (stmt.data_lo, stmt.data_hi):
                if data is not None:
                    new_state = self._write(stmt.addr, data, stmt.data_lo.size, loc, new_state)
        elif isinstance(stmt, (Return, Jump, ConditionalJump)):
            if isinstance(stmt, ConditionalJump):
                exprs = [t for t in (stmt.true_target, stmt.false_target) if t is not None]
            elif isinstance(stmt, Jump):
                exprs = [stmt.target]
            else:
                exprs = list(stmt.ret_exprs or ())
            if any(self.tainted(e, loc) for e in exprs):
                self.escapes = True
        return new_state


class VMContextStoreForwarder:
    """
    Forward stores into the VM context to the loads that must read them. See the module docstring.

    Copies of one block (Clinic duplicates a flag-test block per predecessor) share their address, which is all a jump
    target names, so a later merge of a conditional jump's equal targets cannot tell them apart; they are rewritten only
    if every copy becomes the same.
    """

    MAX_ROUNDS = 8

    def __init__(
        self,
        graph: networkx.DiGraph,
        layout: VMContextLayout,
        ail_manager,
        call_reads: CallGlobalReads | None = None,
        entry_addr: int | None = None,
        new_vvar_id=None,
        named_vvars: set[int] | None = None,
    ):
        self.graph = graph
        self._new_vvar_id = new_vvar_id
        # stores whose memory-reading value a load would be forwarded to once it is named
        self._to_name: set[tuple] = set()
        self._named: set[int] = named_vvars if named_vvars is not None else set()
        self.layout = layout
        self._entry_addr = entry_addr
        self.ctx = VMContext(layout)
        self._ail_manager = ail_manager
        self._call_reads = call_reads
        self._tokens: dict[tuple, list] = {}
        self.forwarded = 0
        self.slot_values: SlotValues | None = None

    def _store_effect(self, stmt: Store, key, state: dict[int, tuple], stores: dict) -> dict[int, tuple] | None:
        """
        Apply a store; None means it may write any VM-context byte.
        """
        base = _const_value(stmt.addr)
        if base is None:
            if self.ctx.is_stack_address(stmt.addr) or (self.ctx.private and not self.ctx.tainted(stmt.addr, key)):
                return state
            return None
        if stmt.size <= 0:
            return None
        written = [b for b in range(base, base + stmt.size) if self.layout.in_region(b)]
        if not written:
            return state
        state = dict(state)
        token = None
        if stmt.guard is None and stmt.data.bits == stmt.size * 8:
            if _is_pure(stmt.data):
                token = self._token(key, (base, stmt.size, stmt.endness, stmt.data), stores)
            elif len(written) == stmt.size and _is_pure_or_loads(stmt.data):
                # the value read from memory when stored: it identifies the bytes, and naming it makes it forwardable
                token = ("stored", key, base, stmt.size)
                stores[token] = (base, stmt.size, stmt.endness, None)
        for b in written:
            if token is None:
                state.pop(b, None)
            else:
                state[b] = token
        return state

    def _token(self, key, store, stores: dict):
        """
        Stores of the same value to the same bytes share a token, so a merge of them still forwards.
        """
        base, size, endness, value = store
        bucket = self._tokens.setdefault((base, size, endness), [])
        for token in bucket:
            if stores[token][3].likes(value):
                return token
        bucket.append(key)
        stores[key] = store
        return key

    @staticmethod
    def _kill(state: dict[int, tuple], ranges) -> dict[int, tuple]:
        if not state or not ranges:
            return state
        return {b: t for b, t in state.items() if not any(lo <= b < hi for lo, hi in ranges)}

    def _call_writes(self, call: Call, loc) -> list[tuple[int, int]] | None:
        """
        Global ranges a call may write; None if it may write every byte.
        """
        if isinstance(call.target, str) and call.target in _ATOMIC_INTRINSICS:
            addr = _const_value(call.args[0]) if call.args else None
            if addr is None or not call.bits:
                return None
            return [(addr, addr + call.bits // 8)]
        if not self.ctx.call_may_access(call, loc):
            return []
        if self._call_reads is None:
            return None
        return self._call_reads.writes(call)

    def _block_pass(self, block, state, facts: _StmtFacts, stores, pre_states, values: SlotValues | None = None):
        key = (block.addr, block.idx)
        for idx, stmt in enumerate(block.statements):
            facts.reset()
            facts.walk_statement(stmt)
            barrier = facts.barrier or bool(facts.calls) or isinstance(stmt, (CAS, DirtyStatement))
            if pre_states is not None and facts.loads and state:
                forwardable = not barrier or (
                    not facts.barrier and len(facts.calls) == 1 and _top_level_call(stmt) is not None
                )
                if forwardable:
                    pre_states[(key, idx)] = state
            if not barrier and facts.loads:
                if values is not None and state:
                    values.states[(key, idx)] = state
                state = self._load_tokens(stmt, (key, idx), facts.loads, state, stores, values)
            if barrier:
                if facts.barrier or isinstance(stmt, DirtyStatement):
                    state = {}
                    continue
                if isinstance(stmt, CAS):
                    addr = _const_value(stmt.addr)
                    size = stmt.data_lo.size * (2 if stmt.data_hi is not None else 1)
                    state = {} if addr is None else self._kill(state, [(addr, addr + size)])
                    continue
                for call in facts.calls:
                    ranges = self._call_writes(call, (key, idx))
                    state = {} if ranges is None else self._kill(state, ranges)
                if not isinstance(stmt, Store):
                    continue
            if isinstance(stmt, Store):
                new_state = self._store_effect(stmt, (key, idx), state, stores)
                state = {} if new_state is None else new_state
        return state

    def _load_tokens(self, stmt, loc, loads, state, stores, values: SlotValues | None) -> dict[int, tuple]:
        """
        After a load of context bytes that no token describes, the bytes hold what it read until something writes them.
        The value is v after v = Load(a), as after a store of v; otherwise it has no expression and only identifies the
        read (see SlotValues).
        """
        for load in loads:
            base = _const_value(load.addr)
            if base is None or load.guard is not None or load.size <= 0:
                continue
            span = range(base, base + load.size)
            if not all(self.layout.in_region(b) for b in span) or all(b in state for b in span):
                continue
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and isinstance(stmt.src, Load)
                and stmt.src.likes(load)
                and stmt.dst.bits == load.size * 8
            ):
                token = self._token(loc, (base, load.size, load.endness, stmt.dst), stores)
            elif any(b in state for b in span):
                # a read token has no value; it must not hide a known one
                continue
            else:
                token = ("read", loc, base, load.size)
                stores[token] = (base, load.size, load.endness, None)
            if values is not None:
                values.origins[(loc, base, load.size)] = token
            state = dict(state)
            for b in span:
                state[b] = token
        return state

    def _solve(self):
        self._tokens = {}
        facts = _StmtFacts()
        stores: dict = {}
        out_states: dict = {}
        entries = self._entries()
        # blocks unreachable from the entry never run; as predecessors they must not dilute a merge
        worklist = list(entries)
        in_worklist = set(worklist)
        while worklist:
            node = worklist.pop(0)
            in_worklist.discard(node)
            state = {} if node in entries else self._in_state(node, out_states)
            out = self._block_pass(node, state, facts, stores, None)
            if out_states.get(node) == out:
                continue
            out_states[node] = out
            for succ in self.graph.successors(node):
                if succ not in in_worklist:
                    worklist.append(succ)
                    in_worklist.add(succ)
        pre_states: dict = {}
        values = SlotValues(stores)
        for node in self.graph:
            if node in out_states:
                state = {} if node in entries else self._in_state(node, out_states)
                self._block_pass(node, state, facts, stores, pre_states, values)
        self.slot_values = values
        return stores, pre_states

    def _entries(self) -> set:
        heads = [n for n in self.graph if self.graph.in_degree(n) == 0]
        if self._entry_addr is not None:
            entries = {n for n in self.graph if n.addr == self._entry_addr}
            if entries:
                return entries
        return set(heads)

    def _in_state(self, node, out_states) -> dict:
        state = None
        for pred in self.graph.predecessors(node):
            if pred not in out_states:
                # not reached (yet): top
                continue
            pred_out = out_states[pred]
            if state is None:
                state = dict(pred_out)
            else:
                state = {b: t for b, t in state.items() if pred_out.get(b) == t}
            if not state:
                return {}
        return state or {}

    #
    # rewriting
    #

    def _replacement(self, load: Load, state: dict, stores: dict) -> Expression | None:
        addr = _const_value(load.addr)
        if addr is None or load.size <= 0 or load.guard is not None:
            return None
        tokens = [state.get(b) for b in range(addr, addr + load.size)]
        if None in tokens:
            return None
        if any(stores[t][3] is None for t in set(tokens)):
            if len(set(tokens)) == 1 and tokens[0][0] == "stored":
                _, store_loc, base, size = tokens[0]
                if base == addr and size == load.size and stores[tokens[0]][2] == load.endness:
                    self._to_name.add(store_loc)
            return None
        if len(set(tokens)) == 1:
            base, size, endness, value = stores[tokens[0]]
            if endness == load.endness and addr == base and load.size == size:
                return value
        if load.endness != "Iend_LE":
            return None
        # little-endian: assemble the loaded bytes from the stores that wrote them
        tags = dict(load.tags)
        bits = load.size * 8
        result = None
        start = 0
        while start < load.size:
            token = tokens[start]
            end = start
            while end < load.size and tokens[end] == token:
                end += 1
            base, size, endness, value = stores[token]
            if endness != "Iend_LE" or value.bits != size * 8:
                return None
            if _const_value(value) != 0:
                piece = self._bytes_of(value, addr + start - base, end - start, tags)
                if piece.bits != bits:
                    piece = Convert(self._ail_manager.next_atom(), piece.bits, bits, False, piece, **tags)
                if start:
                    piece = self._shift(piece, "Shl", start * 8, tags)
                result = (
                    piece
                    if result is None
                    else BinaryOp(self._ail_manager.next_atom(), "Or", [result, piece], False, bits=bits, **tags)
                )
            start = end
        return result if result is not None else Const(self._ail_manager.next_atom(), 0, bits, **tags)

    def _shift(self, value: Expression, op: str, amount: int, tags) -> Expression:
        return BinaryOp(
            self._ail_manager.next_atom(),
            op,
            [value, Const(self._ail_manager.next_atom(), amount, 8)],
            False,
            bits=value.bits,
            **tags,
        )

    def _bytes_of(self, value: Expression, offset: int, size: int, tags) -> Expression:
        """
        ``size`` bytes of a little-endian value starting at byte ``offset``.
        """
        if offset == 0 and size * 8 == value.bits:
            return value
        if offset:
            value = self._shift(value, "Shr", offset * 8, tags)
        return Convert(self._ail_manager.next_atom(), value.bits, size * 8, False, value, **tags)

    def _rewrite(self, stores, pre_states) -> int:
        forwarder = self

        class _Rewriter(AILBlockRewriter):
            def __init__(self):
                super().__init__(update_block=False)
                self.state = None
                self.count = 0

            def _handle_stmt(self, stmt_idx, stmt, block):
                self.state = pre_states.get(((block.addr, block.idx), stmt_idx))
                if self.state is None:
                    return stmt
                return super()._handle_stmt(stmt_idx, stmt, block)

            def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
                rebuilt = super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
                current = rebuilt if rebuilt is not None else expr
                repl = forwarder._replacement(current, self.state, stores)
                if repl is None:
                    return rebuilt
                self.count += 1
                return repl

        rewriter = _Rewriter()
        keys = {key for key, _ in pre_states}
        copies: dict[int, list] = defaultdict(list)
        for block in self.graph:
            copies[block.addr].append(block)
        count = 0
        for group in copies.values():
            if not any((block.addr, block.idx) in keys for block in group):
                continue
            rewritten = []
            group_count = 0
            for block in group:
                rewriter.count = 0
                new_block = rewriter.walk(block)
                rewritten.append(block.statements if new_block is None else list(new_block.statements))
                group_count += rewriter.count
            if not group_count:
                continue
            if len(group) > 1 and not all(
                len(stmts) == len(rewritten[0]) and all(a.likes(b) for a, b in zip(stmts, rewritten[0]))
                for stmts in rewritten[1:]
            ):
                continue
            for block, stmts in zip(group, rewritten):
                block.statements = stmts
            count += group_count
        return count

    def _name_stored_values(self) -> int:
        """
        Store(a, e) -> v = e; Store(a, v): the same evaluation at the same point, with a name loads can be forwarded to.
        """
        if not self._to_name or self._new_vvar_id is None:
            return 0
        copies = defaultdict(int)
        for block in self.graph:
            copies[block.addr] += 1
        named = 0
        for block in self.graph:
            if copies[block.addr] > 1:
                continue
            todo = sorted(
                (loc[1] for loc in self._to_name if loc[0] == (block.addr, block.idx)),
                reverse=True,
            )
            if not todo:
                continue
            stmts = list(block.statements)
            for idx in todo:
                stmt = stmts[idx]
                if not isinstance(stmt, Store):
                    continue
                varid = self._new_vvar_id()
                vvar = VirtualVariable(
                    self._ail_manager.next_atom(),
                    varid,
                    stmt.data.bits,
                    VirtualVariableCategory.TMP,
                    oident=varid,
                    **stmt.tags,
                )
                stmts[idx : idx + 1] = [
                    Assignment(self._ail_manager.next_atom(), vvar, stmt.data, **stmt.tags),
                    Store(stmt.idx, stmt.addr, vvar, stmt.size, stmt.endness, stmt.guard, **stmt.tags),
                ]
                named += 1
                self._named.add(varid)
            block.statements = stmts
        self._to_name = set()
        return named

    def run(self) -> int:
        if not self.layout or self._ail_manager is None:
            return 0
        for _ in range(self.MAX_ROUNDS):
            self.ctx = VMContext.analyze(self.graph, self.layout)
            self._solve()
            self.ctx = VMContext.analyze(self.graph, self.layout, slot_values=self.slot_values)
            stores, pre_states = self._solve()
            if not pre_states:
                break
            self._to_name = set()
            count = self._rewrite(stores, pre_states)
            named = self._name_stored_values()
            if not count and not named:
                break
            self.forwarded += count
        self._unname()
        return self.forwarded

    def _unname(self) -> None:
        """
        Replace a name by its value where that is exact and keeps the value's evaluation point: a memory-free value
        anywhere it is used (SSA: its operands' definitions dominate every use of the name), a value that reads memory
        only in the store right after it, which is the name's only use.
        """
        if not self._named:
            return
        uses: dict[int, int] = defaultdict(int)
        in_phis: set[int] = set()
        defs: dict[int, tuple] = {}

        class _Uses(AILBlockViewer):
            def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
                uses[expr.varid] += 1

            def _handle_Phi(self, expr_idx, expr, stmt_idx, stmt, block):
                for _, vvar in expr.src_and_vvars:
                    if vvar is not None:
                        uses[vvar.varid] += 1
                        in_phis.add(vvar.varid)

        viewer = _Uses()
        for block in self.graph:
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    if stmt.dst.varid in self._named:
                        defs[stmt.dst.varid] = (block, idx)
                    viewer.walk_expression(stmt.src)
                else:
                    viewer.walk_statement(stmt)
        replace: dict[int, Expression] = {}
        drop: set[int] = set()
        for varid, (block, idx) in defs.items():
            src = block.statements[idx].src
            nxt = block.statements[idx + 1] if idx + 1 < len(block.statements) else None
            if isinstance(src, VirtualVariable) or (_is_pure(src) and varid not in in_phis):
                replace[varid] = src
                drop.add(varid)
            elif (
                uses[varid] == 1
                and isinstance(nxt, Store)
                and isinstance(nxt.data, VirtualVariable)
                and nxt.data.varid == varid
            ):
                replace[varid] = src
                drop.add(varid)
        if not replace:
            return
        for varid in list(replace):
            seen = {varid}
            value = replace[varid]
            while isinstance(value, VirtualVariable) and value.varid in replace and value.varid not in seen:
                seen.add(value.varid)
                value = replace[value.varid]
            replace[varid] = value

        class _Replace(AILBlockRewriter):
            def __init__(self):
                super().__init__(update_block=False)

            def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
                return replace.get(expr.varid, expr)

        rewriter = _Replace()
        for block in self.graph:
            stmts = []
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid in drop:
                    continue
                new_stmt = rewriter.walk_statement(stmt, block=block)
                stmts.append(stmt if new_stmt is None else new_stmt)
            block.statements = stmts
        self._named -= drop


def analyze_vm_context(graph: networkx.DiGraph, layout: VMContextLayout, blocks: dict | None = None) -> VMContext:
    """
    VMContext.analyze, informed by what the store forwarder knows about context bytes.
    """
    ctx = VMContext.analyze(graph, layout, blocks)
    if not layout:
        return ctx
    if blocks:
        graph = networkx.relabel_nodes(graph, {node: blocks[node] for node in graph if node in blocks}, copy=True)
    forwarder = VMContextStoreForwarder(graph, layout, None)
    forwarder.ctx = ctx
    forwarder._solve()  # pylint:disable=protected-access
    return VMContext.analyze(graph, layout, slot_values=forwarder.slot_values)


class _SlotAccesses(AILBlockViewer):
    """
    Constant-address accesses of VM-context bytes in one statement: (base, size, endness, is load).
    """

    def __init__(self, layout: VMContextLayout):
        super().__init__()
        self.layout = layout
        self.accesses: list[tuple[int, int, str, bool]] = []
        # bytes accessed other than by a plain load or store (atomics, CAS)
        self.other: set[int] = set()

    def _const_in(self, addr_expr) -> int | None:
        addr = _const_value(addr_expr)
        return addr if addr is not None and self.layout.in_region(addr) else None

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        base = self._const_in(expr.addr)
        if base is not None:
            if expr.guard is not None:
                self.other.update(range(base, base + expr.size))
            else:
                self.accesses.append((base, expr.size, expr.endness, True))
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx, stmt, block):
        base = self._const_in(stmt.addr)
        if base is not None:
            if stmt.guard is not None or stmt.data.bits != stmt.size * 8:
                self.other.update(range(base, base + stmt.size))
            else:
                self.accesses.append((base, stmt.size, stmt.endness, False))
        super()._handle_Store(stmt_idx, stmt, block)

    def _handle_CAS(self, stmt_idx, stmt, block):
        base = _const_value(stmt.addr)
        if base is not None:
            self.other.update(range(base, base + stmt.data_lo.size * (2 if stmt.data_hi is not None else 1)))
        super()._handle_CAS(stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.target, str) and expr.target in _ATOMIC_INTRINSICS and expr.args:
            base = _const_value(expr.args[0])
            if base is not None:
                self.other.update(range(base, base + max(expr.bits // 8, 8)))
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


class VMContextSlotPromoter:
    """
    Promote slots of a private VM context to SSA variables (mem2reg), for what store forwarding cannot express: a VM
    register carried around a loop, a flag set on some paths.

    Exact when (1) the context is private, (2) every access to the slot's bytes is a whole-slot load or store by
    constant address, (3) nothing else may write it: no store through a pointer that may carry a context address, no
    call that may access the context, no unmodelled side effect, no atomic on it, and (4) every path from the entry to
    a promoted load stores the slot first. Then a load reads the value of the last store executed, which SSA
    construction names at every point. The stores stay; dead-store elimination decides about them.
    """

    def __init__(
        self,
        graph: networkx.DiGraph,
        layout: VMContextLayout,
        ail_manager,
        new_vvar_id,
        entry_addr=None,
        stack_addresses_only: bool = False,
    ):
        self.graph = graph
        self.layout = layout
        self._ail_manager = ail_manager
        self._new_vvar_id = new_vvar_id
        self._entry_addr = entry_addr
        # only slots that always hold a stack address (a VM stack or frame pointer)
        self._stack_addresses_only = stack_addresses_only
        self.promoted_loads = 0
        self.names: set[int] = set()

    def run(self) -> int:
        if not self.layout or self._ail_manager is None or self._new_vvar_id is None:
            return 0
        entry = self._entry()
        if entry is None:
            return 0
        if self._stack_addresses_only and not self._stores_stack_address():
            return 0
        ctx = analyze_vm_context(self.graph, self.layout)
        if not ctx.private:
            return 0
        slots = self._slots(ctx)
        if not slots:
            return 0
        copies = defaultdict(int)
        for block in self.graph:
            copies[block.addr] += 1
        idom = networkx.immediate_dominators(self.graph, entry)
        frontiers = networkx.dominance_frontiers(self.graph, entry)
        children = defaultdict(list)
        for node, dom in idom.items():
            if node is not dom:
                children[dom].append(node)
        order = []
        stack = [entry]
        while stack:
            node = stack.pop()
            order.append(node)
            stack.extend(children[node])
        for base, size, endness in slots:
            self.promoted_loads += self._promote(base, size, endness, entry, idom, frontiers, order, copies)
        return self.promoted_loads

    def _entry(self):
        heads = [n for n in self.graph if self.graph.in_degree(n) == 0]
        if self._entry_addr is not None:
            entries = [n for n in self.graph if n.addr == self._entry_addr]
            if len(entries) == 1 and self.graph.in_degree(entries[0]) == 0:
                return entries[0]
        return heads[0] if len(heads) == 1 else None

    def _slots(self, ctx: VMContext) -> list[tuple[int, int, str]]:
        facts = _StmtFacts()
        scan = _SlotAccesses(self.layout)
        for block in self.graph:
            key = (block.addr, block.idx)
            for idx, stmt in enumerate(block.statements):
                loc = (key, idx)
                facts.reset()
                facts.walk_statement(stmt)
                if facts.barrier or isinstance(stmt, DirtyStatement):
                    return []
                for call in facts.calls:
                    if isinstance(call.target, str) and call.target in _ATOMIC_INTRINSICS and call.args:
                        if _const_value(call.args[0]) is None and ctx.tainted(call.args[0], loc):
                            return []
                    elif ctx.call_may_access(call, loc):
                        return []
                if isinstance(stmt, (Store, CAS)) and _const_value(stmt.addr) is None:
                    if not ctx.is_stack_address(stmt.addr) and ctx.tainted(stmt.addr, loc):
                        return []
                scan.walk_statement(stmt, block=block)
        shapes: dict[int, set] = defaultdict(set)
        stored: set[tuple] = set()
        loaded: set[tuple] = set()
        for base, size, endness, is_load in scan.accesses:
            for b in range(base, base + size):
                shapes[b].add((base, size, endness))
            (loaded if is_load else stored).add((base, size, endness))
        slots = []
        for shape in loaded & stored:
            base, size, _ = shape
            span = range(base, base + size)
            if any(b in scan.other or shapes[b] != {shape} for b in span):
                continue
            if self._stack_addresses_only and not self._holds_stack_address(ctx, base, size):
                continue
            slots.append(shape)
        return sorted(slots)

    def _stores_stack_address(self) -> bool:
        """
        Cheap check before the context analysis: some constant-address store into the context stores a stack address.
        """
        ctx = VMContext(self.layout)
        for block in self.graph:
            for stmt in block.statements:
                if isinstance(stmt, Store) and (addr := _const_value(stmt.addr)) is not None:
                    if self.layout.in_region(addr) and ctx.is_stack_address(stmt.data):
                        return True
        return False

    def _holds_stack_address(self, ctx: VMContext, base: int, size: int) -> bool:
        """
        Whether every store to the slot stores a stack address, counting the slot's own value as one.
        """

        def stack_like(expr, key, idx, depth=0) -> bool:
            if depth > 16:
                return False
            if ctx.is_stack_address(expr) or self._is_load(expr, base, size):
                return True
            if isinstance(expr, BinaryOp) and expr.op in {"Add", "Sub"}:
                if _const_value(expr.operands[1]) is not None:
                    return stack_like(expr.operands[0], key, idx, depth + 1)
                if expr.op == "Add" and _const_value(expr.operands[0]) is not None:
                    return stack_like(expr.operands[1], key, idx, depth + 1)
                return False
            if isinstance(expr, Tmp):
                found = ctx._tmp_defs.get((key, expr.tmp_idx))
                return found is not None and found[1][1] < idx and stack_like(found[0], key, found[1][1], depth + 1)
            if isinstance(expr, VirtualVariable):
                src = ctx._stack_defs.get(expr.varid)
                loc = ctx._def_locs.get(expr.varid)
                return src is not None and not isinstance(src, Phi) and stack_like(src, loc[0], loc[1], depth + 1)
            return False

        found = False
        for block in self.graph:
            key = (block.addr, block.idx)
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Store) and _const_value(stmt.addr) == base and stmt.size == size:
                    if not stack_like(stmt.data, key, idx):
                        return False
                    found = True
        return found

    def _is_load(self, expr, base, size) -> bool:
        return isinstance(expr, Load) and _const_value(expr.addr) == base and expr.size == size and expr.guard is None

    def _promote(self, base, size, endness, entry, idom, frontiers, order, copies) -> int:
        bits = size * 8
        reachable = set(idom) | {entry}
        promoter = self

        def is_load(expr) -> bool:
            return promoter._is_load(expr, base, size)

        class _Finder(AILBlockViewer):
            def __init__(self):
                super().__init__()
                self.found = False

            def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
                if is_load(expr):
                    self.found = True
                super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

        finder = _Finder()

        def stores_slot(stmt) -> bool:
            return isinstance(stmt, Store) and _const_value(stmt.addr) == base and stmt.size == size

        def loads_slot(stmt) -> bool:
            finder.found = False
            finder.walk_statement(stmt)
            return finder.found

        def_blocks = {n for n in reachable if any(stores_slot(st) for st in n.statements)}
        use_blocks = {n for n in reachable if any(loads_slot(st) for st in n.statements)}
        if not use_blocks or any(copies[n.addr] > 1 for n in def_blocks | use_blocks):
            return 0
        # phi placement: the iterated dominance frontier of the stores
        phi_blocks: set = set()
        work = list(def_blocks)
        while work:
            node = work.pop()
            for df in frontiers.get(node, ()):
                if df not in phi_blocks:
                    phi_blocks.add(df)
                    if df not in def_blocks:
                        work.append(df)
        # values: ("phi", node) | ("store", node, idx) | None (undefined: what the slot held on entry)
        out_value: dict = {}
        load_values: list = []
        for node in order:
            value = ("phi", node) if node in phi_blocks else (out_value[idom[node]] if node is not entry else None)
            for idx, stmt in enumerate(node.statements):
                if loads_slot(stmt):
                    load_values.append((node, idx, value))
                if stores_slot(stmt):
                    value = ("store", node, idx)
            out_value[node] = value
        # the phis loads depend on, and their operands must be defined
        needed: set = set()
        work = [v[1] for _, _, v in load_values if v is not None and v[0] == "phi"]
        if any(v is None for _, _, v in load_values):
            return 0
        while work:
            node = work.pop()
            if node in needed:
                continue
            if copies[node.addr] > 1:
                return 0
            needed.add(node)
            for pred in self.graph.predecessors(node):
                if pred not in reachable:
                    continue
                operand = out_value[pred]
                if operand is None:
                    return 0
                if operand[0] == "phi":
                    work.append(operand[1])
        # name the stored values and the phis
        names: dict = {}

        def new_vvar(tags):
            varid = self._new_vvar_id()
            self.names.add(varid)
            return VirtualVariable(
                self._ail_manager.next_atom(), varid, bits, VirtualVariableCategory.TMP, oident=varid, **tags
            )

        used_stores = {v for _, _, v in load_values if v[0] == "store"}
        for node in needed:
            for pred in self.graph.predecessors(node):
                if pred in reachable and out_value[pred][0] == "store":
                    used_stores.add(out_value[pred])
        for node in needed:
            names[("phi", node)] = new_vvar({"ins_addr": node.addr})
        to_name = []
        for value in used_stores:
            _, node, idx = value
            stmt = node.statements[idx]
            if isinstance(stmt.data, VirtualVariable) and stmt.data.bits == bits:
                names[value] = stmt.data
            else:
                names[value] = new_vvar(stmt.tags)
                to_name.append(value)
        # loads read the value reaching them (statement indices are still the original ones)
        count = 0
        by_block: dict = defaultdict(list)
        for node, idx, value in load_values:
            by_block[node].append((idx, names[value]))
        for node, items in by_block.items():
            stmts = list(node.statements)
            for idx, vvar in items:
                stmts[idx] = self._replace_loads(stmts[idx], base, size, vvar)
                count += 1
            node.statements = stmts
        # Store(a, e) -> v = e; Store(a, v)
        for _, node, idx in sorted(to_name, key=lambda v: v[2], reverse=True):
            stmt = node.statements[idx]
            vvar = names[("store", node, idx)]
            stmts = list(node.statements)
            stmts[idx : idx + 1] = [
                Assignment(self._ail_manager.next_atom(), vvar, stmt.data, **stmt.tags),
                Store(stmt.idx, stmt.addr, vvar, stmt.size, stmt.endness, stmt.guard, **stmt.tags),
            ]
            node.statements = stmts
        for node in needed:
            phi = names[("phi", node)]
            src = [
                ((pred.addr, pred.idx), names[out_value[pred]] if pred in reachable else None)
                for pred in self.graph.predecessors(node)
            ]
            stmt = Assignment(
                self._ail_manager.next_atom(),
                phi,
                Phi(self._ail_manager.next_atom(), bits, src, ins_addr=node.addr),
                ins_addr=node.addr,
            )
            node.statements = [stmt, *node.statements]
        self._fold_trivial_phis({names[("phi", node)].varid: node for node in needed})
        return count

    def _fold_trivial_phis(self, phis: dict) -> None:
        """
        A phi whose operands are one variable a or values equal to the phi itself (v - c + c around a loop) is a: by
        induction over the iterations, the slot never changes from a. a reaches the block on every path that does not
        come around through the phi, so its definition dominates the block.
        """
        while phis:
            ctx = VMContext(self.layout)
            for block in self.graph:
                key = (block.addr, block.idx)
                for idx, stmt in enumerate(block.statements):
                    if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                        ctx._stack_defs[stmt.dst.varid] = stmt.src
                        ctx._def_locs[stmt.dst.varid] = (key, idx)
                    elif isinstance(stmt, Assignment) and isinstance(stmt.dst, Tmp):
                        # before stack SSA, stored values still read temporaries
                        ctx._tmp_defs[(key, stmt.dst.tmp_idx)] = (stmt.src, (key, idx))
            normalizer = _Normalizer(ctx)
            folded = None
            for varid, node in phis.items():
                stmt = node.statements[0]
                if not (isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and stmt.dst.varid == varid):
                    continue
                others = set()
                ok = True
                for _, operand in stmt.src.src_and_vvars:
                    if operand is None:
                        ok = False
                        break
                    try:
                        if normalizer.key(operand, None) == ("V", varid):
                            continue
                    except (_Budget, RecursionError):
                        pass
                    others.add(operand.varid)
                if ok and len(others) == 1:
                    folded = varid, node, next(iter(others))
                    break
            if folded is None:
                return
            varid, node, other = folded
            replacement = next(op for _, op in node.statements[0].src.src_and_vvars if op.varid == other)
            node.statements = node.statements[1:]
            del phis[varid]

            class _Replace(AILBlockRewriter):
                def __init__(self):
                    super().__init__(update_block=False)

                def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
                    return replacement if expr.varid == varid else expr

            rewriter = _Replace()
            for block in self.graph:
                block.statements = [
                    new if (new := rewriter.walk_statement(st, block=block)) is not None else st
                    for st in block.statements
                ]

    def _replace_loads(self, stmt, base, size, vvar):
        promoter = self

        class _Rewriter(AILBlockRewriter):
            def __init__(self):
                super().__init__(update_block=False)

            def _handle_Load(self, expr_idx, expr, stmt_idx, stmt_, block):
                if promoter._is_load(expr, base, size):
                    return vvar
                rebuilt = super()._handle_Load(expr_idx, expr, stmt_idx, stmt_, block)
                return rebuilt if rebuilt is not None else expr

        new_stmt = _Rewriter().walk_statement(stmt)
        return stmt if new_stmt is None else new_stmt


def promote_vm_context_slots(
    graph: networkx.DiGraph,
    layout: VMContextLayout,
    ail_manager,
    new_vvar_id,
    entry_addr: int | None = None,
    named_vvars: set[int] | None = None,
    stack_addresses_only: bool = False,
) -> int:
    """
    Turn private VM-context slots into SSA variables where exact (see VMContextSlotPromoter). Returns the number of
    loads replaced.

    :param stack_addresses_only: Only promote slots that always hold a stack address.
    """
    if not layout:
        return 0
    promoter = VMContextSlotPromoter(graph, layout, ail_manager, new_vvar_id, entry_addr, stack_addresses_only)
    count = promoter.run()
    if named_vvars is not None:
        named_vvars |= promoter.names
    return count


def forward_vm_context_stores(
    graph: networkx.DiGraph,
    layout: VMContextLayout,
    ail_manager,
    call_reads: CallGlobalReads | None = None,
    entry_addr: int | None = None,
    new_vvar_id=None,
    named_vvars: set[int] | None = None,
) -> int:
    """
    Forward VM-context stores to their loads in place. Returns the number of loads replaced.

    :param call_reads:  Bounds the globals a library call may write, for calls that may reach the context.
    :param entry_addr:  Address of the function's entry block; without it every block without predecessors is one.
    :param new_vvar_id: Allocates virtual variable ids, for naming stored values that read memory.
    :param named_vvars: The ids of such names, kept across calls.
    """
    if not layout:
        return 0
    forwarded = VMContextStoreForwarder(
        graph, layout, ail_manager, call_reads, entry_addr, new_vvar_id, named_vvars
    ).run()
    if forwarded:
        l.debug("Forwarded %d VM-context loads in %s.", forwarded, [(hex(a), hex(b)) for a, b in layout.regions])
    return forwarded
