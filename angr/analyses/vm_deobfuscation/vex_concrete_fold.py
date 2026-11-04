"""
Fold every VEX tmp of a deobfuscated block that is a constant whatever the block's inputs are.

The block is executed from a fully symbolic entry state twice, with two unrelated stack pointers; a tmp that is concrete
and equal in both runs is replaced by that constant. Image bytes are read from the loaded image, as during exploration.
A memory access through a symbolic address is sent to a fresh location of its own, so it never aliases the stack or the
image and never makes a later read concrete; this matches the decompiler's view that a pointer write does not reach a
stack slot. Image pages that any block of the function stores to (Themida keeps its VM context there) are symbolic at
every block's entry, since another block may have written them.

A devirtualized VM block fetches its bytecode through a VIP that is a constant here but is computed through the VM's
stack with NOR handlers and partial-slot writes the decompiler cannot fold; with the VIP folded, every bytecode byte and
every VM context offset becomes a constant.
"""

from __future__ import annotations

import itertools
import logging
import random

import pyvex
from cle.backends.elf.regions import ELFSection

from angr import sim_options as o
from angr.concretization_strategies import SimConcretizationStrategy

l = logging.getLogger(name=__name__)

_STACK_POINTERS = (0x7FFF_FFFF_0008, 0x0000_1234_5678_9AB0)
_SINK_BASE = 0x6000_0000_0000

_CONST_CLASSES = {
    "Ity_I1": pyvex.const.U1,
    "Ity_I8": pyvex.const.U8,
    "Ity_I16": pyvex.const.U16,
    "Ity_I32": pyvex.const.U32,
    "Ity_I64": pyvex.const.U64,
}


class _FreshLocation(SimConcretizationStrategy):
    """Concretize every symbolic address to a location no other access uses."""

    def __init__(self, counter, **kwargs):
        super().__init__(**kwargs)
        self._counter = counter

    def _concretize(self, memory, addr, **kwargs):
        if not addr.symbolic:
            return [memory.state.solver.eval(addr)]
        return [_SINK_BASE + next(self._counter) * 0x1000]


_PAGE = 0x1000
_SHF_TLS = 0x400


def uninitialized_data_ranges(project) -> list[tuple[int, int]]:
    """
    (addr, size) of the main object's writable, non-executable bytes with no file contents (.bss, a section's tail
    past its raw data), outside byte_code_regions. They are zero at load time only; the program assigns them at run
    time, so their image value says nothing about what a function reads there.
    """
    obj = project.loader.main_object
    regions = getattr(project, "byte_code_regions", None) or ()
    ranges = []
    for sec in getattr(obj, "sections", ()) or ():
        if not sec.is_writable or sec.is_executable:
            continue
        # an ELF TLS (.tbss) or non-alloc section has no bytes of its own at its vaddr
        if isinstance(sec, ELFSection) and (sec.flags & _SHF_TLS or not sec.occupies_memory):
            continue
        start = sec.vaddr if sec.only_contains_uninitialized_data else sec.vaddr + sec.filesize
        end = sec.vaddr + sec.memsize
        if start >= end or any(lo < end and start < hi for lo, hi in regions):
            continue
        ranges.append((start, end - start))
    return ranges


_BSS_WORD = 8
_BSS_TOUCHED = "image_bss_touched"


def symbolize_uninitialized_data(state, project) -> None:
    """
    Make every uninitialized_data_ranges() byte of `state` unknown. Lazily: an 8-byte word gets its symbol, named
    after its address, when it is first read or written, since a range may span megabytes. The words touched so far
    are a frozenset in state.globals, so each copy of the state keeps its own.
    """
    ranges = uninitialized_data_ranges(project)
    if not ranges:
        return
    state.globals[_BSS_TOUCHED] = frozenset()

    def touch(s, addr, size):
        if addr is None or size is None:
            return
        if not isinstance(addr, int):
            if addr.symbolic:
                return
            addr = addr.concrete_value
        if not isinstance(size, int):
            if size.symbolic:
                return
            size = size.concrete_value
        touched = s.globals.get(_BSS_TOUCHED, frozenset())
        new = []
        for start, length in ranges:
            lo, hi = max(addr, start), min(addr + size, start + length)
            word = lo - lo % _BSS_WORD
            while word < hi:
                if word not in touched:
                    a, b = max(word, start), min(word + _BSS_WORD, start + length)
                    sym = s.solver.BVS(f"image_bss_{a:x}", (b - a) * 8, explicit_name=True)
                    s.memory.store(a, sym, inspect=False)
                    new.append(word)
                word += _BSS_WORD
        if new:
            s.globals[_BSS_TOUCHED] = touched | frozenset(new)

    def on_read(s):
        touch(s, s.inspect.attrs.mem_read_address, s.inspect.attrs.mem_read_length)

    def on_write(s):
        attrs = s.inspect.attrs
        size = attrs.mem_write_length
        if size is None and attrs.mem_write_expr is not None:
            size = len(attrs.mem_write_expr) // 8
        # a partial write keeps the rest of its word unknown
        touch(s, attrs.mem_write_address, size)

    state.inspect.b("mem_read", when="before", action=on_read)
    state.inspect.b("mem_write", when="before", action=on_write)


def _entry_state(project, irsb, sp: int, volatile_pages=()):
    state = project.factory.blank_state(
        addr=irsb.addr,
        add_options={o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS, o.SYMBOL_FILL_UNCONSTRAINED_MEMORY},
    )
    # blank_state seeds cc_op, the direction/ID/AC flags, segment and FPU registers; a block entered from anywhere
    # knows none of them
    for reg in project.arch.register_list:
        if reg.default_value is not None and reg.name != project.arch.register_names[project.arch.sp_offset]:
            state.registers.store(reg.vex_offset, state.solver.BVS(f"entry_{reg.name}", reg.size * 8))
    # a flags read with a symbolic cc_op then yields unknown flags instead of raising; otherwise the block is neither
    # folded nor known not to write the image
    state.globals["cur_block_id"] = irsb.addr
    state.regs.sp = sp
    counter = itertools.count()
    state.memory.read_strategies = [_FreshLocation(counter)]
    state.memory.write_strategies = [_FreshLocation(counter)]
    for page in volatile_pages:
        state.memory.store(page, state.solver.BVS(f"image_page_{page:x}", _PAGE * 8))
    symbolize_uninitialized_data(state, project)
    return state


def _run(project, state, irsb):
    from angr.engines import UberEngine  # pylint:disable=import-outside-toplevel

    UberEngine(project).process(state, irsb=irsb)


def written_image_pages(project, irsbs) -> set[int]:
    """
    The pages of the main object that any of `irsbs` stores to through a concrete address.
    """
    obj = project.loader.main_object
    pages: set[int] = set()

    def on_write(s):
        addr = s.inspect.attrs.mem_write_address
        if not addr.symbolic:
            value = s.solver.eval(addr)
            if obj.min_addr <= value <= obj.max_addr:
                pages.add(value & ~(_PAGE - 1))

    for irsb in irsbs:
        state = _entry_state(project, irsb, _STACK_POINTERS[0])
        state.inspect.b("mem_write", when="before", action=on_write)
        try:
            _run(project, state, irsb)
        except Exception:  # pylint:disable=broad-exception-caught
            # its writes are unknown: no image byte is known at any block's entry
            return {page for page in range(obj.min_addr & ~(_PAGE - 1), obj.max_addr + 1, _PAGE)}
    return pages


def _concrete_tmps(project, irsb, sp: int, volatile_pages=()) -> dict[int, int]:
    state = _entry_state(project, irsb, sp, volatile_pages)
    values: dict[int, int | None] = {}

    def on_tmp_write(s):
        attrs = s.inspect.attrs
        expr = attrs.tmp_write_expr
        values[attrs.tmp_write_num] = None if expr.symbolic else s.solver.eval(expr)

    state.inspect.b("tmp_write", when="after", action=on_tmp_write)
    _run(project, state, irsb)
    return {t: v for t, v in values.items() if v is not None}


def bounded_load_offsets(project, irsb, stmt_idxs, limit: int = 4) -> dict[int, set[int]]:
    """
    For the loads at `stmt_idxs`, the offsets from the block-entry stack pointer they may read, when there are at most
    `limit` of them whatever the block's inputs and memory contents are. A VM branch that picks one of two pushed VIPs
    through `sp + c + (flag & 8)` is such a load.
    """
    sp = _STACK_POINTERS[0]
    state = _entry_state(project, irsb, sp)
    addrs: dict[int, object] = {}
    counter = itertools.count()

    def on_read(s):
        attrs = s.inspect.attrs
        if s.scratch.stmt_idx in stmt_idxs:
            addrs.setdefault(s.scratch.stmt_idx, attrs.mem_read_address)
        # memory contents are not tracked: the bound must hold for any value a load returns
        size = attrs.mem_read_length
        size = size if isinstance(size, int) else s.solver.eval_one(size)
        attrs.mem_read_expr = s.solver.BVS(f"load_{next(counter)}", size * 8)

    state.inspect.b("mem_read", when="before", action=on_read)
    try:
        _run(project, state, irsb)
    except Exception:  # pylint:disable=broad-exception-caught
        l.debug("Cannot execute block %#x symbolically; no load is bounded", irsb.addr, exc_info=True)
        return {}
    bits = project.arch.bits
    # value sets of address expressions seen before, keyed by their variable-renamed form
    memo = project.__dict__.setdefault("_vm_bounded_load_memo", {})
    rnd = random.Random(0)
    result = {}
    for idx, addr in addrs.items():
        expr = addr - sp
        leaves = _symbolic_leaves(expr)
        key = _renamed_key(expr, leaves)
        if key in memo:
            values = memo[key]
        elif _samples_exceed(expr, leaves, limit, rnd):
            values = None
        else:
            values = state.solver.eval_upto(expr, limit + 1)
            values = values if len(values) <= limit else None
        memo[key] = values
        if values is not None:
            result[idx] = {v - (1 << bits) if v >> (bits - 1) else v for v in values}
    return result


_SAMPLES = 16


def _symbolic_leaves(expr):
    leaves = {}
    for leaf in expr.leaf_asts():
        if leaf.symbolic:
            leaves.setdefault(leaf.hash(), leaf)
    return list(leaves.values())


def _renamed_key(expr, leaves):
    """
    A key equal for expressions that differ only in the names of their variables. Every variable here is
    unconstrained and independent, so such expressions have the same set of values.
    """
    from angr import claripy  # pylint:disable=import-outside-toplevel

    renamed = expr
    for i, leaf in enumerate(leaves):
        renamed = renamed.replace(leaf, claripy.BVS(f"__bounded_load_{i}", leaf.size(), explicit_name=True))
    return renamed.hash(), renamed.size()


def _samples_exceed(expr, leaves, limit: int, rnd) -> bool:
    """
    True when random inputs alone give expr more than `limit` values, which the solver would find too. Deep
    obfuscated address chains make each solver query take seconds.
    """
    from angr import claripy  # pylint:disable=import-outside-toplevel

    seen = set()
    for _ in range(_SAMPLES):
        value = expr
        for leaf in leaves:
            value = value.replace(leaf, claripy.BVV(rnd.getrandbits(leaf.size()), leaf.size()))
        if value.symbolic:
            value = value.simplify()
            if value.symbolic:
                return False
        seen.add(value.concrete_value)
        if len(seen) > limit:
            return True
    return False


def fold_concrete_tmps(project, irsb: pyvex.IRSB, volatile_pages=()) -> pyvex.IRSB | None:
    """
    A copy of `irsb` with every input-independent tmp definition replaced by its constant, or None if none is.
    `volatile_pages` are image pages whose bytes are not known at the block's entry.
    """
    try:
        runs = [_concrete_tmps(project, irsb, sp, volatile_pages) for sp in _STACK_POINTERS]
    except Exception:  # pylint:disable=broad-exception-caught
        l.warning("Cannot execute block %#x symbolically; not folding it", irsb.addr, exc_info=True)
        return None
    first = runs[0]
    statements = list(irsb.statements)
    folded = 0
    for i, stmt in enumerate(statements):
        if not isinstance(stmt, pyvex.stmt.WrTmp) or isinstance(stmt.data, pyvex.expr.Const):
            continue
        value = first.get(stmt.tmp)
        if value is None or any(run.get(stmt.tmp) != value for run in runs[1:]):
            continue
        const_cls = _CONST_CLASSES.get(irsb.tyenv.lookup(stmt.tmp))
        if const_cls is None:
            continue
        statements[i] = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Const(const_cls(value)))
        folded += 1
    if not folded:
        return None
    l.debug("Folded %d tmps of block %#x", folded, irsb.addr)
    return pyvex.IRSB.empty_block(
        irsb.arch,
        irsb.addr,
        statements=statements,
        tyenv=irsb.tyenv,
        nxt=irsb.next,
        direct_next=irsb.direct_next,
        jumpkind=irsb.jumpkind,
        size=irsb.size,
    )
