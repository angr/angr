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

import pyvex

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
    state.regs.sp = sp
    counter = itertools.count()
    state.memory.read_strategies = [_FreshLocation(counter)]
    state.memory.write_strategies = [_FreshLocation(counter)]
    for page in volatile_pages:
        state.memory.store(page, state.solver.BVS(f"image_page_{page:x}", _PAGE * 8))
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
