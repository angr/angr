"""
Per-block "entry seeds": VM bookkeeping values that every explored arrival at a VM-CFG block id agrees on.

These kinds are kept, as (kind, register offset, size) -> value:

* ``vip``: the VIP register and its value;
* ``key``: a decode-key register, one that the block combines with a byte-code read through the VIP;
* ``vsp``: a VM stack pointer, a register the block addresses memory through (plus constants only) and adjusts by a
  constant, as its distance from the entry stack pointer;
* ``ctx``: a VM context base, a register the block addresses memory through plus a byte-code operand (a VM register
  index), as its distance from the entry stack pointer;
* ``mem``: one byte of a VM context, keyed (``mem``, base register offset, byte offset from the base). The context is
  the range the operand index can reach, and only bytes that are concrete at the arrival are kept.

A general register that only holds a stack address (a program pointer) is not one of them: seeding it lets a fold
resolve program values.
"""

from __future__ import annotations

import logging
import os

import pyvex

from angr import claripy

_l = logging.getLogger(name=__name__)

_ARITH = ("Iop_Add", "Iop_Sub", "Iop_Xor", "Iop_And", "Iop_Or")
_CONVERSIONS = ("to", "Uto", "Sto")


class _Val:
    """What the static scan knows about a value."""

    __slots__ = ("base", "bc", "const", "ctx", "index", "op", "regs")

    def __init__(self, regs=frozenset(), bc=False, base=None, const=None, op=None):
        self.regs = regs  # entry registers it derives from
        self.bc = bc  # derives from a byte-code read through the VIP
        self.base = base  # (entry register, constant offset) when it is one
        self.const = const
        self.op = op  # bit width, when it is a zero-extended value computed from a byte-code read
        self.index = None  # the entry register it is, as an unscaled index
        self.ctx = None  # (entry register, constant offset, operand width) when it is register + operand


_UNKNOWN = _Val()


def seed_registers(irsb: pyvex.IRSB, vip_off: int, arch) -> tuple[frozenset, frozenset]:
    """
    (decode-key register offsets, VM stack pointer register offsets) of `irsb`, from its VEX alone, for VIP register
    `vip_off`.
    """
    return seed_locations(irsb, vip_off, arch)[:2]


def seed_locations(irsb: pyvex.IRSB, vip_off: int, arch) -> tuple[frozenset, frozenset, frozenset]:
    """
    seed_registers plus the VM contexts of `irsb`: (base register offset, first byte offset, end byte offset) of each
    range the block addresses as base register + byte-code operand.
    """
    gprs = {r.vex_offset for r in arch.register_list if r.general_purpose and r.size == arch.bytes}
    gprs -= {arch.sp_offset, arch.ip_offset, vip_off}
    word = f"Ity_I{arch.bits}"
    tmps: dict[int, _Val] = {}
    regs: dict[int, _Val] = {}  # full-width registers the block wrote so far
    written: set[int] = set()
    keys: set[int] = set()
    addr_regs: set[int] = set()
    adjusted: set[int] = set()
    operands: dict[int, int] = {}  # written register -> operand width of its value
    ctxs: dict[int, tuple[int, int]] = {}

    def bits(e) -> int | None:
        try:
            return pyvex.const.get_type_size(e.result_type(irsb.tyenv))
        except Exception:  # pylint:disable=broad-exception-caught
            return None

    def val(e) -> _Val:
        if isinstance(e, pyvex.expr.RdTmp):
            return tmps.get(e.tmp, _UNKNOWN)
        if isinstance(e, pyvex.expr.Const):
            return _Val(const=e.con.value)
        return _UNKNOWN

    def addr_use(addr):
        v = val(addr)
        if v.base is not None:
            addr_regs.add(v.base[0])
        if v.ctx is not None:
            reg, off, width = v.ctx
            lo, hi = ctxs.get(reg, (off, off))
            ctxs[reg] = (min(lo, off), max(hi, off + (1 << width) - 1 + arch.bytes))

    def expr(e) -> _Val:
        if isinstance(e, (pyvex.expr.RdTmp, pyvex.expr.Const)):
            return val(e)
        if isinstance(e, pyvex.expr.Get):
            if e.offset in operands and e.ty != word:
                # the low part of an operand
                prev = regs.get(e.offset, _UNKNOWN)
                return _Val(prev.regs, prev.bc, op=min(operands[e.offset], bits(e) or arch.bits))
            if e.offset in regs:
                return regs[e.offset]
            if e.offset in written:
                return _Val(op=operands[e.offset]) if e.offset in operands and e.ty == word else _UNKNOWN
            base = (e.offset, 0) if e.offset in gprs and e.ty == word else None
            return _Val(frozenset((e.offset,)), base=base)
        if isinstance(e, pyvex.expr.Load):
            addr_use(e.addr)
            bc = vip_off in val(e.addr).regs and not val(e.addr).bc
            return _Val(bc=bc, op=bits(e) if bc else None)
        args = [val(x) for x in e.child_expressions if isinstance(x, (pyvex.expr.RdTmp, pyvex.expr.Const))]
        out = _Val(frozenset().union(*(x.regs for x in args)) if args else frozenset(), any(x.bc for x in args))
        op = getattr(e, "op", "")
        if any(x.op is not None for x in args):
            out.op = bits(e)
        if isinstance(e, pyvex.expr.Binop) and len(args) == 2:
            x, y = args
            if op.startswith(_ARITH) and x.bc != y.bc and x.const is None and y.const is None:
                # a byte-code value meeting a register value: that register is a decode key
                keys.update(r for r in (y if x.bc else x).regs if r in gprs)
            if op.startswith(("Iop_Add", "Iop_Sub")):
                sign = -1 if op.startswith("Iop_Sub") else 1
                if x.base is not None and y.const is not None:
                    out.base = (x.base[0], x.base[1] + sign * y.const)
                elif sign == 1 and y.base is not None and x.const is not None:
                    out.base = (y.base[0], y.base[1] + x.const)
                elif sign == 1 and x.const is None and y.const is None:
                    # register + operand: an index into a VM context
                    for b, i in ((x, y), (y, x)):
                        base = b.base if b.base is not None else (b.index, 0) if b.index is not None else None
                        if base is not None and i.op is not None and i.op < arch.bits and i.base is None:
                            out.ctx = (*base, i.op)
            elif op.startswith("Iop_Shl") and y.const is not None:
                if x.op is not None:
                    # a scaled operand
                    out.op = min(x.op + y.const, bits(e) or arch.bits)
                if not y.const:
                    # an unscaled index register
                    out.index = x.base[0] if x.base is not None and not x.base[1] else None
        elif isinstance(e, pyvex.expr.Unop) and len(args) == 1 and any(c in op for c in _CONVERSIONS):
            if op.endswith(("to64", "to32")) and args[0].base is not None:
                out.base = args[0].base
            if "Uto" in op:
                out.op = args[0].op
        return out

    for stmt in irsb.statements:
        if isinstance(stmt, pyvex.stmt.WrTmp):
            tmps[stmt.tmp] = expr(stmt.data)
        elif isinstance(stmt, pyvex.stmt.Store):
            addr_use(stmt.addr)
        elif isinstance(stmt, (pyvex.stmt.LoadG, pyvex.stmt.StoreG)):
            addr_use(stmt.addr)
        elif isinstance(stmt, pyvex.stmt.Put):
            v = val(stmt.data)
            if stmt.offset in gprs and stmt.offset not in written and v.base is not None and \
                    v.base[0] == stmt.offset and v.base[1]:
                # reg = reg +/- c: a push or a pop
                adjusted.add(stmt.offset)
            size = pyvex.const.get_type_size(stmt.data.result_type(irsb.tyenv)) // 8
            # a narrower operand written over the low bytes of an operand leaves an operand
            low = operands.get(stmt.offset) if size < arch.bytes and v.op is not None else None
            for r in [r for r in gprs | set(regs) if r < stmt.offset + size and stmt.offset < r + arch.bytes]:
                written.add(r)
                regs.pop(r, None)
                operands.pop(r, None)
            written.add(stmt.offset)
            if size == arch.bytes:
                regs[stmt.offset] = v
                if v.op is not None:
                    operands[stmt.offset] = v.op
            elif low is not None:
                operands[stmt.offset] = max(low, size * 8)
    contexts = frozenset((r, lo, hi) for r, (lo, hi) in ctxs.items() if r not in adjusted)
    return frozenset(keys), frozenset(addr_regs & adjusted), contexts


def _sp_distance(state, value) -> int | None:
    """value - sp at entry, when that is a constant structurally (no solver)."""
    d = (value - state.regs.sp)
    if d.symbolic:
        d = claripy.simplify(d)
    if d.symbolic:
        return None
    v = d.concrete_value
    return v - (1 << d.size()) if v >> (d.size() - 1) else v


def entry_seeds(state, vip_reg, keys, vsps, single_value, contexts=()) -> dict:
    """The seeds `state` holds at a block entry. `single_value(state, (off, size))` is the one value of a register."""
    seeds = {}
    vip = single_value(state, vip_reg)
    if vip is None:
        return seeds
    seeds[("vip", vip_reg[0], vip_reg[1])] = vip
    size = state.arch.bytes
    for off in sorted(keys):
        v = state.registers.load(off, size, inspect=False, disable_actions=True)
        value = v.concrete_value if not v.symbolic else single_value(state, (off, size))
        if value is not None:
            seeds[("key", off, size)] = value
    for off in sorted(vsps):
        v = state.registers.load(off, size, inspect=False, disable_actions=True)
        if v.symbolic and v.variables:
            d = _sp_distance(state, v)
            if d is not None:
                seeds[("vsp", off, size)] = d
    probe = None
    for off, lo, hi in sorted(contexts):
        v = state.registers.load(off, size, inspect=False, disable_actions=True)
        d = _sp_distance(state, v) if v.symbolic and v.variables else None
        if d is None:
            continue
        seeds[("ctx", off, size)] = d
        if probe is None:
            probe = state.copy()  # a load fills unbacked bytes
        try:
            hi += -(hi - lo) % size
            data = probe.memory.load(v + lo, hi - lo, inspect=False, disable_actions=True)
        except Exception:  # pylint:disable=broad-exception-caught
            continue
        for w, word in enumerate(data.chop(8 * size)) if not (hi - lo) % size else ():
            if not word.symbolic:
                for i, b in enumerate(word.concrete_value.to_bytes(size, "big")):
                    seeds[("mem", off, lo + w * size + i)] = b
                continue
            for i, byte in enumerate(word.chop(8)):
                if not byte.symbolic:
                    seeds[("mem", off, lo + w * size + i)] = byte.concrete_value
    return seeds


def merge_seeds(prev: dict | None, new: dict) -> dict | None:
    """What two arrivals agree on; None once nothing is left (the block is no longer tracked)."""
    if prev is None:
        return None
    merged = {k: v for k, v in prev.items() if new.get(k) == v}
    if not any(k[0] == "vip" for k in merged):
        return None
    # context bytes mean nothing without their base
    bases = {k[1] for k in merged if k[0] == "ctx"}
    return {k: v for k, v in merged.items() if k[0] != "mem" or k[1] in bases}


def seeds_for_block_id(project, block_id) -> dict | None:
    """The seeds recorded for `block_id`, following block-id relabels, or None."""
    table = getattr(project, "vm_entry_seeds", None) or {}
    upd = getattr(project, "updated_block_id_map", None) or {}
    seen = set()
    b = block_id
    while b is not None and b not in table and b in upd and b not in seen:
        seen.add(b)
        b = upd[b]
    return table.get(b) if b is not None else None


def encode_seeds(seeds: dict | None, enc_int) -> list | None:
    if not seeds:
        return None
    return [[k[0], k[1], k[2], enc_int(v)] for k, v in sorted(seeds.items())]



def seeded_fold_enabled(project) -> bool:
    if os.environ.get("PUSHAN_ENTRY_SEEDS", "1").lower() in {"0", "false", "no", "n"}:
        return False
    return getattr(project, "vm_deob_entry_seeds", True)


def apply_seeded_fold(project, nodes, volatile_pages=()) -> int:
    """
    Fold each node's IRSB from the entry seeds recorded for its block id (vex_concrete_fold.seeded_fold_tmps), before
    data references are collected. Both the in-process pipeline and the dump reader call this. Returns the number of
    nodes changed.
    """
    from .vex_concrete_fold import seeded_fold_tmps  # pylint:disable=import-outside-toplevel

    synthetic = getattr(project, "synthetic_irsbs", None)
    changed = 0
    for node in nodes:
        irsb = getattr(node, "irsb", None)
        block_id = getattr(node, "block_id", None)
        if irsb is None or not irsb.statements or block_id is None:
            continue
        seeds = seeds_for_block_id(project, block_id)
        if not seeds:
            continue
        folded = seeded_fold_tmps(project, irsb, seeds, getattr(block_id, "vm_vpc", None), volatile_pages)
        if folded is None:
            continue
        node.irsb = folded
        if synthetic is not None:
            synthetic[node.addr] = folded
        changed += 1
    _l.info("entry seeds: folded %d of %d nodes", changed, len(nodes))
    return changed
