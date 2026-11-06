"""
Per-block "entry seeds": VM bookkeeping values that every explored arrival at a VM-CFG block id agrees on.

Only three kinds are kept, as (kind, register offset, size) -> value:

* ``vip``: the VIP register and its value;
* ``key``: a decode-key register, one that the block combines with a byte-code read through the VIP;
* ``vsp``: a VM stack pointer, a register the block addresses memory through (plus constants only) and adjusts by a
  constant, as its distance from the entry stack pointer.

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

    __slots__ = ("base", "bc", "const", "regs")

    def __init__(self, regs=frozenset(), bc=False, base=None, const=None):
        self.regs = regs  # entry registers it derives from
        self.bc = bc  # derives from a byte-code read through the VIP
        self.base = base  # (entry register, constant offset) when it is one
        self.const = const


_UNKNOWN = _Val()


def seed_registers(irsb: pyvex.IRSB, vip_off: int, arch) -> tuple[frozenset, frozenset]:
    """
    (decode-key register offsets, VM stack pointer register offsets) of `irsb`, from its VEX alone, for VIP register
    `vip_off`.
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

    def expr(e) -> _Val:
        if isinstance(e, (pyvex.expr.RdTmp, pyvex.expr.Const)):
            return val(e)
        if isinstance(e, pyvex.expr.Get):
            if e.offset in regs:
                return regs[e.offset]
            if e.offset in written:
                return _UNKNOWN
            base = (e.offset, 0) if e.offset in gprs and e.ty == word else None
            return _Val(frozenset((e.offset,)), base=base)
        if isinstance(e, pyvex.expr.Load):
            addr_use(e.addr)
            return _Val(bc=vip_off in val(e.addr).regs and not val(e.addr).bc)
        args = [val(x) for x in e.child_expressions if isinstance(x, (pyvex.expr.RdTmp, pyvex.expr.Const))]
        out = _Val(frozenset().union(*(x.regs for x in args)) if args else frozenset(), any(x.bc for x in args))
        op = getattr(e, "op", "")
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
        elif isinstance(e, pyvex.expr.Unop) and len(args) == 1 and any(c in op for c in _CONVERSIONS):
            if op.endswith(("to64", "to32")) and args[0].base is not None:
                out.base = args[0].base
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
            for r in [r for r in gprs | set(regs) if r < stmt.offset + size and stmt.offset < r + arch.bytes]:
                written.add(r)
                regs.pop(r, None)
            written.add(stmt.offset)
            if size == arch.bytes:
                regs[stmt.offset] = v
    return frozenset(keys), frozenset(addr_regs & adjusted)


def _sp_distance(state, value) -> int | None:
    """value - sp at entry, when that is a constant structurally (no solver)."""
    d = (value - state.regs.sp)
    if d.symbolic:
        d = claripy.simplify(d)
    if d.symbolic:
        return None
    v = d.concrete_value
    return v - (1 << d.size()) if v >> (d.size() - 1) else v


def entry_seeds(state, vip_reg, keys, vsps, single_value) -> dict:
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
    return seeds


def merge_seeds(prev: dict | None, new: dict) -> dict | None:
    """What two arrivals agree on; None once nothing is left (the block is no longer tracked)."""
    if prev is None:
        return None
    merged = {k: v for k, v in prev.items() if new.get(k) == v}
    if not any(k[0] == "vip" for k in merged):
        return None
    return merged


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
