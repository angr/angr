"""
Data-reference collection for deobfuscated VEX.

CFGFast records every constant a lifted block uses that points into loaded memory, and then
classifies it (string, pointer array, ...); the decompiler renders string arguments from that
memory data. The deobfuscated code is never lifted by CFGFast, so its CFG model has to be
populated the same way from the synthetic IRSBs.
"""

from __future__ import annotations

from collections.abc import Iterable

import pyvex

from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from angr.knowledge_plugins.xrefs import XRef, XRefType


def collect_data_references(project, kb, cfg_model, nodes: Iterable) -> list[int]:
    """
    Record the constants in `nodes`' IRSBs that point into loaded memory as memory data of `cfg_model`
    (with an xref each), then classify the new entries.

    :return: The addresses of the memory data entries that were added.
    """
    added = []
    for node in nodes:
        irsb = getattr(node, "irsb", None)
        if irsb is None or not irsb.statements:
            continue
        for stmt_idx, ins_addr, value, size, sort in _scan_irsb(project, irsb):
            if not project.loader.find_loadable_containing(value):
                continue
            if cfg_model.add_memory_data(value, sort, data_size=size):
                added.append(value)
            kb.xrefs.add_xref(
                XRef(
                    ins_addr=ins_addr,
                    block_addr=node.addr,
                    stmt_idx=stmt_idx,
                    memory_data=cfg_model.memory_data[value],
                    xref_type=XRefType.Offset,
                )
            )
    if added:
        cfg_model.tidy_data_references(
            memory_data_addrs=added, exec_mem_regions=_exec_mem_regions(project), xrefs=kb.xrefs
        )
    return added


def _exec_mem_regions(project) -> list[tuple[int, int]]:
    regions = []
    for obj in project.loader.all_objects:
        for sec in obj.sections:
            if sec.is_executable and sec.memsize:
                regions.append((sec.vaddr, sec.vaddr + sec.memsize))
    return regions


def _scan_irsb(project, irsb):
    """Yield (stmt_idx, ins_addr, value, size, sort) for every constant CFGFast would treat as a data reference."""
    ip_offset = project.arch.ip_offset
    imark_addrs = [s.addr + s.delta for s in irsb.statements if type(s) is pyvex.stmt.IMark]
    ins_addr = None
    next_ins_addr = None

    def _consts(expr, size=None, sort=None):
        if type(expr) is pyvex.expr.Const:
            yield expr.con.value, size, sort
        elif type(expr) is int:
            yield expr, size, sort

    for stmt_idx, stmt in enumerate(irsb.statements):
        found = ()
        if type(stmt) is pyvex.stmt.IMark:
            ins_addr = stmt.addr + stmt.delta
            if imark_addrs and ins_addr == imark_addrs[0]:
                imark_addrs.pop(0)
                next_ins_addr = imark_addrs[0] if imark_addrs else None
            continue
        if type(stmt) is pyvex.stmt.WrTmp:
            data = stmt.data
            if type(data) is pyvex.expr.Load:
                found = _consts(data.addr, data.result_size(irsb.tyenv) // 8, MemoryDataSort.Integer)
            elif type(data) is pyvex.expr.Binop:
                args = data.args
                if data.op in ("Iop_Add32", "Iop_Add64") and all(type(a) is pyvex.expr.Const for a in args):
                    found = _consts(args[0].con.value + args[1].con.value)
                else:
                    found = (c for a in args for c in _consts(a))
            elif type(data) is pyvex.expr.Const:
                found = _consts(data)
            elif type(data) is pyvex.expr.ITE:
                found = (c for e in data.child_expressions for c in _consts(e))
        elif type(stmt) is pyvex.stmt.Put:
            if stmt.offset != ip_offset:
                found = _consts(stmt.data)
        elif type(stmt) is pyvex.stmt.Store:
            found = (c for e in (stmt.addr, stmt.data) for c in _consts(e))
        elif type(stmt) is pyvex.stmt.Dirty:
            found = _consts(stmt.mAddr, stmt.mSize, MemoryDataSort.FloatingPoint)
        elif type(stmt) is pyvex.stmt.LoadG:
            found = _consts(stmt.addr, stmt.addr.result_size(irsb.tyenv) // project.arch.byte_width)

        for value, size, sort in found:
            if value != next_ins_addr:
                yield stmt_idx, ins_addr, value, size, sort
