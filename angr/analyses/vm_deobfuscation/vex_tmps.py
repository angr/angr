"""
VEX temporaries of the deobfuscated CFG: definitions, dangling reads, and the renumbering that joins two blocks.
"""

from __future__ import annotations

import copy

import pyvex

from angr.engines.vex.data_sensitive import DataSensitiveRdTmp
from angr.errors import AngrAnalysisError

_INVALID_TMP = 0xFFFFFFFF


class DanglingTmpError(AngrAnalysisError):
    """
    A statement reads a VEX temporary that no earlier statement of its block defines.
    """

    def __init__(self, where, addr, block_id, stmt_idx, tmp, stmt_str):
        self.addr = addr
        self.block_id = block_id
        self.stmt_idx = stmt_idx
        self.tmp = tmp
        loc = "the block's next" if stmt_idx is None else f"statement {stmt_idx} ({stmt_str})"
        super().__init__(
            f"{where}: block {addr:#x} (block_id {block_id}): {loc} reads t{tmp}, "
            f"which no earlier statement of the block defines"
        )


def vex_stmt_tmp_defs(stmt) -> list[int]:
    if isinstance(stmt, pyvex.stmt.WrTmp):
        return [stmt.tmp]
    if isinstance(stmt, pyvex.stmt.CAS):
        return [t for t in (stmt.oldLo, stmt.oldHi) if t != _INVALID_TMP]
    if isinstance(stmt, pyvex.stmt.Dirty):
        return [stmt.tmp] if stmt.tmp != _INVALID_TMP else []
    if isinstance(stmt, pyvex.stmt.LoadG):
        return [stmt.dst]
    if isinstance(stmt, pyvex.stmt.LLSC):
        return [stmt.result]
    return []


_DEF_FIELDS = {
    pyvex.stmt.WrTmp: ("tmp",),
    pyvex.stmt.CAS: ("oldLo", "oldHi"),
    pyvex.stmt.Dirty: ("tmp",),
    pyvex.stmt.LoadG: ("dst",),
    pyvex.stmt.LLSC: ("result",),
}


def _rename_reads(obj, mapping, on_missing):
    """
    Copy of an expression or statement whose tmp reads go through mapping (copies only what changes). on_missing(tmp)
    is called for a read not in mapping.
    """
    if isinstance(obj, pyvex.expr.RdTmp):
        new = mapping.get(obj.tmp)
        if new is None:
            on_missing(obj.tmp)
        if new is None or new == obj.tmp:
            return obj
        if isinstance(obj, DataSensitiveRdTmp):
            return DataSensitiveRdTmp(new, obj.block_id)
        return pyvex.expr.RdTmp.get_instance(new)
    changed = {}
    for k in type(obj).__slots__:
        v = getattr(obj, k)
        if isinstance(v, (pyvex.expr.IRExpr)):
            nv = _rename_reads(v, mapping, on_missing)
        elif isinstance(v, (list, tuple)) and any(isinstance(e, pyvex.expr.IRExpr) for e in v):
            items = [_rename_reads(e, mapping, on_missing) if isinstance(e, pyvex.expr.IRExpr) else e for e in v]
            nv = v if all(a is b for a, b in zip(items, v)) else type(v)(items)
        else:
            continue
        if nv is not v:
            changed[k] = nv
    if not changed:
        return obj
    obj = copy.copy(obj)
    for k, v in changed.items():
        setattr(obj, k, v)
    return obj


def find_dangling_tmp_reads(irsb) -> list[tuple[int | None, int]]:
    """
    (statement index, tmp) of every read of a tmp with no earlier definition in the block; index None is the
    block's next.
    """
    found = []
    defined = set()
    for idx, stmt in enumerate(irsb.statements):
        _rename_reads(stmt, _Identity(defined), lambda t, i=idx: found.append((i, t)))
        defined.update(vex_stmt_tmp_defs(stmt))
    if isinstance(irsb.next, pyvex.expr.RdTmp) and irsb.next.tmp not in defined:
        found.append((None, irsb.next.tmp))
    return found


class _Identity:
    __slots__ = ("defined",)

    def __init__(self, defined):
        self.defined = defined

    def get(self, tmp):
        return tmp if tmp in self.defined else None


def join_irsbs(first, second, first_loc, second_loc, where="join_basic_blocks"):
    """
    Statements, type list and next of `second` appended to `first`. Each read refers to exactly the definition it
    referred to before: tmps of `first` keep their numbers; a tmp `second` defines gets a fresh number if `first`
    defines the same number. A read with no earlier definition in its own block raises DanglingTmpError; first_loc and
    second_loc are (addr, block_id) for the message.
    """

    def missing(loc, idx, stmt):
        def raise_(tmp):
            raise DanglingTmpError(
                where, loc[0], loc[1], idx, tmp, None if stmt is None else stmt.pp_str(arch=None, tyenv=None)
            )

        return raise_

    stmts = []
    types = {}
    first_defs = {}
    for idx, stmt in enumerate(first.statements):
        stmts.append(_rename_reads(stmt, first_defs, missing(first_loc, idx, stmt)))
        for t in vex_stmt_tmp_defs(stmt):
            first_defs[t] = t
            types[t] = first.tyenv.lookup(t)

    second_defs_all = [t for stmt in second.statements for t in vex_stmt_tmp_defs(stmt)]
    fresh = max([*first_defs, *second_defs_all], default=-1) + 1
    second_map = {}
    for idx, stmt in enumerate(second.statements):
        new_stmt = _rename_reads(stmt, second_map, missing(second_loc, idx, stmt))
        fields = _DEF_FIELDS.get(type(stmt), ())
        for field in fields:
            t = getattr(stmt, field)
            if t == _INVALID_TMP:
                continue
            if t in first_defs:
                new_t = fresh
                fresh += 1
            else:
                new_t = t
            second_map[t] = new_t
            types[new_t] = second.tyenv.lookup(t)
            if new_t != t:
                if new_stmt is stmt:
                    new_stmt = copy.copy(stmt)
                setattr(new_stmt, field, new_t)
        stmts.append(new_stmt)

    nxt = _rename_reads(second.next, second_map, missing(second_loc, None, None))

    types_list = [types.get(i, "tmp removed") for i in range(max(types) + 1)] if types else []
    return stmts, types_list, nxt
