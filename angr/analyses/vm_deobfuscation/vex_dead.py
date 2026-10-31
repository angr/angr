"""
Statements of a VEX block that block-wise dead-assignment elimination removes in any case, found syntactically.

Running them past reaching definitions first costs most of a DAE round on a freshly unrolled VM trace (~87% of its
statements are dead). Only two rules, each a subset of what the RDA-based fixpoint concludes:

- a WrTmp whose tmp no live statement (nor the block's next) reads;
- a Put whose bytes later Puts of the block all overwrite before any live statement reads one of them.

Anything that may read guest state implicitly (Dirty, PutI, GetI) ends the Put rule's reach, Puts touching the stack
pointer are never removed (RDA may not define them), and every operand counts as a use, including those RDA ignores.
"""

from __future__ import annotations

import pyvex

_BARRIERS = (pyvex.stmt.Dirty, pyvex.stmt.PutI)


def _scan(obj, tmps, regs):
    """Collect tmp reads and (offset, size) register reads of a statement or expression. False: it may read state."""
    if isinstance(obj, pyvex.expr.RdTmp):
        tmps.append(obj.tmp)
        return True
    if isinstance(obj, pyvex.expr.Get):
        regs.append((obj.offset, pyvex.get_type_size(obj.ty) // 8))
        return True
    if isinstance(obj, pyvex.expr.GetI):
        ok = False
    else:
        ok = True
    for k in type(obj).__slots__:
        v = getattr(obj, k, None)
        if isinstance(v, pyvex.expr.IRExpr):
            ok = _scan(v, tmps, regs) and ok
        elif isinstance(v, (list, tuple)):
            for e in v:
                if isinstance(e, pyvex.expr.IRExpr):
                    ok = _scan(e, tmps, regs) and ok
    return ok


def syntactically_dead_statements(irsb, sp_offset: int, sp_size: int) -> set[int]:
    stmts = irsb.statements
    tyenv = irsb.tyenv
    n = len(stmts)
    reads_t = [None] * n
    reads_r = [None] * n
    barrier = [False] * n
    uses = {}
    for i, s in enumerate(stmts):
        t, r = [], []
        ok = _scan(s, t, r)
        reads_t[i], reads_r[i] = t, r
        barrier[i] = (not ok) or isinstance(s, _BARRIERS)
        for x in t:
            uses[x] = uses.get(x, 0) + 1
    nt = []
    if irsb.next is not None:
        _scan(irsb.next, nt, [])
    for x in nt:
        uses[x] = uses.get(x, 0) + 1

    dead = set()

    def kill(i):
        dead.add(i)
        work = []
        for x in reads_t[i]:
            uses[x] -= 1
            if uses[x] == 0:
                work.append(x)
        return work

    wrtmp_of = {s.tmp: i for i, s in enumerate(stmts) if isinstance(s, pyvex.stmt.WrTmp)}

    def drain(work):
        while work:
            x = work.pop()
            i = wrtmp_of.get(x)
            if i is not None and i not in dead and uses.get(x, 0) == 0:
                work.extend(kill(i))

    drain([x for x, i in wrtmp_of.items() if uses.get(x, 0) == 0])

    sp_lo, sp_hi = sp_offset, sp_offset + sp_size
    while True:
        changed = False
        covered = set()
        for i in range(n - 1, -1, -1):
            if i in dead:
                continue
            s = stmts[i]
            if barrier[i]:
                covered.clear()
                continue
            if isinstance(s, pyvex.stmt.Put):
                lo = s.offset
                hi = lo + s.data.result_size(tyenv) // 8
                if lo < sp_hi and sp_lo < hi:
                    covered.difference_update(range(lo, hi))
                    for rlo, size in reads_r[i]:
                        covered.difference_update(range(rlo, rlo + size))
                    continue
                span = range(lo, hi)
                if all(b in covered for b in span):
                    drain(kill(i))
                    changed = True
                    continue
                covered.update(span)
            for lo, size in reads_r[i]:
                covered.difference_update(range(lo, lo + size))
        if not changed:
            return dead
