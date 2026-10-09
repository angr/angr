from __future__ import annotations

import networkx

from angr.ailment.expression import Phi, VirtualVariable
from angr.ailment.statement import Assignment


def copy_roots(graph: networkx.DiGraph) -> dict[int, VirtualVariable]:
    """
    For each virtual variable, the one variable it copies through plain copies and phis, when that is unambiguous.
    Cyclic phi webs (loop-carried registers and spill slots) resolve to the single value entering them.
    """
    srcs: dict[int, list[int]] = {}
    vvars: dict[int, VirtualVariable] = {}
    for block in graph.nodes:
        for stmt in block.statements:
            if not (isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)):
                continue
            dst, src = stmt.dst, stmt.src
            vvars.setdefault(dst.varid, dst)
            if isinstance(src, VirtualVariable):
                srcs[dst.varid] = [src.varid]
                vvars.setdefault(src.varid, src)
            elif isinstance(src, Phi):
                ids = []
                for _, v in src.src_and_vvars:
                    if v is None:
                        ids.append(-1)  # an undefined incoming value: ambiguous
                    else:
                        ids.append(v.varid)
                        vvars.setdefault(v.varid, v)
                srcs[dst.varid] = ids
    g = networkx.DiGraph()
    g.add_nodes_from(vvars)
    for dst, ids in srcs.items():
        for s in ids:
            g.add_edge(dst, s)
    cond = networkx.condensation(g)
    members = cond.graph["mapping"]
    scc_roots: dict[int, set[int]] = {}
    for scc in reversed(list(networkx.topological_sort(cond))):
        roots: set[int] = set()
        for m in cond.nodes[scc]["members"]:
            if m not in srcs:
                roots.add(m)
                continue
            for s in srcs[m]:
                if members[s] != scc:
                    roots |= scc_roots[members[s]]
        scc_roots[scc] = roots
    out = {}
    for varid in vvars:
        roots = scc_roots[members[varid]]
        if len(roots) == 1:
            (root,) = roots
            if root in vvars:
                out[varid] = vvars[root]
    return out
