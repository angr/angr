"""Structural checks an AIL graph in (partial) SSA form has to satisfy.

Every problem reported here is one that survives quietly and surfaces much later
as an unrelated failure: a vvar with two definitions makes ``SReachingDefinitions``
and ``GraphDephicationVVarMapping`` record only the last one (both key definitions
by variable id in a plain dict), and a phi naming a block that is no longer a
predecessor sends de-phi looking for a definition along an edge that does not
exist. Passes that add, copy or delete blocks are what break these, so checking a
graph after a pass has run is the cheapest way to catch the damage where it
happened.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from angr.ailment.expression import VirtualVariable
from angr.ailment.statement import Assignment

from . import is_phi_assignment

if TYPE_CHECKING:
    from angr.ailment import Block

Address = tuple[int, "int | None"]

#: two blocks share one ``(addr, idx)``; consumers key blocks by that pair in a
#: plain dict, so one silently shadows the other
DUPLICATE_BLOCK = "duplicate-block"
#: the graph does not have exactly one entry block at the function's address
BAD_ENTRY = "bad-entry"
#: a virtual variable is assigned in more than one place
VVAR_REDEFINED = "vvar-redefined"
#: a phi operand names a block that is not in the graph at all
PHI_SOURCE_REMOVED = "phi-source-removed"
#: a phi operand names a live block that is not a predecessor of the phi's block
PHI_SOURCE_NOT_PREDECESSOR = "phi-source-not-predecessor"
#: a predecessor that no operand of the phi mentions
PHI_MISSING_PREDECESSOR = "phi-missing-predecessor"

ALL_CHECKS = frozenset(
    {
        DUPLICATE_BLOCK,
        BAD_ENTRY,
        VVAR_REDEFINED,
        PHI_SOURCE_REMOVED,
        PHI_SOURCE_NOT_PREDECESSOR,
        PHI_MISSING_PREDECESSOR,
    }
)


@dataclass(frozen=True)
class GraphProblem:
    """One violation, identified well enough to go straight into an assertion message."""

    kind: str
    block: Address
    detail: str
    stmt_idx: int | None = None

    def __str__(self):
        where = f"{self.block[0]:#x}.{self.block[1]}"
        if self.stmt_idx is not None:
            where += f"[{self.stmt_idx}]"
        return f"{self.kind} at {where}: {self.detail}"


def check_ail_graph(graph, func_addr: int | None = None, checks=ALL_CHECKS) -> list[GraphProblem]:
    """Report every structural problem in ``graph``.

    :param graph:       The AIL graph to check.
    :param func_addr:   Function address, for the entry-block check. Omit to skip it.
    :param checks:      Which checks to run; see the module constants. Narrow this when a
                        known-unfixed class would otherwise drown out what you are testing.
    :return:            The problems found, ordered by block and statement.
    """
    problems: list[GraphProblem] = []
    locations: dict[Address, Block] = {}

    for block in graph:
        loc = (block.addr, block.idx)
        if loc in locations and DUPLICATE_BLOCK in checks:
            problems.append(GraphProblem(DUPLICATE_BLOCK, loc, "two blocks share this location"))
        locations[loc] = block

    if func_addr is not None and BAD_ENTRY in checks:
        entries = [b for b in graph if b.addr == func_addr and b.idx is None]
        if len(entries) != 1:
            problems.append(
                GraphProblem(BAD_ENTRY, (func_addr, None), f"expected exactly one entry block, found {len(entries)}")
            )

    definitions: dict[int, list[tuple[Address, int]]] = defaultdict(list)
    for block in graph:
        loc = (block.addr, block.idx)
        predecessors = {(p.addr, p.idx) for p in graph.predecessors(block)}

        for stmt_idx, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                definitions[stmt.dst.varid].append((loc, stmt_idx))

            if not is_phi_assignment(stmt):
                continue

            named = set()
            for src, _ in stmt.src.src_and_vvars:
                named.add(src)
                if src not in locations:
                    if PHI_SOURCE_REMOVED in checks:
                        problems.append(
                            GraphProblem(
                                PHI_SOURCE_REMOVED,
                                loc,
                                f"operand names {src[0]:#x}.{src[1]}, which is not in the graph",
                                stmt_idx,
                            )
                        )
                elif src not in predecessors and PHI_SOURCE_NOT_PREDECESSOR in checks:
                    problems.append(
                        GraphProblem(
                            PHI_SOURCE_NOT_PREDECESSOR,
                            loc,
                            f"operand names {src[0]:#x}.{src[1]}, which is not a predecessor",
                            stmt_idx,
                        )
                    )

            if PHI_MISSING_PREDECESSOR in checks:
                for missing in sorted(predecessors - named):
                    problems.append(
                        GraphProblem(
                            PHI_MISSING_PREDECESSOR,
                            loc,
                            f"predecessor {missing[0]:#x}.{missing[1]} has no operand",
                            stmt_idx,
                        )
                    )

    if VVAR_REDEFINED in checks:
        for varid, sites in sorted(definitions.items()):
            if len(sites) > 1:
                where = ", ".join(f"{loc[0]:#x}.{loc[1]}[{i}]" for loc, i in sites[:4])
                problems.append(
                    GraphProblem(VVAR_REDEFINED, sites[0][0], f"vvar {varid} is defined {len(sites)} times: {where}")
                )

    problems.sort(key=lambda p: (p.block[0], -1 if p.block[1] is None else p.block[1], p.stmt_idx or -1, p.kind))
    return problems
