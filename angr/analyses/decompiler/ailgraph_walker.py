from __future__ import annotations
from typing import TYPE_CHECKING
from collections.abc import Sequence

if TYPE_CHECKING:
    from typing import Any
    from collections.abc import Callable
    import networkx
    from angr import ailment


class RemoveNodeNotice(Exception):
    pass


class AILGraphWalker:
    """
    Walks an AIL graph and optionally replaces each node with a new node.
    """

    def __init__(
        self,
        graph: networkx.DiGraph[ailment.Block],
        handler: Callable[[ailment.Block], ailment.Block | None],
        replace_nodes: bool = False,
        strict_order_start: Sequence[ailment.Block] = (),
    ):
        self.graph = graph
        self.handler = handler
        self._replace_nodes = replace_nodes
        self._strict_order_start = strict_order_start
        self._edits: dict[ailment.Block, ailment.Block | None] = {}

    def _handle(self, node: ailment.Block):
        try:
            r = self.handler(node)
        except RemoveNodeNotice:
            # we need to remove this node
            self._edits[node] = None
        else:
            if r is not None and r is not node and self._replace_nodes:
                self._edits[node] = r

    def walk(self):
        if not self._strict_order_start:
            for node in self.graph.nodes():
                self._handle(node)
        else:
            traverse_in_order(self.graph, self._strict_order_start, self._handle)

        if self._replace_nodes:
            for old, new in self._edits.items():
                if new is None:
                    self.graph.remove_node(old)
                    continue

                in_edges = list(self.graph.in_edges(old, data=True))
                out_edges = list(self.graph.out_edges(old, data=True))

                self.graph.remove_node(old)
                self.graph.add_node(new)

                for src, _, data in in_edges:
                    if src is old:
                        self.graph.add_edge(new, new, **data)
                    else:
                        self.graph.add_edge(src, new, **data)

                for _, dst, data in out_edges:
                    if dst is old:
                        self.graph.add_edge(new, new, **data)
                    else:
                        self.graph.add_edge(new, dst, **data)


def traverse_in_order(
    ail_graph: networkx.DiGraph[ailment.Block],
    entry_blocks: Sequence[ailment.Block],
    visitor: Callable[[ailment.Block], Any],
):
    seen = set(entry_blocks)
    pending = list(entry_blocks)
    last_pending = set(pending)
    forcing = set()

    # walk this graph in a special order to make sure we see defs of variables before their uses when possible
    while pending:
        stack = pending
        pending = set()

        while stack:
            block = stack.pop()
            if block in forcing or all(pred in seen for pred in ail_graph.pred[block]):
                # process it!
                visitor(block)

                news = set(ail_graph.succ[block])
                news -= seen
                stack.extend(sorted(news))
                seen.update(news)
            else:
                pending.add(block)

        if last_pending == pending:
            if len(pending) > 1:
                # emergency: break any ties by peeking ahead and seeing if one might unlock the other
                frontiers = {node: ({node}, {node}) for node in pending}
                while True:
                    for node, (seen2, frontier) in frontiers.items():
                        nxt = {n for f in frontier for n in ail_graph.succ[f] if n not in seen2}
                        seen2.update(nxt)
                        frontiers[node] = (seen2, nxt)
                    ready = {n for n, (_, frontier) in frontiers.items() if pending - frontier}
                    if ready:
                        break
                    if all(not frontier for _, frontier in frontiers.values()):
                        ready = pending
                        break
            else:
                ready = pending
            forcing = set(ready)

        last_pending = set(pending)
        pending = sorted(pending)
