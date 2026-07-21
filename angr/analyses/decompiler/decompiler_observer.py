from __future__ import annotations

import itertools
import json
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import networkx

    from angr.ailment import Block


class ObserverFormat:
    """
    Output formats supported by DecompilerObserver.
    """

    JSON = "json"
    DOT = "dot"
    TEXT = "text"

    ALL = (JSON, DOT, TEXT)


class DecompilerObserver:
    """
    Dumps intermediate decompilation state to disk for observability purposes.

    When passed to the Decompiler analysis (observer=...), it is invoked after each Clinic stage and after each stage
    in Decompiler itself, and dumps two types of data for the current AIL graph:

    - The graph itself (only block addresses and block IDs).
    - All AIL blocks in the graph, pretty-printed.

    Each dump is written to output_dir with a monotonically increasing sequence number so that files sort
    chronologically. Notes:

    - Clinic-stage dumps only appear when Clinic actually runs; when the Decompiler reuses a cached Clinic
      (regen_clinic=False with a cache hit), only Decompiler-stage dumps are produced.
    - The observer is not forwarded to child Clinic instances created for inlined callees.
    - Observer failures are logged and swallowed by the callers; they never alter decompilation results.

    :ivar output_dir:   The directory where dump files are written. Created if it does not exist.
    :ivar formats:      The output formats to dump in; one or more of ObserverFormat.ALL.
    """

    def __init__(self, output_dir: str, formats: str | tuple[str, ...] = (ObserverFormat.JSON,)):
        if isinstance(formats, str):
            formats = (formats,)
        for fmt in formats:
            if fmt not in ObserverFormat.ALL:
                raise ValueError(f"Unsupported dump format {fmt!r}; expected one of {ObserverFormat.ALL}")
        if not formats:
            raise ValueError("At least one dump format must be specified")
        self.output_dir = output_dir
        self.formats: tuple[str, ...] = tuple(formats)
        self._seq = itertools.count()
        os.makedirs(self.output_dir, exist_ok=True)

    #
    # Callbacks
    #

    def on_clinic_stage(self, func_addr: int, stage_name: str, ail_graph: networkx.DiGraph) -> None:
        self._dump(func_addr, "clinic", stage_name, ail_graph)

    def on_decompiler_stage(self, func_addr: int, stage_name: str, ail_graph: networkx.DiGraph) -> None:
        self._dump(func_addr, "decompiler", stage_name, ail_graph)

    #
    # Private methods
    #

    @staticmethod
    def _sort_key(block: Block) -> tuple[int, int]:
        return block.addr, -1 if block.idx is None else block.idx

    @staticmethod
    def _node_str(block: Block) -> str:
        return f"{block.addr:#x}:{block.idx}"

    def _dump(self, func_addr: int, phase: str, stage_name: str, ail_graph: networkx.DiGraph) -> None:
        seq = next(self._seq)
        basename = f"{seq:03d}_{func_addr:#x}_{phase}_{stage_name}"

        nodes = sorted(ail_graph.nodes(), key=self._sort_key)
        edges = sorted(ail_graph.edges(), key=lambda e: (self._sort_key(e[0]), self._sort_key(e[1])))

        for fmt in self.formats:
            if fmt == ObserverFormat.JSON:
                self._dump_json(basename, func_addr, seq, phase, stage_name, nodes, edges)
            elif fmt == ObserverFormat.DOT:
                self._dump_dot(basename, func_addr, stage_name, nodes, edges)
            elif fmt == ObserverFormat.TEXT:
                self._dump_text(basename, func_addr, seq, phase, stage_name, nodes, edges)

    def _dump_json(
        self,
        basename: str,
        func_addr: int,
        seq: int,
        phase: str,
        stage_name: str,
        nodes: list[Block],
        edges: list[tuple[Block, Block]],
    ) -> None:
        data = {
            "function": hex(func_addr),
            "sequence": seq,
            "phase": phase,
            "stage": stage_name,
            "graph": {
                "nodes": [{"addr": node.addr, "idx": node.idx} for node in nodes],
                "edges": [
                    [{"addr": src.addr, "idx": src.idx}, {"addr": dst.addr, "idx": dst.idx}] for src, dst in edges
                ],
            },
            "blocks": [{"addr": node.addr, "idx": node.idx, "dbg_repr": node.dbg_repr()} for node in nodes],
        }
        with open(os.path.join(self.output_dir, basename + ".json"), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _dump_dot(
        self,
        basename: str,
        func_addr: int,
        stage_name: str,
        nodes: list[Block],
        edges: list[tuple[Block, Block]],
    ) -> None:
        def node_id(block: Block) -> str:
            return f"n_{block.addr:#x}_{block.idx}"

        lines = [f'digraph "{func_addr:#x} {stage_name}" {{']
        lines.extend(f'  {node_id(node)} [label="{node.addr:#x} (idx={node.idx})"];' for node in nodes)
        lines.extend(f"  {node_id(src)} -> {node_id(dst)};" for src, dst in edges)
        lines.append("}")
        with open(os.path.join(self.output_dir, basename + ".dot"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        # DOT files cannot sanely hold multi-line block bodies; dump pretty-printed blocks alongside
        with open(os.path.join(self.output_dir, basename + "_blocks.txt"), "w", encoding="utf-8") as f:
            f.write(self._blocks_text(nodes))

    def _dump_text(
        self,
        basename: str,
        func_addr: int,
        seq: int,
        phase: str,
        stage_name: str,
        nodes: list[Block],
        edges: list[tuple[Block, Block]],
    ) -> None:
        lines = [
            f"# function: {func_addr:#x}",
            f"# sequence: {seq}",
            f"# phase: {phase}",
            f"# stage: {stage_name}",
            "",
            "== Graph ==",
        ]
        lines.extend(f"{self._node_str(src)} -> {self._node_str(dst)}" for src, dst in edges)
        nodes_with_edges = {node for edge in edges for node in edge}
        isolated = [node for node in nodes if node not in nodes_with_edges]
        lines.extend(f"{self._node_str(node)} (isolated)" for node in isolated)
        lines += ["", "== Blocks ==", self._blocks_text(nodes)]
        with open(os.path.join(self.output_dir, basename + ".txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _blocks_text(self, nodes: list[Block]) -> str:
        return "\n\n".join(f"## Block {self._node_str(node)}\n{node.dbg_repr()}" for node in nodes) + "\n"
