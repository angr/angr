from __future__ import annotations
from typing import TYPE_CHECKING, overload

from .atoms import Atom, Register, MemoryLocation, SpOffset
from .uses import Uses
from .live_definitions import LiveDefinitions
from .liveness import Liveness
from .constants import OP_BEFORE, ObservationPointType

if TYPE_CHECKING:
    from angr.knowledge_plugins.key_definitions.definition import Definition
    from angr.code_location import CodeLocation


# TODO: Make ReachingDefinitionsModel serializable
class ReachingDefinitionsModel:
    """
    Models the definitions, uses, and memory of a ReachingDefinitionState object
    """

    def __init__(self, func_addr: int | None = None, track_liveness: bool = True):
        self.func_addr = func_addr  # do not use. only for pretty-printing
        self.observed_results: dict[
            tuple[str, int | tuple[int, int] | tuple[int, int, int], ObservationPointType], LiveDefinitions
        ] = {}
        self.all_definitions: set[Definition] = set()
        self.all_uses = Uses()
        self.liveness = Liveness() if track_liveness else None

    def __repr__(self):
        return "<RDModel{} with {} observations>".format(
            f"[func {self.func_addr:#x}]" if self.func_addr is not None else "",
            len(self.observed_results),
        )

    def add_def(self, d: Definition) -> None:
        if self.liveness is not None:
            self.liveness.add_def(d)

    def kill_def(self, d: Definition) -> None:
        if self.liveness is not None:
            self.liveness.kill_def(d)

    def at_new_stmt(self, codeloc: CodeLocation) -> None:
        if self.liveness is not None:
            self.liveness.at_new_stmt(codeloc)

    def at_new_block(self, code_loc: CodeLocation, pred_codelocs: list[CodeLocation]) -> None:
        if self.liveness is not None:
            self.liveness.at_new_block(code_loc, pred_codelocs)

    def make_liveness_snapshot(self) -> None:
        if self.liveness is not None:
            self.liveness.make_liveness_snapshot()

    def find_defs_at(self, code_loc: CodeLocation, op: int = OP_BEFORE) -> set[Definition]:
        return self.liveness.find_defs_at(code_loc, op=op)

    def get_defs(self, atom: Atom, code_loc: CodeLocation, op: int) -> set[Definition]:
        all_defs = self.liveness.find_defs_at(code_loc, op=op)
        defs = None
        if isinstance(atom, Register):
            defs = {
                d
                for d in all_defs
                if isinstance(d.atom, Register)
                and d.atom.reg_offset <= atom.reg_offset < d.atom.reg_offset + d.atom.size
            }
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, int):
                defs = {
                    d
                    for d in all_defs
                    if isinstance(d.atom, MemoryLocation)
                    and isinstance(d.atom.addr, int)
                    and (
                        d.atom.addr <= atom.addr < d.atom.addr + d.size
                        or atom.addr <= d.atom.addr < atom.addr + atom.size
                    )
                }
            elif isinstance(atom.addr, SpOffset):
                defs = {
                    d
                    for d in all_defs
                    if isinstance(d.atom, MemoryLocation)
                    and isinstance(d.atom.addr, SpOffset)
                    and (
                        d.atom.addr.offset <= atom.addr.offset < d.atom.addr.offset + d.size
                        or atom.addr.offset <= d.atom.addr.offset < atom.addr.offset + atom.size
                    )
                }

        if defs is None:
            # unsupported for now
            defs = set()

        return defs

    def copy(self) -> ReachingDefinitionsModel:
        new = ReachingDefinitionsModel(self.func_addr)
        new.observed_results = self.observed_results.copy()
        new.all_definitions = self.all_definitions.copy()
        new.all_uses = self.all_uses.copy()
        new.liveness = self.liveness.copy() if self.liveness is not None else None
        return new

    def merge(self, model: ReachingDefinitionsModel):
        for k, v in model.observed_results.items():
            if k not in self.observed_results:
                self.observed_results[k] = v
            else:
                merged, merge_occurred = self.observed_results[k].merge(v)
                if merge_occurred:
                    self.observed_results[k] = merged
        self.all_definitions.union(model.all_definitions)
        self.all_uses.merge(model.all_uses)
        # TODO: Merge self.liveness

    def get_observation_by_insn(
        self, ins_addr: int | CodeLocation, kind: ObservationPointType
    ) -> LiveDefinitions | None:
        if isinstance(ins_addr, int):
            return self.observed_results.get(("insn", ins_addr, kind), None)
        if ins_addr.ins_addr is None:
            raise ValueError("CodeLocation must have an instruction address associated")
        return self.observed_results.get(("insn", ins_addr.ins_addr, kind))

    def get_observation_by_node(
        self, node_addr: int | CodeLocation, kind: ObservationPointType, node_idx: int | None = None
    ) -> LiveDefinitions | None:
        if isinstance(node_addr, int):
            key = ("node", node_addr, kind) if node_idx is None else ("node", (node_addr, node_idx), kind)
            return self.observed_results.get(key, None)
        key = (
            ("node", node_addr.block_addr, kind)
            if node_idx is None
            else ("node", (node_addr.block_addr, node_idx), kind)
        )
        return self.observed_results.get(key, None)

    @overload
    def get_observation_by_stmt(self, codeloc: CodeLocation, kind: ObservationPointType) -> LiveDefinitions | None: ...

    @overload
    def get_observation_by_stmt(
        self, node_addr: int, stmt_idx: int, kind: ObservationPointType, *, block_idx: int | None = None
    ): ...

    def get_observation_by_stmt(self, arg1, arg2, arg3=None, *, block_idx=None):
        if isinstance(arg1, int):
            if block_idx is None:
                return self.observed_results.get(("stmt", (arg1, arg2), arg3), None)
            return self.observed_results.get(("stmt", (arg1, arg2, block_idx), arg3), None)
        if arg1.stmt_idx is None:
            raise ValueError("CodeLocation must have a statement index associated")
        if arg1.block_idx is None:
            return self.observed_results.get(("stmt", (arg1.block_addr, arg1.stmt_idx), arg2), None)
        return self.observed_results.get(("stmt", (arg1.block_addr, arg1.stmt_idx, block_idx), arg2), None)

    def get_observation_by_exit(
        self,
        node_addr: int,
        stmt_idx: int,
        src_node_idx: int | None = None,
    ) -> LiveDefinitions | None:
        key = (
            ("exit", (node_addr, stmt_idx), ObservationPointType.OP_AFTER)
            if src_node_idx is None
            else ("exit", (node_addr, src_node_idx, stmt_idx), ObservationPointType.OP_AFTER)
        )
        return self.observed_results.get(key, None)
