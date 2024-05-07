from typing import DefaultDict, Optional, TYPE_CHECKING

from collections import defaultdict
from itertools import chain

from angr.utils.constants import DEFAULT_STATEMENT
from angr.knowledge_plugins.key_definitions.atoms import Tmp

from .constants import ObservationPointType, OP_BEFORE, OP_AFTER

if TYPE_CHECKING:
    from .definition import Definition
    from angr.code_location import CodeLocation


LocationType = tuple[int, Optional[int], Optional[int]]  # block addr, block ID, stmt ID
LocationWithPosType = tuple[
    int, Optional[int], Optional[int], ObservationPointType
]  # block addr, block ID, stmt ID, before/after
BlockAddrType = tuple[int, Optional[int]]  # block addr, block ID


class Liveness:
    """
    This class stores liveness information for each definition.
    """

    def __init__(self):
        self.curr_live_defs: set["Definition"] = set()
        self.curr_loc: LocationType | None = None
        self.curr_block: BlockAddrType | None = None
        self.curr_stmt_idx: int | None = None
        self.blockstart_to_defs: DefaultDict[BlockAddrType, set["Definition"]] = defaultdict(set)
        self.blockend_to_defs: DefaultDict[BlockAddrType, set["Definition"]] = defaultdict(set)
        self.loc_to_killed_defs: DefaultDict[BlockAddrType, dict[int, set["Definition"]]] = defaultdict(dict)
        self.loc_to_added_defs: DefaultDict[BlockAddrType, dict[int, set["Definition"]]] = defaultdict(dict)
        self._node_max_stmt_id: DefaultDict[BlockAddrType, int] = defaultdict(int)

    def add_def(self, d: "Definition") -> None:
        self.curr_live_defs.add(d)
        if self.curr_stmt_idx not in self.loc_to_added_defs[self.curr_block]:
            self.loc_to_added_defs[self.curr_block][self.curr_stmt_idx] = set()
        self.loc_to_added_defs[self.curr_block][self.curr_stmt_idx].add(d)

    def kill_def(self, d: "Definition") -> None:
        self.curr_live_defs.discard(d)
        if self.curr_stmt_idx not in self.loc_to_killed_defs[self.curr_block]:
            self.loc_to_killed_defs[self.curr_block][self.curr_stmt_idx] = set()
        self.loc_to_killed_defs[self.curr_block][self.curr_stmt_idx].add(d)

    def make_liveness_snapshot(self) -> None:
        if self.curr_block is not None:
            self.blockend_to_defs[self.curr_block] |= self.curr_live_defs

    def at_new_stmt(self, code_loc: "CodeLocation") -> None:
        """
        Only support moving from a statement to the next statement within one basic block.
        """
        self.curr_loc = code_loc.block_addr, code_loc.block_idx, code_loc.stmt_idx
        self.curr_block = code_loc.block_addr, code_loc.block_idx
        self.curr_stmt_idx = code_loc.stmt_idx
        if (
            code_loc.stmt_idx is not None
            and code_loc.stmt_idx > self._node_max_stmt_id[(code_loc.block_addr, code_loc.block_idx)]
        ):
            self._node_max_stmt_id[(code_loc.block_addr, code_loc.block_idx)] = code_loc.stmt_idx

    def at_new_block(self, code_loc: "CodeLocation", pred_codelocs: list["CodeLocation"]) -> None:
        """
        Only support moving to a new block from one or more blocks.
        """
        self.make_liveness_snapshot()

        loc = code_loc.block_addr, code_loc.block_idx, code_loc.stmt_idx
        key = code_loc.block_addr, code_loc.block_idx
        for pred_codeloc in pred_codelocs:
            all_pred_defs = self.blockend_to_defs[pred_codeloc.block_addr, pred_codeloc.block_idx]

            # remove tmp defs
            pred_defs = set()
            for pred_def in all_pred_defs:
                if not isinstance(pred_def.atom, Tmp):
                    pred_defs.add(pred_def)
            self.blockstart_to_defs[key] |= pred_defs

        self.curr_live_defs = self.blockstart_to_defs[key].copy()
        self.curr_loc = loc
        self.curr_stmt_idx = 0

    def find_defs_at(self, code_loc: "CodeLocation", op: int = OP_BEFORE) -> set["Definition"]:
        return self.find_defs_at_raw(code_loc.block_addr, code_loc.block_idx, code_loc.stmt_idx, op=op)

    def find_defs_at_raw(
        self, block_addr: int, block_idx: int | None, stmt_idx: int | None, op: int = OP_BEFORE
    ) -> set["Definition"]:
        block: BlockAddrType = block_addr, block_idx
        if block not in self.blockstart_to_defs:
            defs = set()
        else:
            defs = self.blockstart_to_defs[block].copy()

        if stmt_idx is None:
            return defs

        added_defs = self.loc_to_added_defs[block] if block in self.loc_to_added_defs else None
        killed_defs = self.loc_to_killed_defs[block] if block in self.loc_to_added_defs else None

        if stmt_idx == DEFAULT_STATEMENT:
            end_stmt_idx = self._node_max_stmt_id[block] + 1
        else:
            if op == OP_BEFORE:
                end_stmt_idx = stmt_idx
            else:
                end_stmt_idx = stmt_idx + 1

        if added_defs is not None and killed_defs is not None:
            indices = chain(added_defs, killed_defs)
        elif added_defs is None and killed_defs is not None:
            indices = killed_defs
        elif added_defs is not None and killed_defs is None:
            indices = added_defs
        else:
            indices = []

        tmp_indices = []
        if killed_defs is not None and None in killed_defs:
            # External codeloc
            defs.difference_update(killed_defs[None])
            for idx in indices:
                if idx is not None:
                    tmp_indices.append(idx)
            indices = tmp_indices

        tmp_indices = []
        if added_defs is not None and None in added_defs:
            # External codeloc
            defs.update(added_defs[None])
            for idx in indices:
                if idx is not None:
                    tmp_indices.append(idx)
            indices = tmp_indices

        for idx in sorted(indices):
            if idx >= end_stmt_idx:
                break
            if killed_defs is not None and idx in killed_defs:
                defs.difference_update(killed_defs[idx])
            if added_defs is not None and idx in added_defs:
                defs.update(added_defs[idx])

        if stmt_idx == DEFAULT_STATEMENT and op == OP_AFTER:
            if killed_defs is not None and DEFAULT_STATEMENT in killed_defs:
                defs.difference_update(killed_defs[DEFAULT_STATEMENT])
            if added_defs is not None and DEFAULT_STATEMENT in added_defs:
                defs.update(added_defs[DEFAULT_STATEMENT])

        return defs

    def copy(self) -> "Liveness":
        o = Liveness()
        o.curr_live_defs = self.curr_live_defs.copy()
        o.curr_loc = self.curr_loc
        o.curr_block = self.curr_block
        o.curr_stmt_idx = self.curr_stmt_idx
        o.blockstart_to_defs = self.blockstart_to_defs.copy()
        o.blockend_to_defs = self.blockend_to_defs.copy()
        o.loc_to_added_defs = self.loc_to_added_defs.copy()
        o.loc_to_killed_defs = self.loc_to_killed_defs.copy()
        o._node_max_stmt_id = self._node_max_stmt_id.copy()
        return o
