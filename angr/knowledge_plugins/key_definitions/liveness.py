from typing import DefaultDict, Optional, List, Set, Tuple, TYPE_CHECKING

from collections import defaultdict

from angr.knowledge_plugins.key_definitions.atoms import Tmp

from .constants import ObservationPointType, OP_BEFORE, OP_AFTER

if TYPE_CHECKING:
    from .definition import Definition
    from angr.code_location import CodeLocation


LocationType = Tuple[int, Optional[int], Optional[int]]  # block addr, block ID, stmt ID
LocationWithPosType = Tuple[
    int, Optional[int], Optional[int], ObservationPointType
]  # block addr, block ID, stmt ID, before/after


class Liveness:
    """
    This class stores liveness information for each definition.
    """

    def __init__(self):
        self.curr_live_defs: Set["Definition"] = set()
        self.curr_loc: Optional[LocationType] = None
        self.def_to_liveness: DefaultDict["Definition", Set[LocationType]] = defaultdict(set)
        self.loc_to_defs: DefaultDict[LocationWithPosType, Set["Definition"]] = defaultdict(set)
        self._node_max_stmt_id: DefaultDict[Tuple[int, Optional[int]], int] = defaultdict(int)

    def add_def(self, d: "Definition", code_loc: "CodeLocation") -> None:
        loc = (code_loc.block_addr, code_loc.block_idx, code_loc.stmt_idx)
        self.curr_live_defs.add(d)
        self.def_to_liveness[d].add(loc)

    def kill_def(self, d: "Definition") -> None:
        self.curr_live_defs.discard(d)

    def complete_loc(self) -> None:
        if self.curr_loc is not None:
            for live_def in self.curr_live_defs:
                self.def_to_liveness[live_def].add(self.curr_loc)
            self.loc_to_defs[self.curr_loc + (OP_AFTER,)] |= self.curr_live_defs

    def at_new_stmt(self, code_loc: "CodeLocation") -> None:
        """
        Only support moving from a statement to the next statement within one basic block.
        """
        self.complete_loc()
        self.curr_loc = code_loc.block_addr, code_loc.block_idx, code_loc.stmt_idx
        if (
            code_loc.stmt_idx is not None
            and code_loc.stmt_idx > self._node_max_stmt_id[(code_loc.block_addr, code_loc.block_idx)]
        ):
            self._node_max_stmt_id[(code_loc.block_addr, code_loc.block_idx)] = code_loc.stmt_idx

    def at_new_block(self, code_loc: "CodeLocation", pred_codelocs: List["CodeLocation"]) -> None:
        """
        Only support moving to a new block from one or more blocks.
        """
        loc = code_loc.block_addr, code_loc.block_idx, code_loc.stmt_idx
        key = code_loc.block_addr, code_loc.block_idx, code_loc.stmt_idx, OP_BEFORE
        for pred_codeloc in pred_codelocs:
            if pred_codeloc.stmt_idx is None:
                # external code location
                pred_max_stmt_id = None
            else:
                pred_max_stmt_id = self._node_max_stmt_id[(pred_codeloc.block_addr, pred_codeloc.block_idx)]
            pred_key = pred_codeloc.block_addr, pred_codeloc.block_idx, pred_max_stmt_id, OP_AFTER
            all_pred_defs = self.loc_to_defs[pred_key]

            # remove tmp defs
            pred_defs = set()
            for pred_def in all_pred_defs:
                if not isinstance(pred_def.atom, Tmp):
                    pred_defs.add(pred_def)
            for pred_def in pred_defs:
                self.def_to_liveness[pred_def].add(loc)
            self.loc_to_defs[key] |= pred_defs

        self.curr_live_defs = set(self.loc_to_defs[key])
        self.curr_loc = loc

    def find_defs_at(self, code_loc: "CodeLocation", op: int = OP_BEFORE) -> Set["Definition"]:
        if op == OP_BEFORE:
            if code_loc.stmt_idx != 0:
                loc = code_loc.block_addr, code_loc.block_idx, code_loc.stmt_idx - 1, OP_AFTER
            else:
                loc = code_loc.block_addr, code_loc.block_idx, 0, OP_BEFORE
        else:
            loc = code_loc.block_addr, code_loc.block_idx, code_loc.stmt_idx, OP_AFTER
        return set() if loc not in self.loc_to_defs else self.loc_to_defs[loc]

    def copy(self) -> "Liveness":
        o = Liveness()
        o.curr_live_defs = self.curr_live_defs.copy()
        o.curr_loc = self.curr_loc
        o.def_to_liveness = self.def_to_liveness.copy()
        o.loc_to_defs = self.loc_to_defs.copy()
        o._node_max_stmt_id = self._node_max_stmt_id.copy()
        return o
