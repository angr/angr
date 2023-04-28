from typing import Dict, Optional, TYPE_CHECKING

import networkx

from .phoenix import PhoenixStructurer

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


class CombingStructurer(PhoenixStructurer):
    """
    Structure a region using a structuring algorithm that is similar to the one described in the paper "A Comb for
    Decompiled C Code." Note that this implementation is not exactly the same as what the paper described (especially
    since some key details necessary for reproducing were missing in the original paper) and *should not* be used to
    evaluate the performance of the original algorithm described in the paper.
    """

    NAME = "comb"

    def __init__(
        self,
        region,
        parent_map=None,
        condition_processor=None,
        func: Optional["Function"] = None,
        case_entry_to_switch_head: Optional[Dict[int, int]] = None,
        parent_region=None,
        improve_structurer: bool = False,
    ):
        super().__init__(
            region,
            parent_map=parent_map,
            condition_processor=condition_processor,
            func=func,
            case_entry_to_switch_head=case_entry_to_switch_head,
            parent_region=parent_region,
            improve_structurer=improve_structurer,
        )

        self._analyze()

    def _last_resort_refinement(self, head, graph: networkx.DiGraph, full_graph: Optional[networkx.DiGraph]) -> bool:
        raise Exception()
