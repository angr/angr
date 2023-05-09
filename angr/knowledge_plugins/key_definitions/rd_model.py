from typing import Dict, Tuple, Set, Union, Optional, TYPE_CHECKING, overload

from angr.knowledge_plugins.key_definitions.constants import ObservationPointType
from angr.code_location import CodeLocation

from .uses import Uses
from .live_definitions import LiveDefinitions

if TYPE_CHECKING:
    from angr.knowledge_plugins.key_definitions.definition import Definition


# TODO: Make ReachingDefinitionsModel serializable
class ReachingDefinitionsModel:
    """
    Models the definitions, uses, and memory of a ReachingDefinitionState object
    """

    def __init__(self, func_addr: Optional[int] = None):
        self.func_addr = func_addr  # do not use. only for pretty-printing
        self.observed_results: Dict[
            Tuple[str, Union[int, Tuple[int, int], Tuple[int, int, int]], ObservationPointType], LiveDefinitions
        ] = {}
        self.all_definitions: Set["Definition"] = set()
        self.all_uses = Uses()

    def __repr__(self):
        return "<RDModel{} with {} observations>".format(
            f"[func {self.func_addr:#x}]" if self.func_addr is not None else "",
            len(self.observed_results),
        )

    def copy(self) -> "ReachingDefinitionsModel":
        new = ReachingDefinitionsModel(self.func_addr)
        new.observed_results = self.observed_results.copy()
        new.all_definitions = self.all_definitions.copy()
        new.all_uses = self.all_uses.copy()
        return new

    def merge(self, model: "ReachingDefinitionsModel"):
        for k, v in model.observed_results.items():
            if k not in self.observed_results:
                self.observed_results[k] = v
            else:
                merged, merge_occured = self.observed_results[k].merge(v)
                if merge_occured:
                    self.observed_results[k] = merged
        self.all_definitions.union(model.all_definitions)
        self.all_uses.merge(model.all_uses)

    def get_observation_by_insn(
        self, ins_addr: Union[int, CodeLocation], kind: ObservationPointType
    ) -> Optional[LiveDefinitions]:
        if isinstance(ins_addr, int):
            return self.observed_results.get(("insn", ins_addr, kind), None)
        elif ins_addr.ins_addr is None:
            raise ValueError("CodeLocation must have an instruction address associated")
        return self.observed_results.get(("insn", ins_addr.ins_addr, kind))

    def get_observation_by_node(
        self, node_addr: Union[int, CodeLocation], kind: ObservationPointType
    ) -> Optional[LiveDefinitions]:
        if isinstance(node_addr, int):
            return self.observed_results.get(("node", node_addr, kind), None)
        else:
            return self.observed_results.get(("node", node_addr.block_addr, kind))

    @overload
    def get_observation_by_stmt(self, codeloc: CodeLocation, kind: ObservationPointType) -> Optional[LiveDefinitions]:
        ...

    @overload
    def get_observation_by_stmt(
        self, node_addr: int, stmt_idx: int, kind: ObservationPointType, *, block_idx: Optional[int] = None
    ):
        ...

    def get_observation_by_stmt(self, arg1, arg2, arg3=None, *, block_idx=None):
        if isinstance(arg1, int):
            if block_idx is None:
                return self.observed_results.get(("stmt", (arg1, arg2), arg3), None)
            else:
                return self.observed_results.get(("stmt", (arg1, arg2, block_idx), arg3), None)
        else:
            if arg1.stmt_idx is None:
                raise ValueError("CodeLocation must have a statement index associated")
            if arg1.block_idx is None:
                return self.observed_results.get(("stmt", (arg1.block_addr, arg1.stmt_idx), arg2), None)
            else:
                return self.observed_results.get(("stmt", (arg1.block_addr, arg1.stmt_idx, block_idx), arg2), None)
