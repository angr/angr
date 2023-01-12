from typing import Dict, Tuple, Set, Optional, TYPE_CHECKING

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
        self.observed_results: Dict[Tuple[str, int, int], LiveDefinitions] = {}
        self.all_definitions: Set["Definition"] = set()
        self.all_uses = Uses()

    def __repr__(self):
        return "<RDModel{} with {} observations>".format(
            "[func %#x]" if self.func_addr is not None else "",
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
