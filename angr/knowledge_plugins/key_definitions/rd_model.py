from typing import Dict, Tuple, Set, Optional, TYPE_CHECKING

from .uses import Uses
from .live_definitions import LiveDefinitions

if TYPE_CHECKING:
    from angr.knowledge_plugins.key_definitions.definition import Definition


# TODO: Make ReachingDefinitionsModel serializable
class ReachingDefinitionsModel:
    def __init__(self, func_addr: Optional[int]=None):
        self.func_addr = func_addr  # do not use. only for pretty-printing
        self.observed_results: Dict[Tuple[str, int, int], LiveDefinitions] = {}
        self.all_definitions: Set['Definition'] = set()
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
