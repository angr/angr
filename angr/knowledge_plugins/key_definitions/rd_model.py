from typing import Dict, Tuple, Optional

from .uses import Uses
from .live_definitions import LiveDefinitions


# TODO: Make ReachingDefinitionsModel serializable
class ReachingDefinitionsModel:
    def __init__(self, func_addr: Optional[int]=None):
        self.func_addr = func_addr  # do not use. only for pretty-printing
        self.observed_results: Dict[Tuple[str, int, int], LiveDefinitions] = {}
        self.all_definitions = set()
        self.all_uses = Uses()

    def __repr__(self):
        return "<RDModel{} with {} observations>".format(
            "[func %#x]" if self.func_addr is not None else "",
            len(self.observed_results),
        )
