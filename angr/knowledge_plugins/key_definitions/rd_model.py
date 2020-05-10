from typing import Dict, Tuple

from .uses import Uses
from .live_definitions import LiveDefinitions


# TODO: Make ReachingDefinitionsModel serializable
class ReachingDefinitionsModel:
    def __init__(self):
        self.observed_results: Dict[Tuple[str, int, int], LiveDefinitions] = {}
        self.all_definitions = set()
        self.all_uses = Uses()
