from typing import Tuple, Dict, Set, List, Any

import networkx


class ReplacementRecorder:
    """
    Records all replacements that have happened during simplifications.
    """

    def __init__(self):
        self.replacements: Dict[Tuple[int, Any], Any] = {}

    def record_replacement(self, ins_addr: int, old: Any, new: Any) -> None:
        self.replacements[(ins_addr, old)] = new

    def equivalence_classes(self) -> List[Set[Tuple[int, Any]]]:
        equ_classes = []

        graph = networkx.Graph()
        for (ins_addr, old), new in self.replacements.items():
            graph.add_edge((ins_addr, old), (new.ins_addr if hasattr(new, "ins_addr") else None, new))

        for component in networkx.algorithms.connected_components(graph):
            equ_classes.append(set(component))

        return equ_classes
