from typing import Dict, Tuple, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from angr import SimState


class AbstractStateFields:
    def __init__(self, fields: Dict[str,Tuple[int,int]]):
        self.fields = fields

    def generate_abstract_state(self, state: 'SimState') -> Tuple[Tuple[str,Any]]:
        lst = [ ]
        for field, (offset, size) in self.fields.items():
            val = state.solver.eval(state.memory.load(offset, size=size))
            lst.append((field, val))
        return tuple(lst)
