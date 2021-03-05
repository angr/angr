from typing import Dict, Tuple, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from angr import SimState


class AbstractState:
    """
    Defines an abstract state in a state graph. An abstract state is defined by a set of fields (AbstractStateFields)
    and the value of each field.
    """
    def __init__(self, fields: 'AbstractStateFields', values: Dict[str,Any]):
        self.fields = fields
        self.values = values


class AbstractStateFields:
    def __init__(self, fields: Dict[str,Tuple[int,int]]):
        self.fields = fields

    def generate_abstract_state(self, state: 'SimState') -> Tuple[Tuple[str,Any]]:
        lst = [ ]
        for field, (offset, size) in self.fields.items():
            val = state.solver.eval(state.memory.load(offset, size=size))
            lst.append((field, val))
        return tuple(lst)
