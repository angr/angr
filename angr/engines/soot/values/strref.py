
from .thisref import SimSootValue_ThisRef

class SimSootValue_StringRef(SimSootValue_ThisRef):

    def __init__(self, heap_alloc_id, symbolic=False):
        super().__init__(heap_alloc_id, 'java.lang.String', symbolic=symbolic)

    def __repr__(self):
        return self.id

    def __eq__(self, other):
        return isinstance(other, SimSootValue_StringRef) and \
            self.id == other.id and \
            self.heap_alloc_id == other.heap_alloc_id and \
            self.type == other.type

    @classmethod
    def new_object(cls, state, value, symbolic=False):
        """
        Allocate and initialize a new string in the context of the state passed.

        The method returns the reference to the newly allocated string object

        :param state: angr state where we want to allocate the string
        :type SimState
        :param value: value of the string to initialize
        :type claripy.String
        :param symbolic: whether the value is symbolic (StringS)
        :type bool

        :return SimSootValue_StringRef
        """
        str_ref = cls(state.javavm_memory.get_new_uuid(), symbolic=symbolic)
        str_ref.set_field(state, 'value', 'java.lang.String', value)

        length = state.solver.BVS('string_length', 32) if symbolic else state.solver.BVV(value.string_length, 32)
        str_ref.set_field(state, 'length', 'int', length)
        return str_ref
