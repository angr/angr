from .base import SimSootValue


class SimSootValue_StringRef(SimSootValue):
    __slots__ = ["id", "type"]

    def __init__(self, heap_alloc_id):
        self.id = "%s.string" % heap_alloc_id
        self.type = "java.lang.String"

    def __repr__(self):
        return self.id

    def __eq__(self, other):
        return isinstance(other, SimSootValue_StringRef) and self.id == other.id and self.type == other.type

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        raise NotImplementedError()

    @staticmethod
    def new_string(state, value):
        """
        Allocate and initialize a new string in the context of the state passed.

        The method returns the reference to the newly allocated string

        :param state: angr state where we want to allocate the string
        :type SimState
        :param value: value of the string to initialize
        :type claripy.String

        :return SimSootValue_StringRef
        """
        str_ref = SimSootValue_StringRef(state.memory.get_new_uuid())
        state.memory.store(str_ref, value)
        return str_ref
