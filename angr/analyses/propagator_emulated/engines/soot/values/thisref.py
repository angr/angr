
import logging

from archinfo.arch_soot import SootAddressTerminator, SootArgument

from .base import SimSootValue
from .instancefieldref import SimSootValue_InstanceFieldRef
from .local import SimSootValue_Local
from ..method_dispatcher import resolve_method
from cle.errors import CLEError

l = logging.getLogger("angr.engines.soot.values.thisref")


class SimSootValue_ThisRef(SimSootValue):

    def __init__(self, heap_alloc_id, type_, symbolic=False):
        self.heap_alloc_id = heap_alloc_id
        self.type = type_
        self.symbolic = symbolic

    def __repr__(self):
        return self.id

    def __eq__(self, other):
        return isinstance(other, SimSootValue_ThisRef) and \
            self.id == other.id and \
            self.heap_alloc_id == other.heap_alloc_id and \
            self.type == other.type

    @property
    def id(self):
        return "%s.%s.this" % (self.heap_alloc_id, self.type)

    def set_field(self, state, field_name, field_type, value):
        """
        Sets an instance field.
        """
        field_ref = SimSootValue_InstanceFieldRef.get_ref(state=state,
                                                          obj_alloc_id=self.heap_alloc_id,
                                                          field_class_name=self.type,
                                                          field_name=field_name,
                                                          field_type=field_type)
        # store value in java memory
        state.memory.store(field_ref, value)

    def get_field(self, state, field_name, field_type):
        """
        Gets the value of an instance field.
        """
        # get field reference
        field_ref = SimSootValue_InstanceFieldRef.get_ref(state=state,
                                                          obj_alloc_id=self.heap_alloc_id,
                                                          field_class_name=self.type,
                                                          field_name=field_name,
                                                          field_type=field_type)
        # load value from java memory
        return state.memory.load(field_ref, none_if_missing=True)

    def store_field(self, state, field_name, field_type, value):
        """
        Store a field of a given object, without resolving hierachy

        :param state: angr state where we want to allocate the object attribute
        :type SimState
        :param field_name: name of the attribute
        :type str
        :param field_value: attibute's value
        :type SimSootValue
        """
        field_ref = SimSootValue_InstanceFieldRef(self.heap_alloc_id, self.type, field_name, field_type)
        state.memory.store(field_ref, value)

    def load_field(self, state, field_name, field_type):
        """
        Load a field of a given object, without resolving hierachy

        :param state: angr state where we want to load the object attribute
        :type SimState
        :param field_name: name of the attribute
        :type str
        :param field_type: type of the attribute
        :type str
        """
        field_ref = SimSootValue_InstanceFieldRef(self.heap_alloc_id, self.type, field_name, field_type)
        return state.memory.load(field_ref, none_if_missing=False)

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        local = SimSootValue_Local("this", soot_value.type)
        return state.memory.load(local, none_if_missing=True)

    @classmethod
    def new_object(cls, state, type_, symbolic=False, init_object=False):
        """
        Creates a new object reference.
        :param state: State associated to the object.
        :param type_: Class of the object.
        :param init_object: Whether the objects initializer method should be run.
        :return: Reference to the new object.
        """
        # create reference
        obj_ref = cls(heap_alloc_id=state.memory.get_new_uuid(), type_=type_, symbolic=symbolic)
        # run initializer
        if init_object:
            l.info(">" * 15 + " Initialize object %r ... " + ">" * 15, obj_ref)
            # find initializer method
            # TODO: add support for non-default initializing methods
            init_method = resolve_method(state, '<init>', type_, init_class=False).address()

            # setup init state
            args = [SootArgument(obj_ref, obj_ref.type, is_this_ref=True)]
            init_state = state.project.simos.state_call(init_method, *args,
                                                        base_state=state,
                                                        ret_addr=SootAddressTerminator())
            # run init state
            simgr = state.project.factory.simgr(init_state)
            simgr.run()
            # copy results from initialization to the state
            state.memory.vm_static_table = simgr.deadended[0].memory.vm_static_table.copy()
            state.memory.heap = simgr.deadended[0].memory.heap.copy()
            l.debug("<" * 15 + " Initialize object %r ... done " + "<" * 15, obj_ref)
        return obj_ref
