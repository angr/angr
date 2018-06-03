
import binascii
import os

from ..engines.soot.values import SimSootValue_Local, SimSootValue_ArrayRef, SimSootValue_ParamRef, \
                                  SimSootValue_StaticFieldRef, SimSootValue_ThisRef, SimSootValue_InstanceFieldRef

from ..storage.memory import SimMemory
from .keyvalue_memory import SimKeyValueMemory
from .plugin import SimStatePlugin
from ..errors import SimUnsatError, SimMemoryAddressError
from .. import concretization_strategies
from .. import sim_options as options

import logging
l = logging.getLogger("angr.state_plugins.javavm_memory")

# MAX_ARRAY_SIZE = 1000

class SimJavaVmMemory(SimMemory):
    def __init__(self, memory_id="mem", stack=None, heap=None, vm_static_table=None,
                 load_strategies=[], store_strategies=[]):
        super(SimJavaVmMemory, self).__init__()

        self.id = memory_id

        self._stack = [ ] if stack is None else stack
        self.heap = SimKeyValueMemory("mem") if heap is None else heap
        self.vm_static_table = SimKeyValueMemory("mem") if vm_static_table is None else vm_static_table

        # Heap helper
        # TODO: ask someone how we want to manage this
        # TODO: Manage out of memory allocation
        # self._heap_allocation_id = 0
        # self.max_array_size = MAX_ARRAY_SIZE

        # concretizing strategies
        self.load_strategies = load_strategies
        self.store_strategies = store_strategies

    def get_new_uuid(self):
        # self._heap_allocation_id += 1
        # return str(self._heap_allocation_id)
        return binascii.hexlify(os.urandom(4))

    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None,
              inspect=True, priv=None, disable_actions=False, frame=0):

        if type(addr) is SimSootValue_Local:
            cstack = self._stack[-1+(-1*frame)]
            # A local variable
            # TODO: Implement the stacked stack frames model
            cstack.store(addr.id, data, type_=addr.type)

        elif type(addr) is SimSootValue_ArrayRef:
            self._store_array_ref(addr, data)

        elif type(addr) is SimSootValue_StaticFieldRef:
            self.vm_static_table.store(addr.id, data, type_=addr.type)
        elif type(addr) is SimSootValue_InstanceFieldRef:
            self.heap.store(addr.id, data, type_=addr.type)
        else:
            raise l.warning("Unknown addr type %s" % addr)

    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None,
             inspect=True, disable_actions=False, ret_on_segv=False, none_if_missing=False, frame=0):

        if type(addr) is SimSootValue_Local:
            cstack = self._stack[-1+(-1*frame)]
            # Load a local variable
            # TODO: Implement the stacked stack frames model
            return cstack.load(addr.id, none_if_missing=True)

        elif type(addr) is SimSootValue_ArrayRef:
            return self._load_array_ref(addr)

        elif type(addr) is SimSootValue_ParamRef:
            cstack = self._stack[-1+(-1*frame)]
            # Load a local variable
            # TODO: Implement the stacked stack frames model
            return cstack.load(addr.id, none_if_missing=True)

        elif type(addr) is SimSootValue_StaticFieldRef:
            return self.vm_static_table.load(addr.id, none_if_missing=True)

        else:
            l.warning("Unknown addr type %s" % addr)
            return None

    def push_stack_frame(self):
        self._stack.append(SimKeyValueMemory("mem"))

    def pop_stack_frame(self):
        self._stack = self._stack[:-1]

    @property
    def stack(self):
        return self._stack[-1]


    #
    # Arrays
    #

    def _store_array_ref(self, addr, data):

        idx = addr.index
        idxes = self.concretize_store_idx(idx)
    
        if len(idxes) == 1:
            concretized_idx = idxes[0]
            self._store_arrayref_on_array(array_id=addr.heap_alloc_id, 
                                          idx=concretized_idx,
                                          value=data,
                                          value_type=addr.type)

            # if idx was symbolic, constraint it to the concretized one
            if self.state.solver.symbolic(idx):
                self.state.solver.add(idx == concretized_idx)
        
        else:
            idx_options = []
            for concretized_idx in idxes:
                idx_options.append(concretized_idx == idx)
                self._store_arrayref_on_array(array_id=addr.heap_alloc_id, 
                                              idx=concretized_idx,
                                              value=data,
                                              value_type=addr.type,
                                              store_condition=idx_options[-1])
            idx_constraint = self.state.solver.Or(*idx_options)
            self.state.add_constraints(idx_constraint)

    def _store_arrayref_on_array(self, array_id, idx, value, value_type, store_condition=None):
        if store_condition is not None:
            current_value = self._load_arrayref_from_heap(array_id, idx)
            new_value = value
            value = self.state.solver.If(store_condition, new_value, current_value)
        heap_elem_id = '%s[%d]' % (array_id, idx)
        self.heap.store(heap_elem_id, value, value_type)

    def _load_array_ref(self, addr):

        idx = addr.index
        idxes = self.concretize_load_idx(idx)

        load_value = self._load_arrayref_from_heap(array_id=addr.heap_alloc_id, idx=idxes[0])
        idx_options = [idx == idxes[0]]
        
        for concretized_idx in idxes[1:]:
            load_value = self.state.solver.If(
                concretized_idx == idx,
                self._load_arrayref_from_heap(array_id=addr.heap_alloc_id, idx=concretized_idx),
                load_value
            )
            idx_options.append(idx == concretized_idx)
        
        if len(idx_options) > 1:
            load_constraint = [self.state.solver.Or(*idx_options)]
        elif not self.state.solver.symbolic(idx_options[0]):
            load_constraint = []
        else:  
            load_constraint = [idx_options[0]]
            
        self.state.add_constraints(*load_constraint)

        return load_value

    def _load_arrayref_from_heap(self, array_id, idx):
        heap_elem_id = '%s[%d]' % (array_id, idx)
        value = self.heap.load(heap_elem_id, none_if_missing=True)
        if value is None:
            # TODO consider type during init
            # -> int vs long vs object vs float arrays
            value = self.state.se.BVV(0, 32)
            l.info("Init array element %s to 0." % heap_elem_id)
            self.heap.store(heap_elem_id, value)
        return value

    #
    # Concretization strategies
    #

    def _apply_concretization_strategies(self, idx, strategies, action):
        """
        Applies concretization strategies on the index until one of them succeeds.
        """

        for s in strategies:
            try:
                idxes = s.concretize(self, idx)
            except SimUnsatError:
                idxes = None

            if idxes:
                return idxes
        else:
            raise SimMemoryAddressError("Unable to concretize index %s" % str(idx))
        
    def concretize_store_idx(self, idx, strategies=None):
        """
        Concretizes a store index.

        :param idx:             An expression for the index.
        :param strategies:      A list of concretization strategies (to override the default).
        :param min_idx:         Minimum value for a concretized index (inclusive).
        :param max_idx:         Maximum value for a concretized index (exclusive).
        :returns:               A list of concrete indexes.
        """
        if isinstance(idx, int):
            return [ idx ]
        elif not self.state.solver.symbolic(idx):
            return [ self.state.solver.eval(idx) ]

        strategies = self.store_strategies if strategies is None else strategies
        return self._apply_concretization_strategies(idx, strategies, 'store')

    def concretize_load_idx(self, idx, strategies=None):
        """
        Concretizes a load index.

            :param idx:             An expression for the index.
            :param strategies:      A list of concretization strategies (to override the default).
            :param min_idx:         Minimum value for a concretized index (inclusive).
            :param max_idx:         Maximum value for a concretized index (exclusive).
            :returns:               A list of concrete indexes.
        """

        if isinstance(idx, int):
            return [ idx ]
        elif not self.state.solver.symbolic(idx):
            return [ self.state.se.eval(idx) ]

        strategies = self.load_strategies if strategies is None else strategies
        return self._apply_concretization_strategies(idx, strategies, 'load')

    def _create_default_load_strategies(self):
        # reset dict
        self.load_strategies = []

        # symbolically read up to 1024 elements
        s = concretization_strategies.SimConcretizationStrategyRange(1024)
        self.load_strategies.append(s)

        # if range is too big, fallback to load only one arbitrary element
        s = concretization_strategies.SimConcretizationStrategyAny()
        self.load_strategies.append(s)

    def _create_default_store_strategies(self):
        # reset dict
        self.store_strategies = []

        # symbolically write up to 256 elements
        s = concretization_strategies.SimConcretizationStrategyRange(256)
        self.store_strategies.append(s)

        # if range is too big, fallback to store only the last element
        s = concretization_strategies.SimConcretizationStrategyMax()
        self.store_strategies.append(s)


    #
    # MISC
    #

    def set_state(self, state):
        super(SimJavaVmMemory, self).set_state(state)
        if not self.load_strategies:
            self._create_default_load_strategies()
        if not self.store_strategies:
            self._create_default_store_strategies()

    @SimStatePlugin.memo
    def copy(self, _):
        return SimJavaVmMemory(
            memory_id=self.id,
            stack=[stack_frame.copy() for stack_frame in self._stack],
            heap=self.heap.copy(),
            vm_static_table=self.vm_static_table.copy(),
            load_strategies=[s.copy() for s in self.load_strategies],
            store_strategies=[s.copy() for s in self.store_strategies]
        )


from angr.sim_state import SimState
SimState.register_default('javavm_memory', SimJavaVmMemory)
