import claripy
import logging

from ..java import JavaSimProcedure
from ...engines.soot.expressions import SimSootExpr_NewArray, SimSootExpr_NullConstant
from ...engines.soot.values import SimSootValue_StringRef, SimSootValue_ThisRef
from .collection import ELEMS, SIZE

log = logging.getLogger(name=__name__)

MAP_SIZE = 'size'
MAP_KEYS = 'keys'


def get_map_key(state, key_ref):
    if isinstance(key_ref, SimSootValue_StringRef):
        string = state.memory.load(key_ref)
        if string.concrete:
            return state.solver.eval(string)
        else:
            return state.solver.eval(string)

    else:
        return key_ref.id


class MapInit(JavaSimProcedure):

    __provides__ = (
        ('java.util.Map', '<init>()'),
        ('java.util.HashMap', '<init>()')
    )

    def run(self, this_ref):
        log.debug('Called SimProcedure java.util.Map.<init> with args: {}'.format(this_ref))
        # init map size
        this_ref.store_field(self.state, MAP_SIZE, 'int', claripy.BVV(0, 32))
        array_ref = SimSootExpr_NewArray.new_array(self.state, 'java.lang.Object', claripy.BVV(1000, 32))
        this_ref.store_field(self.state, MAP_KEYS, 'java.lang.Object[]', array_ref)

        return


class MapPut(JavaSimProcedure):

    __provides__ = (
        ('java.util.Map', 'put(java.lang.Object,java.lang.Object)'),
        ('java.util.HashMap', 'put(java.lang.Object,java.lang.Object)')
    )

    def run(self, this_ref, key_ref, value_ref):
        log.debug('Called SimProcedure java.util.Map.add with args: {} {} {}'.format(this_ref, key_ref, value_ref))

        if this_ref.symbolic:
            return SimSootExpr_NullConstant

        # store value
        this_ref.store_field(self.state, get_map_key(self.state, key_ref), 'java.lang.Object', value_ref)
        # store key
        map_size = this_ref.load_field(self.state, MAP_SIZE, 'int')
        keys_array_ref = this_ref.load_field(self.state, MAP_KEYS, 'java.lang.Object[]')
        # TODO we should check if key_ref is already in keys_array_ref
        self.state.javavm_memory.store_array_element(keys_array_ref, map_size, key_ref)

        # Update size
        new_map_size = claripy.BVV(self.state.solver.eval(map_size) + 1, 32)
        this_ref.store_field(self.state, MAP_SIZE, 'int', new_map_size)

        # TODO
        # returns the previous value associated with key, or null if there was no mapping for key.
        return SimSootExpr_NullConstant


class MapGet(JavaSimProcedure):

    __provides__ = (
        ('java.util.Map', 'get(java.lang.Object)'),
        ('java.util.HashMap', 'get(java.lang.Object)')
    )

    def run(self, this_ref, key_ref):
        log.debug('Called SimProcedure java.util.Map.get with args: {} {}'.format(this_ref, key_ref))

        if this_ref.symbolic:
            return SimSootValue_ThisRef(self.state, 'java.lang.Object', symbolic=True)

        try:
            return this_ref.load_field(self.state, get_map_key(self.state, key_ref), 'java.lang.Object')
        except (KeyError, AttributeError):
            return SimSootExpr_NullConstant


class MapSize(JavaSimProcedure):

    __provides__ = (
        ('java.util.Map', 'size()'),
        ('java.util.HashMap', 'size()')
    )

    def run(self, this_ref):
        log.debug('Called SimProcedure java.util.Map.size with args: {}'.format(this_ref))

        if this_ref.symbolic:
            return claripy.BVS('map_size', 32)

        return this_ref.get_field(self.state, MAP_SIZE, 'int')


class MapContainsKey(JavaSimProcedure):

    __provides__ = (
        ('java.util.Map', 'containsKey(java.lang.Object)'),
        ('java.util.HashMap', 'containsKey(java.lang.Object)')
    )

    def run(self, this_ref, key_ref):
        log.debug('Called SimProcedure java.util.Map.containsKey with args: {} {}'.format(this_ref, key_ref))

        if this_ref.symbolic:
            return claripy.BoolS('contains_key')

        try:
            this_ref.load_field(self.state, get_map_key(self.state, key_ref), 'java.lang.Object')
            return claripy.BoolV(1)

        except (KeyError, AttributeError):
            return claripy.BoolV(0)


class MapKeySet(JavaSimProcedure):

    __provides__ = (
        ('java.util.Map', 'keySet()'),
        ('java.util.HashMap', 'keySet()')
    )

    def run(self, this_ref):
        log.debug('Called SimProcedure java.util.Map.keySet with args: {}'.format(this_ref))

        if this_ref.symbolic:
            return SimSootValue_ThisRef.new_object(self.state, 'java.util.Set', symbolic=True)

        set_ref = SimSootValue_ThisRef.new_object(self.state, 'java.util.Set')
        keys_array_ref = this_ref.load_field(self.state, MAP_KEYS, 'java.lang.Object[]')
        set_ref.store_field(self.state, ELEMS, 'java.lang.Object[]', keys_array_ref)
        map_size = this_ref.load_field(self.state, MAP_SIZE, 'int')
        set_size = claripy.BVV(self.state.solver.eval(map_size), 32)
        set_ref.store_field(self.state, SIZE, 'int', set_size)

        return set_ref
