from __future__ import annotations
import logging

import claripy

from . import translate_value
from ....errors import SimEngineError
from .base import SimSootValue
from .constants import SimSootValue_IntConstant

l = logging.getLogger("angr.engines.soot.values.arrayref")


class SimSootValue_ArrayBaseRef(SimSootValue):
    __slots__ = ["id", "element_type", "size", "_default_value_generator", "type"]

    def __init__(self, heap_alloc_id, element_type, size, default_value_generator=None):
        self.id = f"{heap_alloc_id}.array_{element_type}"
        self.element_type = element_type
        self.size = size
        self._default_value_generator = default_value_generator
        self.type = element_type + "[]"

    def __repr__(self):
        return self.id

    def get_default_value(self, state):
        """
        :return: Default value for array elements.
        """
        if self._default_value_generator:
            return self._default_value_generator(state)
        return state.project.simos.get_default_value_by_type(self.element_type, state=state)

    def add_default_value_generator(self, generator):
        """
        Add a generator for overwriting the default value for array elements.

        :param function generator: Function that given the state, returns a
                                   default value for array elements, e.g.
                                   `generator = lambda state: claripy.BVV(0, 32)`
        """
        self._default_value_generator = generator

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        raise NotImplementedError


class SimSootValue_ArrayRef(SimSootValue):
    __slots__ = ["id", "base", "index"]

    def __init__(self, base, index):
        self.id = f"{base.id}[{index}]"
        self.base = base
        self.index = index

    def __repr__(self):
        return self.id

    @classmethod
    def from_sootvalue(cls, soot_value, state):
        base_local = translate_value(soot_value.base, state)
        base = state.memory.load(base_local)
        idx = cls.translate_array_index(soot_value.index, state)
        cls.check_array_bounds(idx, base, state)
        return cls(base, idx)

    @staticmethod
    def translate_array_index(idx, state):
        idx_value = translate_value(idx, state)
        if isinstance(idx_value, SimSootValue_IntConstant):
            # idx is a constant
            return idx_value.value
        # idx is a variable
        # => load value from memory
        return state.memory.load(idx_value)

    @staticmethod
    def check_array_bounds(idx, array, state):
        # a valid idx fulfills the constraint
        # 0 <= idx < length
        zero = claripy.BVV(0, 32)
        length = array.size
        bound_constraint = claripy.And(
            length.SGT(idx),
            zero.SLE(idx),
        )

        # evaluate the constraint
        # Note: if index and/or the array length are symbolic, the result
        #       can be True and False and the same time
        idx_stays_within_bounds = state.solver.eval_upto(bound_constraint, 2)

        # There are 3 cases:
        # 1) idx has only valid solutions
        # 2) idx has only invalid solutions
        #    TODO: raise a java.lang.ArrayIndexOutOfBoundsException
        # 3) idx has some valid and some invalid solutions
        #    TODO: split current SimState into two successors:
        #          --> one w/ all valid indexes
        #          --> one w/ all invalid indexes and a raised exception
        #
        # For now we just constraint the index to stay within the bounds

        # raise exception, if index is *always* invalid
        if True not in idx_stays_within_bounds:
            raise SimEngineError(
                f"Access of {array.id}[{idx}] (length {length}) is always invalid. "
                "Cannot continue w/o raising java.lang.ArrayIndexOutOfBoundsException."
            )

        # bound index and/or length, if there are *some* invalid values
        if False in idx_stays_within_bounds:
            l.warning(
                "Possible out-of-bounds access! Index and/or length gets constraint to "
                "valid values. (%s[%s], length %s)",
                array.id,
                idx,
                length,
            )
            state.solver.add(claripy.And(length.SGT(idx), zero.SLE(idx)))
