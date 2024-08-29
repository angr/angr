from __future__ import annotations
import claripy
import logging

from ..java import JavaSimProcedure
from ...engines.soot.values import SimSootValue_ThisRef
from .collection import ELEMS, SIZE, INDEX

log = logging.getLogger(name=__name__)


class IteratorHasNext(JavaSimProcedure):
    __provides__ = (("java.util.Iterator", "hasNext()"),)

    def run(self, this_ref):
        log.debug(f"Called SimProcedure java.util.Iterator.hasNext with args: {this_ref}")

        if this_ref.symbolic:
            return claripy.BoolS("iterator.hasNext")

        iterator_size = this_ref.load_field(self.state, SIZE, "int")
        iterator_index = this_ref.load_field(self.state, INDEX, "int")

        has_next = self.state.solver.eval(iterator_index) < self.state.solver.eval(iterator_size)

        return claripy.BoolV(has_next)


class IteratorNext(JavaSimProcedure):
    __provides__ = (("java.util.Iterator", "next()"),)

    def run(self, this_ref):
        log.debug(f"Called SimProcedure java.util.Iterator.hasNext with args: {this_ref}")

        if this_ref.symbolic:
            return SimSootValue_ThisRef.new_object(self.state, "java.lang.Object", symbolic=True)

        array_ref = this_ref.load_field(self.state, ELEMS, "java.lang.Object[]")
        iterator_index = this_ref.load_field(self.state, INDEX, "int")
        # TODO should check boundaries?

        # Update index
        new_iterator_index = claripy.BVV(self.state.solver.eval(iterator_index) + 1, 32)
        this_ref.store_field(self.state, INDEX, "int", new_iterator_index)

        return self.state.javavm_memory.load_array_element(array_ref, iterator_index)
