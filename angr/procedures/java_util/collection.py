import claripy
import logging

from ..java import JavaSimProcedure
from ...engines.soot.values import SimSootValue_ThisRef

log = logging.getLogger(name=__name__)

ELEMS = "elems"
SIZE = "size"
INDEX = "index"


class GetIterator(JavaSimProcedure):
    __provides__ = (
        ("java.util.Collection", "iterator()"),
        ("java.util.Set", "iterator()"),
        ("java.util.List", "iterator()"),
        ("java.util.LinkedList", "iterator()"),
        ("java.util.AbstractSequentialList", "iterator()"),
    )

    def run(self, this_ref):
        log.debug(f"Called SimProcedure java.util.*.iterator with args: {this_ref}")

        iterator_ref = SimSootValue_ThisRef.new_object(self.state, "java.util.Iterator")
        elems_array_ref = this_ref.get_field(self.state, ELEMS, "java.lang.Object[]")
        iterator_ref.store_field(self.state, ELEMS, "java.lang.Object[]", elems_array_ref)
        collection_size = this_ref.get_field(self.state, SIZE, "int")
        iterator_size = claripy.BVV(self.state.solver.eval(collection_size), 32)
        iterator_ref.store_field(self.state, SIZE, "int", iterator_size)
        iterator_ref.store_field(self.state, INDEX, "int", claripy.BVV(0, 32))

        return iterator_ref
