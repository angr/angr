from ..java import JavaSimProcedure
from angr.engines.soot.values.thisref import SimSootValue_ThisRef
from angr.engines.soot.values.instancefieldref import SimSootValue_InstanceFieldRef
import logging

import claripy

l = logging.getLogger('angr.procedures.java.scanner.nextLine')

class ScannerNextLine(JavaSimProcedure):

    __provides__ = (
        ("java.util.Scanner", "nextLine()"),
    )

    def run(self, this):
        l.debug("Called SimProcedure java.utils.scanner.nextLine")
        heap_allocation_id = self.state.memory.get_new_uuid()
        type_ = "java.lang.String"
        this_ref = SimSootValue_ThisRef(heap_allocation_id, type_)
        field_ref = SimSootValue_InstanceFieldRef(heap_allocation_id, type_, 'value', type_)
        self.state.memory.store(field_ref, claripy.StringS("scanner_return", 1000))
        return this_ref
