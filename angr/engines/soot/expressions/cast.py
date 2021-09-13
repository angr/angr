
import logging

from archinfo import ArchSoot
from archinfo.arch_soot import SootNullConstant

from .base import SimSootExpr
from .constants import SimSootExpr_NullConstant
from ..values.thisref import SimSootValue_ThisRef
from ..values.arrayref import SimSootValue_ArrayBaseRef
from ..expressions.newMultiArray import SimSootExpr_NewMultiArray

l = logging.getLogger("angr.engines.soot.expressions.cast")


class SimSootExpr_Cast(SimSootExpr):
    def _execute(self):
        # get value
        local = self._translate_value(self.expr.value)
        value_uncasted = self.state.javavm_memory.load(local)
        # cast value
        if self.expr.cast_type in ArchSoot.primitive_types:
            javavm_simos = self.state.project.simos
            self.expr = javavm_simos.cast_primitive(self.state,
                                                    value_uncasted,
                                                    to_type=self.expr.cast_type)
        # We are casting an array
        elif isinstance(value_uncasted, SimSootValue_ArrayBaseRef):
            self.expr = SimSootValue_ArrayBaseRef(value_uncasted.heap_alloc_id, self.expr.cast_type.replace('[]', ''),
                                                  value_uncasted.size)
        # We are casting a null value
        elif isinstance(value_uncasted, SootNullConstant) or value_uncasted == SimSootExpr_NullConstant:
            self.expr = SootNullConstant()
        # We are casting a reference to a multidimensional array (we just oversimplify and return a new multi array)
        elif self.expr.cast_type.endswith("[][]"):
            element_type = self.expr.cast_type[:-2]
            self.expr = SimSootExpr_NewMultiArray.new_array(self.state, element_type, self.state.solver.BVV(2, 32),
                                                            default_value_generator=lambda s: SimSootExpr_NewMultiArray._generate_inner_array(s, element_type, [self.state.solverBVV(2, 32)]))
        else:
            self.expr = SimSootValue_ThisRef(heap_alloc_id=value_uncasted.heap_alloc_id,
                                             type_=self.expr.cast_type, symbolic=value_uncasted.symbolic)
