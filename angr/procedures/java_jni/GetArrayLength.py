from angr import SimProcedure
from angr.engines.soot.expressions.length import SimSootExpr_Length
from . import lookup_local_reference

class GetArrayLength(SimProcedure):

    def run(self, env, array_opaque_ref):
        array_ref = lookup_local_reference(self.state, array_opaque_ref)
        return array_ref.size