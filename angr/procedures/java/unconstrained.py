import claripy

from . import JavaSimProcedure
from ...engines.soot.values import SimSootValue_ThisRef, SimSootValue_StringRef


class UnconstrainedMethod(JavaSimProcedure):

    __provides__ = (
        ('angr.unconstrained', 'unconstrained()'),
    )

    def run(self, this_ref, method_descriptor, *args):
        # FIXME: implement this method for static methods as well

        # mMark object as symbolic
        if isinstance(this_ref, SimSootValue_ThisRef):
            this_ref.symbolic = True
        # return the appropriate value based on the return type of the method
        if method_descriptor.ret == 'int':
            return claripy.BVS('unc_int_{}'.format(method_descriptor.name), 32)
        elif method_descriptor.ret == 'java.lang.String':
            str_ref = SimSootValue_StringRef.new_string(
                self.state, claripy.StringS("unc_string_{}".format(method_descriptor.name), 1000))
            return str_ref
        elif method_descriptor.ret == 'void' or method_descriptor.ret is None:
            return
        else:
            obj_ref = SimSootValue_ThisRef.new_object(self.state, method_descriptor.ret, init_object=True)
            return obj_ref
