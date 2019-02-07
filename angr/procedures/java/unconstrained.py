import claripy

from . import JavaSimProcedure
from ...engines.soot.values import SimSootValue_ThisRef, SimSootValue_StringRef
from ...engines.soot.expressions import SimSootExpr_NewArray


class UnconstrainedMethod(JavaSimProcedure):

    __provides__ = (
        ('angr.unconstrained', 'unconstrained()'),
    )

    def run(self, thing, *args):
        # mMark object as symbolic
        if isinstance(thing, SimSootValue_ThisRef):
            this_ref = thing

        if args:
            method_descriptor = args[-1]
        else:
            # if args is empty, method is static and has no params
            method_descriptor = thing

        # return the appropriate value based on the return type of the method
        if method_descriptor is None or method_descriptor.ret is None or method_descriptor.ret == 'void':
            return
        elif method_descriptor.ret in ['byte', 'char', 'short', 'int', 'boolean']:
            return claripy.BVS('unc_{}_{}'.format(method_descriptor.ret, method_descriptor.name), 32)
        elif method_descriptor.ret == 'long':
            return claripy.BVS('unc_long_{}'.format(method_descriptor.name), 64)
        elif method_descriptor.ret == 'float':
            return claripy.FPS('unc_float_{}'.format(method_descriptor.name), claripy.FSORT_FLOAT)
        elif method_descriptor.ret == 'double':
            return claripy.FPS('unc_double_{}'.format(method_descriptor.name), claripy.FSORT_DOUBLE)
        elif method_descriptor.ret == 'java.lang.String':
            str_ref = SimSootValue_StringRef.new_string(
                self.state, claripy.StringS("unc_string_{}".format(method_descriptor.name), 1000))
            return str_ref
        elif method_descriptor.ret.endswith('[][]'):
            raise NotImplementedError
        elif method_descriptor.ret.endswith('[]'):
            # TODO here array size should be symbolic
            return SimSootExpr_NewArray.new_array(self.state, method_descriptor.ret[:-2], claripy.BVV(2, 32))
        else:
            obj_ref = SimSootValue_ThisRef.new_object(
                self.state, method_descriptor.ret, symbolic=True, init_object=False)
            return obj_ref
