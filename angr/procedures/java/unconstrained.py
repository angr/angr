import claripy

from . import JavaSimProcedure
from ...engines.soot.values import SimSootValue_ThisRef, SimSootValue_StringRef
from ...engines.soot.expressions import SimSootExpr_NewArray
from ... import sim_options as options


class JavaMethodAnnotation(claripy.Annotation):

    def __init__(self, method):
        super(JavaMethodAnnotation, self).__init__()
        self.method = method

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

    def __repr__(self):
        return self.method

    def __str__(self):
        return self.method


class UnconstrainedMethod(JavaSimProcedure):

    __provides__ = (
        ('angr.unconstrained', 'unconstrained()'),
    )

    def run(self, thing, *args):
        this_ref = thing if isinstance(thing, SimSootValue_ThisRef) else None

        if args:
            method_descriptor = args[-1]
            args = args[:-1]
        else:
            # if args is empty, method is static and has no params
            method_descriptor = thing

        # return the appropriate value based on the return type of the method
        if method_descriptor is None or method_descriptor.ret is None or method_descriptor.ret == 'void':
            ret_value = None
        elif method_descriptor.ret in ['byte', 'char', 'short', 'int', 'boolean']:
            ret_value = claripy.BVS('unc_{}_{}'.format(method_descriptor.ret, method_descriptor.name), 32)
        elif method_descriptor.ret == 'long':
            ret_value = claripy.BVS('unc_long_{}'.format(method_descriptor.name), 64)
        elif method_descriptor.ret == 'float':
            ret_value = claripy.FPS('unc_float_{}'.format(method_descriptor.name), claripy.FSORT_FLOAT)
        elif method_descriptor.ret == 'double':
            ret_value = claripy.FPS('unc_double_{}'.format(method_descriptor.name), claripy.FSORT_DOUBLE)
        elif method_descriptor.ret == 'java.lang.String':
            str_sym = claripy.StringS("unc_string_{}".format(method_descriptor.name), 1000)
            ret_value = SimSootValue_StringRef.new_object(self.state, str_sym, symbolic=True)
        elif method_descriptor.ret.endswith('[][]'):
            raise NotImplementedError
        elif method_descriptor.ret.endswith('[]'):
            # TODO here array size should be symbolic
            ret_value = SimSootExpr_NewArray.new_array(self.state, method_descriptor.ret[:-2], claripy.BVV(2, 32))
        else:
            ret_value = SimSootValue_ThisRef.new_object(
                self.state, method_descriptor.ret, symbolic=True, init_object=False)

        # Simple heuristic to infer if the unknown method we are trying to execute is a getter or a setter
        # Must be improved. This would work only if the method follows the Java naming convention.
        # If the application is obfuscated this won't work.
        if this_ref is not None and options.JAVA_IDENTIFY_GETTER_SETTER in self.state.options:
            if method_descriptor.name.startswith("get"):
                field_name = method_descriptor.name.replace("get", "")
                field_name = field_name[0].lower() + field_name[1:]
                return this_ref.get_field(self.state, field_name, method_descriptor.ret)
            # We define a setter as a method that starts with set
            # and has only one parameter (other than 'this' reference)
            elif method_descriptor.name.startswith("set") and len(method_descriptor.params) == 1 and len(args) == 1:
                field_name = method_descriptor.name.replace("set", "")
                field_name = field_name[0].lower() + field_name[1:]
                this_ref.set_field(self.state, field_name, method_descriptor.params[0], args[0])
                return
        # if ret_value is not None:
        #     import ipdb; ipdb.set_trace()
        if isinstance(ret_value, claripy.ast.Base):
            annotation = JavaMethodAnnotation(method_descriptor.fullname)
            ret_value = ret_value.annotate(annotation)
        return ret_value

