from __future__ import annotations
import claripy

from . import JavaSimProcedure
from ...engines.soot.values import SimSootValue_ThisRef, SimSootValue_StringRef
from ...engines.soot.expressions import SimSootExpr_NewArray
from ... import sim_options as options


class UnconstrainedMethod(JavaSimProcedure):
    __provides__ = (("angr.unconstrained", "unconstrained()"),)

    def run(self, thing, *args):
        this_ref = thing if isinstance(thing, SimSootValue_ThisRef) else None

        if args:
            method_descriptor = args[-1]
            args = args[:-1]
        else:
            # if args is empty, method is static and has no params
            method_descriptor = thing

        # return the appropriate value based on the return type of the method
        if method_descriptor is None or method_descriptor.ret is None or method_descriptor.ret == "void":
            ret_value = None
        elif method_descriptor.ret in ["byte", "char", "short", "int", "boolean"]:
            ret_value = claripy.BVS(f"unc_{method_descriptor.ret}_{method_descriptor.name}", 32)
        elif method_descriptor.ret == "long":
            ret_value = claripy.BVS(f"unc_long_{method_descriptor.name}", 64)
        elif method_descriptor.ret == "float":
            ret_value = claripy.FPS(f"unc_float_{method_descriptor.name}", claripy.FSORT_FLOAT)
        elif method_descriptor.ret == "double":
            ret_value = claripy.FPS(f"unc_double_{method_descriptor.name}", claripy.FSORT_DOUBLE)
        elif method_descriptor.ret == "java.lang.String":
            str_ref = SimSootValue_StringRef.new_string(
                self.state, claripy.StringS(f"unc_string_{method_descriptor.name}", 1000)
            )
            ret_value = str_ref
        elif method_descriptor.ret.endswith("[][]"):
            raise NotImplementedError
        elif method_descriptor.ret.endswith("[]"):
            # TODO here array size should be symbolic
            ret_value = SimSootExpr_NewArray.new_array(self.state, method_descriptor.ret[:-2], claripy.BVV(2, 32))
        else:
            ret_value = SimSootValue_ThisRef.new_object(
                self.state, method_descriptor.ret, symbolic=True, init_object=False
            )

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
            if method_descriptor.name.startswith("set") and len(method_descriptor.params) == 1 and len(args) == 1:
                field_name = method_descriptor.name.replace("set", "")
                field_name = field_name[0].lower() + field_name[1:]
                this_ref.set_field(self.state, field_name, method_descriptor.params[0], args[0])
                return None

        return ret_value
