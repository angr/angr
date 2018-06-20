import logging
l = logging.getLogger("angr.state_plugins.jni_references")

import claripy

from .plugin import SimStatePlugin

class SimStateJNIReferences(SimStatePlugin):

    """
    Native code cannot interact directly with Java objects, but needs to use JNI interface
    functions. For this, Java objects are getting referenced with a opaque reference.

    This plugin is used to store the mapping between opaque and java references.
    """

    def __init__(self, local_refs={}, global_refs={}):
        super(SimStateJNIReferences, self).__init__()
        self.local_refs = local_refs
        self.global_refs = global_refs

    def lookup(self, opaque_ref):
        opaque_ref_value = self._get_reference_value(opaque_ref)
        if opaque_ref_value in self.local_refs:
            return self.local_refs[opaque_ref_value]
        if opaque_ref_value in self.global_refs:
            return self.global_refs[opaque_ref_value]
        raise KeyError("Unknown jni reference %d. Local references: %s Global references: %s"
                       "" % (opaque_ref_value, self.local_refs, self.global_refs))

    def create_new_reference(self, java_ref, global_ref=False):
        opaque_ref = self.state.project.loader.extern_object.allocate()
        if global_ref:
            self.global_refs[opaque_ref] = java_ref
        else:
            self.local_refs[opaque_ref] = java_ref
        l.debug("Map %s to opaque reference %s" % (str(java_ref), hex(opaque_ref)))
        return opaque_ref

    def delete_reference(self, opaque_ref, global_ref=False):
        opaque_ref_value = self._get_reference_value(opaque_ref)
        if global_ref:
            del self.global_refs[opaque_ref_value]
        else:
            del self.local_refs[opaque_ref_value]

    def _get_reference_value(self, opaque_ref):
        if self.state.solver.symbolic(opaque_ref):
            raise NotImplementedError("Opaque reference %s is symbolic."
                                      "" % opaque_ref.to_claripy())
        return self.state.solver.eval(opaque_ref)

    def clear_local_references(self):
        self.local_refs = {}

    @SimStatePlugin.memo
    def copy(self, memo):
        return SimStateJNIReferences(local_refs=self.local_refs,
                                     global_refs=self.global_refs)


# FIXME add this as a javavm preset
from angr.sim_state import SimState
SimState.register_default('jni_references', SimStateJNIReferences)
