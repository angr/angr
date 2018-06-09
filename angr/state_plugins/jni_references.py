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

    def __init__(self, local_references={}, global_references={}):
        super(SimStateJNIReferences, self).__init__()
        self.local_references = local_references
        self.global_references = global_references

    def lookup(self, opaque_ref):
        opaque_ref_value = self._get_reference_value(opaque_ref)
        if opaque_ref_value in self.local_references:
            return self.local_references[opaque_ref_value]
        if opaque_ref_value in self.global_references:
            return self.global_references[opaque_ref_value]
        raise KeyError("Unknown jni reference %x" % opaque_ref_value)

    def lookup_local(self, opaque_ref):
        opaque_ref_value = self._get_reference_value(opaque_ref)
        return self.local_references[opaque_ref_value]
    
    def lookup_global(self, opaque_ref):
        opaque_ref_value = self._get_reference_value(opaque_ref)
        return self.global_references[opaque_ref_value]

    def create_new_reference(self, java_ref):
        opaque_ref = self.state.project.loader.extern_object.allocate()
        self.local_references[opaque_ref] = java_ref
        l.debug("Map %s to opaque reference %s" % (str(java_ref), hex(opaque_ref)))
        return opaque_ref

    def _get_reference_value(self, opaque_ref):
        if self.state.solver.symbolic(opaque_ref):
            raise NotImplementedError("Opaque reference is symbolic.")
        return self.state.solver.eval(opaque_ref)

    def clear_local_references(self):
        self.local_references = {}

    @SimStatePlugin.memo
    def copy(self, memo):
        return SimStateJNIReferences(local_references=self.local_references,
                                     global_references=self.global_references)


# FIXME add this as a javavm preset
from angr.sim_state import SimState
SimState.register_default('jni_references', SimStateJNIReferences)
