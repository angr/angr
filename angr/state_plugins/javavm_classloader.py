from .plugin import SimStatePlugin
from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor


class SimJavaVmClassloader(SimStatePlugin):
    def __init__(self, classes_loaded=set()):
        super(SimJavaVmClassloader, self).__init__()
        self._classes_loaded = classes_loaded

    def load_class(self, class_):
        self.classes_loaded.add(class_.name)
        for method in class_.methods:
            if method.name == "<clinit>":
                entry_state = self.state.copy()
                simgr = self.state.project.factory.simgr(entry_state)
                simgr.active[0].ip = SootAddressDescriptor(SootMethodDescriptor.from_method(method), 0, 0)
                simgr.run()
                # if we reach the end of the method the correct state is the deadended state
                if simgr.deadended:
                    # The only thing that can change in the <clinit> methods are static fields so
                    # it can only change the vm_static_table and the heap.
                    # We need to fix the entry state memory with the new memory state.
                    self.state.memory.vm_static_table = simgr.deadended[0].memory.vm_static_table.copy()
                    self.state.memory.heap = simgr.deadended[0].memory.heap.copy()
                break

    def is_class_loaded(self, class_):
        return class_.name in self._classes_loaded

    @SimStatePlugin.memo
    def copy(self, memo):
        return SimJavaVmClassloader(
            classes_loaded=self.classes_loaded.copy()
        )

    @property
    def classes_loaded(self):
        return self._classes_loaded

# FIXME add this to a javavm preset
SimStatePlugin.register_default('javavm_classloader', SimJavaVmClassloader)
