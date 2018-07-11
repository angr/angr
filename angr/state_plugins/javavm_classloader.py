from .plugin import SimStatePlugin
from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor, SootAddressTerminator, SootClassDescriptor
from ..engines.soot.method_dispatcher import resolve_method

import logging
l = logging.getLogger("angr.state_plugins.javavm_classloader")

class SimJavaVmClassloader(SimStatePlugin):
    """
    The classloader is an interface for resolving and initializing java classes.
    """

    def __init__(self, initialized_classes=None):
        super(SimJavaVmClassloader, self).__init__()
        self._initialized_classes = set() if initialized_classes is None else initialized_classes

    def get_class(self, class_name, init_class=False):
        """
        Get a soot class descriptor for the class.

        :param str class_name: Name of class.
        :param bool init_class: Whether the class initializer <clinit> should be executed.
        """
        # try to get the soot class object from CLE
        java_binary = self.state.javavm_registers.load('ip_binary')
        soot_class = java_binary.get_soot_class(class_name, none_if_missing=True)
        # create class descriptor
        class_descriptor = SootClassDescriptor(class_name, soot_class)
        # load/initialize class
        if init_class:
            self.init_class(class_descriptor)
        return class_descriptor

    def get_superclass(self, class_):
        """
        Get the superclass of the class.
        """
        if not class_.is_loaded or class_.superclass_name is None:
            return None
        return self.get_class(class_.superclass_name)

    def get_class_hierarchy(self, base_class):
        """
        Walks up the class hierarchy and returns a list of all classes between
        base class (inclusive) and java.lang.Object (exclusive).
        """
        classes = [base_class]
        while classes[-1] is not None and classes[-1] != "java.lang.Object":
            classes.append(self.get_superclass(classes[-1]))
        return classes[:-1]

    def is_class_initialized(self, class_):
        """
        Indicates whether the class' initializing method <clinit> was
        already executed on this state.
        """
        return class_ in self.initialized_classes

    def init_class(self, class_):
        """
        This method simulates the loading of a class by the JVM. During the loading parts
        of the class, such as static field, are initialized. This is done by running the
        class initializer method <clinit>.
        
        Note: Initialization is skipped, if the class has already been initialized.
        """
        if self.is_class_initialized(class_):
            l.debug("Class %r already initialized.", class_)
            return

        l.debug("Initialize class %r.", class_)
        self.initialized_classes.add(class_)

        if not class_.is_loaded:
            l.warning("Class %r is not loaded in Cle. Skip initializiation.", class_)
            return

        clinit_method = resolve_method(self.state, '<clinit>', class_.name, 
                                       include_superclasses=False, init_class=False)
        if clinit_method.is_loaded: 
            javavm_simos = self.state.project.simos
            clinit_state = javavm_simos.state_call(addr=SootAddressDescriptor(clinit_method, 0, 0),
                                                   base_state=self.state,
                                                   ret_addr=SootAddressTerminator())
            simgr = self.state.project.factory.simgr(clinit_state)
            l.info(">"*15 + " Run class initializer %r ... " + ">"*15, clinit_method)
            simgr.run()
            l.debug("<"*15 + " Run class initializer %r ... done " + "<"*15, clinit_method)
            # The only thing that can change in the class initializer are static fields
            # => update vm_static_table and the heap
            self.state.memory.vm_static_table = simgr.deadended[0].memory.vm_static_table.copy()
            self.state.memory.heap = simgr.deadended[0].memory.heap.copy()
        else:
            l.debug("Class initializer <clinit> is not loaded in Cle. Skip initializiation.")

    @property
    def initialized_classes(self):
        """
        List of all initialized classes.
        """
        return self._initialized_classes

    @SimStatePlugin.memo
    def copy(self, memo):
        return SimJavaVmClassloader(
            initialized_classes=self.initialized_classes.copy()
        )

# FIXME add this to a javavm preset
SimStatePlugin.register_default('javavm_classloader', SimJavaVmClassloader)
