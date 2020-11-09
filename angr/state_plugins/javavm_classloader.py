import logging

from archinfo.arch_soot import (SootAddressDescriptor, SootAddressTerminator,
                                SootClassDescriptor)

from ..engines.soot.method_dispatcher import resolve_method
from ..engines import UberEngine
from ..sim_state import SimState
from .plugin import SimStatePlugin

l = logging.getLogger("angr.state_plugins.javavm_classloader")


class SimJavaVmClassloader(SimStatePlugin):
    """
    JavaVM Classloader is used as an interface for resolving and initializing
    Java classes.
    """

    def __init__(self, initialized_classes=None):
        super(SimJavaVmClassloader, self).__init__()
        self._initialized_classes = set() if initialized_classes is None else initialized_classes

    def get_class(self, class_name, init_class=False, step_func=None):
        """
        Get a class descriptor for the class.

        :param str class_name:  Name of class.
        :param bool init_class: Whether the class initializer <clinit> should be
                                executed.
        :param func step_func: Callback function executed at every step of the simulation manager during
                             the execution of the main <clinit> method
        """
        # try to get the soot class object from CLE
        java_binary = self.state.javavm_registers.load('ip_binary')
        soot_class = java_binary.get_soot_class(class_name, none_if_missing=True)
        # create class descriptor
        class_descriptor = SootClassDescriptor(class_name, soot_class)
        # load/initialize class
        if init_class:
            self.init_class(class_descriptor, step_func=step_func)
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
        Indicates whether the classes initializing method <clinit> was already
        executed on the state.
        """
        return class_ in self.initialized_classes

    def init_class(self, class_, step_func=None):
        """
        This method simulates the loading of a class by the JVM, during which
        parts of the class (e.g. static fields) are initialized. For this, we
        run the class initializer method <clinit> (if available) and update
        the state accordingly.

        Note: Initialization is skipped, if the class has already been
              initialized (or if it's not loaded in CLE).
        """
        if self.is_class_initialized(class_):
            l.debug("Class %r already initialized.", class_)
            return

        l.debug("Initialize class %r.", class_)
        self.initialized_classes.add(class_)

        if not class_.is_loaded:
            l.warning("Class %r is not loaded in CLE. Skip initializiation.", class_)
            return

        clinit_method = resolve_method(self.state, '<clinit>', class_.name,
                                       include_superclasses=False, init_class=False)
        if clinit_method.is_loaded:
            engine = UberEngine(self.state.project)
            # use a fresh engine, as the default engine instance may be in use at this time
            javavm_simos = self.state.project.simos
            clinit_state = javavm_simos.state_call(addr=SootAddressDescriptor(clinit_method, 0, 0),
                                                   base_state=self.state,
                                                   ret_addr=SootAddressTerminator())
            simgr = self.state.project.factory.simgr(clinit_state)
            l.info(">"*15 + " Run class initializer %r ... " + ">"*15, clinit_method)
            simgr.run(step_func=step_func, engine=engine)
            l.debug("<"*15 + " Run class initializer %r ... done " + "<"*15, clinit_method)
            # The only thing that can be updated during initialization are
            # static or rather global information, which are either stored on
            # the heap or in the vm_static_table
            self.state.memory.vm_static_table = simgr.deadended[-1].memory.vm_static_table.copy()
            self.state.memory.heap = simgr.deadended[-1].memory.heap.copy()
        else:
            l.debug("Class initializer <clinit> is not loaded in CLE. Skip initializiation.")

    @property
    def initialized_classes(self):
        """
        List of all initialized classes.
        """
        return self._initialized_classes

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument
        return SimJavaVmClassloader(
            initialized_classes=self.initialized_classes.copy()
        )

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint: disable=unused-argument
        l.warning("Merging is not implemented for JavaVM classloader!")
        return False

    def widen(self, others): # pylint: disable=unused-argument
        l.warning("Widening is not implemented for JavaVM classloader!")
        return False


# TODO use a default JavaVM preset
#      see for reference: angr/engines/__init__.py
SimState.register_default('javavm_classloader', SimJavaVmClassloader)
