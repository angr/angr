from archinfo.arch_soot import ArchSoot, SootAddressDescriptor, SootAddressTerminator, SootMethodDescriptor

from ..errors import AngrSimOSError, AngrSimOSError

from ..calling_conventions import DEFAULT_CC

from sets import Set

from ..sim_state import SimState
from .simos import SimOS
from ..engines.soot.values.arrayref import SimSootValue_ArrayRef
from ..engines.soot.values.local import SimSootValue_Local
from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor


import logging
l = logging.getLogger('angr.simos.JavaVM')

class SimJavaVM(SimOS):

    def __init__(self, *args, **kwargs):

        super(SimJavaVM, self).__init__(*args, **kwargs)
        self.name = "JavaVM"

        # are native libraries called via JNI?
        self.jni_support = self.project.loader.main_object.jni_support

        if self.jni_support:

            # Step 1: find all native libs
            self.native_libs = [obj for obj in self.project.loader.initial_load_objects
                                    if not isinstance(obj.arch, ArchSoot)]

            # Step 2: determine and set the native SimOS
            from . import os_mapping  # import dynamically, since the JavaVM class is part of the os_mapping dict
            # for each native library get the Arch
            native_libs_arch = Set([obj.arch for obj in self.native_libs])
            # for each native library get the compatible SimOS 
            native_libs_simos = Set([os_mapping[obj.os] for obj in self.native_libs]) 
            # show warning, if more than one SimOS or Arch would be required
            if len(native_libs_simos) > 1 or len(native_libs_arch) > 1:
                l.warning("Unsupported: Native libraries appear to require different SimOS's or Arch's.")
            # instantiate native SimOS
            if native_libs_simos:
                self.native_simos = native_libs_simos.pop()(self.project)
                self.native_simos.arch = native_libs_arch.pop()
                self.native_simos.configure_project()
            else:
                raise AngrSimOSError("Cannot instantiate SimOS for native libraries: No compatible SimOS found.")

            # Step 3: Match JNI symbols from native libs
            self.native_symbols = {}
            for lib in self.native_libs:
                for name, symbol in lib.symbols_by_name.items():
                    if name.startswith(u'Java'):
                        self.native_symbols[name] = symbol

            # Step 4: Allocate memory for the return hook
            # In order to return back from the Vex to the Soot engine, we hook the return address,
            # More specific: we set the return address to the `native_call_return_to_soot` address and hook it
            self.native_call_return_to_soot = self.project.loader.extern_object.allocate()
            self.project.hook(self.native_call_return_to_soot, self.native_call_return_to_soot_hook)

    #
    # States
    #

    def state_blank(self, addr=None, initial_prefix=None, stack_size=None, **kwargs):

        if not kwargs.get('mode', None): kwargs['mode'] = self.project._default_analysis_mode
        if not kwargs.get('arch', None):  kwargs['arch'] = self.arch
        if not kwargs.get('os_name', None): kwargs['os_name'] = self.name

        if self.jni_support:
            # If the JNI support is enabled (i.e. native libs are loaded), the SimState
            # needs to support both the Vex and the Soot engine.
            # Therefore we start with an initialized native state and extend this with the
            # Soot initializations.
            # Note: `addr` needs to be set to a `native address` (i.e. not an SootAddressDescriptor);
            #       otherwise the `project.entry` is used and the SimState would be in "Soot-mode"
            # TODO: use state_blank function from the native simos and not super class
            state = super(SimJavaVM, self).state_blank(addr=0, **kwargs)
        else:
            # w/o JNI support, we can just use a blank state
            state = SimState(project=self.project, **kwargs)

        ## Soot initializations
        state.regs._ip = addr if addr else self.project.entry
        state.regs._ip_binary = self.project.loader.main_object
        state.regs._invoke_return_target = None
        state.regs._invoke_return_variable = None

        # Push the stack frame for the next function we are going to execute
        state.memory.push_stack_frame()
        new_frame = state.callstack.copy()
        new_frame.ret_addr = SootAddressTerminator()
        state.callstack.push(new_frame)
        
        return state

    def state_entry(self, args=None, env=None, argc=None, **kwargs):
        state = self.state_blank(**kwargs)

        # Push the array of command line arguments on the stack frame
        if args is None:
            args = [state.se.StringS("args", 1000)]*100
        # if the user provides only one arguments create a list
        elif not isinstance(args, list):
            args = [args]

        # Since command line arguments are stored into arrays in Java
        # and arrays are stored on the heap we need to allocate the array on the heap\
        # and return the reference
        size_ = len(args)
        type_ = "String"
        local = SimSootValue_Local(state.project.entry.method.fullname, "param_0", type_)
        for idx, elem in enumerate(args):
            ref = SimSootValue_ArrayRef(idx, type_, local, size_)
            state.memory.store(ref, elem)
        base_ref = SimSootValue_ArrayRef(0, type_, local, size_)
        state.memory.store(local, base_ref)

        # Sometimes classes has a special method called "<clinit> that initialize part
        # of the class such as static field with default value etc.
        # This method would never be executed in a normal exploration so at class
        # loading time (loading of the main class in this case) we force the symbolic execution
        # of the method <clinit> and we update the state accordingly.
        manifest = state.project.loader.main_bin.get_manifest()
        main_cls = state.project.loader.main_bin.get_class(manifest["Main-Class"])
        for method in main_cls.methods:
            if method.name == "<clinit>":
                entry_state = state.copy()
                simgr = state.project.factory.simgr(entry_state)
                simgr.active[0].ip = SootAddressDescriptor(SootMethodDescriptor.from_method(method), 0, 0)
                simgr.run()
                # if we reach the end of the method the correct state is the deadended state
                if simgr.deadended:
                    # The only thing that can change in the <clinit> methods are static fields so
                    # it can only change the vm_static_table and the heap.
                    # We need to fix the entry state memory with the new memory state.
                    state.memory.vm_static_table = simgr.deadended[0].memory.vm_static_table.copy()
                    state.memory.heap = simgr.deadended[0].memory.heap.copy()
                break

        return state


    def state_call(self, addr, *args, **kwargs):
        if isinstance(addr, SootAddressDescriptor):
            super(SimJavaVM, self).state_call(addr, *args, **kwargs)
        else:
            cc = DEFAULT_CC[self.native_simos.arch.name](self.native_simos.arch)
            return self.native_simos.state_call(addr, *args, cc=cc, **kwargs)

    #
    # Execution
    #

    def native_call_return_to_soot_hook(self, state):
        """
        Hook target for native function returns. 

        This function will toggle the state, s.t. the execution continues in the Soot engine.
        """

        ret_state = state.copy()
        ret_state.get_plugin("memory", plugin_suffix='soot').pop_stack_frame()
        ret_state.get_plugin("callstack", plugin_suffix='soot').pop()
        ret_addr = ret_state.get_plugin("callstack", plugin_suffix='soot').ret_addr
        ret_state.regs._ip = ret_addr
        ret_state.scratch.guard = ret_state.se.true
        ret_state.history.jumpkind = 'Ijk_Ret'

    #        ret_var = ret_state.callstack.invoke_return_variable
    #        if ret_var is not None and ret_value is not None:
    #            # Write the return value to the return variable in the previous stack frame
    #            ret_state.memory.store(ret_var, ret_value)

        return [ret_state]

    def get_clemory_addr_of_native_method(self, soot_method):
        """
        :param soot_method: Soot method descriptor of a native declared function.
        :return:  CLE address of the given method in a native library
        """
        # TODO: consider more attributes
        for name, symbol in self.native_symbols.items():
            name_list = name.split('_')
            if name_list[-1] == soot_method.name:
                l.debug("Found native symbol '%s' @ %x matching Soot method '%s'" % (name, symbol.rebased_addr, soot_method) )
                return symbol.rebased_addr
                
        else:
            raise AngrSimOSError("No native method found that matches the Soot method.")
