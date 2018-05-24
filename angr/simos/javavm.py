import logging

from angr import SIM_PROCEDURES
from archinfo.arch_soot import (ArchSoot, SootAddressDescriptor,
                                SootAddressTerminator, SootMethodDescriptor)
from claripy import BVV

from ..calling_conventions import DEFAULT_CC
from ..engines.soot.values.arrayref import SimSootValue_ArrayRef
from ..engines.soot.values.local import SimSootValue_Local
from ..errors import AngrSimOSError
from ..procedures.java_jni import jni_functions
from ..sim_state import SimState
from ..sim_type import SimTypeFunction, SimTypeInt, SimTypeReg
from .simos import SimOS

l = logging.getLogger('angr.simos.JavaVM')

class SimJavaVM(SimOS):

    def __init__(self, *args, **kwargs):

        super(SimJavaVM, self).__init__(*args, name='JavaVM', **kwargs)

        # are native libraries called via JNI?
        self.jni_support = self.project.loader.main_object.jni_support

        if self.jni_support:

            # Step 1: find all native libs
            self.native_libs = [obj for obj in self.project.loader.initial_load_objects
                                    if not isinstance(obj.arch, ArchSoot)]

            if len(self.native_libs) == 0:
                raise AngrSimOSError("No native lib was loaded. Is the native_libs_ld_path set correctly?")

            # Step 2: determine and set the native SimOS
            from . import os_mapping  # import dynamically, since the JavaVM class is part of the os_mapping dict
            # for each native library get the Arch
            native_libs_arch = set([obj.arch for obj in self.native_libs])
            # for each native library get the compatible SimOS 
            native_libs_simos = set([os_mapping[obj.os] for obj in self.native_libs]) 
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

            # Step 4: Look up SimCC class of the native calling convention 
            self.native_cc_cls = DEFAULT_CC[self.native_simos.arch.name]

            # Step 5: Allocate memory for the return hook
            # => In order to return back from the Vex to the Soot engine, we hook the return address.
            #    Therefore we set the return address of the native function to `native_call_return_to_soot`
            #    and hook it.
            self.native_call_return_to_soot = self.project.loader.extern_object.allocate()
            self.project.hook(self.native_call_return_to_soot, self.native_call_return_to_soot_hook)

            # Step 6: JNI interface functions
            # => During runtime, the native code can interact with the JVM through JNI interface functions.
            #    We hook these functions and implement the effects with SimProcedures.
            native_addr_size = self.native_simos.arch.bits/8
            # allocate memory for the jni env pointer and function table
            self.jni_env = self.project.loader.extern_object.allocate(size=native_addr_size, 
                                                                      alignment=native_addr_size)
            self.jni_function_table = self.project.loader.extern_object.allocate(size=native_addr_size*len(jni_functions),
                                                                                 alignment=native_addr_size)
            # hook jni functions
            for idx, jni_function in enumerate(jni_functions):
                addr = self.jni_function_table + idx * native_addr_size
                if not jni_function:
                    self.project.hook(addr, SIM_PROCEDURES['java_jni']['NotImplemented'])
                else: 
                    self.project.hook(addr, SIM_PROCEDURES['java_jni'][jni_function])

    #
    # States
    #

    def state_blank(self, addr=None, initial_prefix=None, stack_size=None, **kwargs):

        if not kwargs.get('mode', None): kwargs['mode'] = self.project._default_analysis_mode
        if not kwargs.get('arch', None):  kwargs['arch'] = self.arch
        if not kwargs.get('os_name', None): kwargs['os_name'] = self.name

        if self.jni_support:
            # If the JNI support is enabled (i.e. native libs are loaded), the SimState
            # needs to support both the Vex and the Soot engine. Therefore we start with 
            # an initialized native state and extend this with the Soot initializations.
            # Note: `addr` needs to be set to a `native address` (i.e. not an SootAddressDescriptor);
            #       otherwise the `project.entry` is used and the SimState would be in "Soot-mode"
            # TODO: use state_blank function from the native simos and not the super class
            state = super(SimJavaVM, self).state_blank(addr=0, **kwargs)
            # Let the env pointer point to the function table
            state.memory.store(self.jni_env, BVV(self.jni_function_table, 64).reversed)
            # Initialize the function table
            # => Each entry usually contains the address of the function, but since we hook all functions
            #    with SimProcedures, we store the address of the corresonding hook instead.
            #    This, by construction, is exactly the address of the function table entry itself.
            for idx in range(len(jni_functions)):
                native_addr_size = self.native_simos.arch.bits/8
                jni_function_addr = self.jni_function_table + idx * native_addr_size
                state.memory.store(jni_function_addr, BVV(jni_function_addr, 64).reversed)

        else:
            # w/o JNI support, we can just use a blank state
            state = SimState(project=self.project, **kwargs)

        ## Soot initializations
        state.regs._ip = addr if addr else self.project.entry
        state.regs._ip_binary = self.project.loader.main_object
        state.regs._invoke_return_target = None
        state.regs._invoke_return_variable = None

        # Add empty stack frame
        state.memory.push_stack_frame()

        # Create bottom of callstack
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
            # TODO:
            # If no args are provided, create symbolic bit vectors and constrain
            # the value w.r.t. to the type
            super(SimJavaVM, self).state_call(addr, *args, **kwargs)
        
        else:
            # Create function prototype, so the SimCC know how to setup the call-site
            ret_type = kwargs.pop('ret_type')
            arg_types = tuple(arg_type for (arg, arg_type) in args)
            prototype = SimTypeFunction(arg_types, ret_type)

            native_cc = self.native_cc_cls(self.native_simos.arch, func_ty=prototype)

            arg_values = tuple(arg for (arg, arg_type) in args)

            return self.native_simos.state_call(addr, *arg_values, 
                                                 ret_addr=self.native_call_return_to_soot, 
                                                 cc=native_cc, **kwargs)


    #
    # Execution
    #

    def native_call_return_to_soot_hook(self, native_state):
        """
        Hook target for native function returns. 

        This function will toggle the state, s.t. the execution continues in the Soot engine.
        """
        ret_state = native_state.copy()
        ret_addr = ret_state.get_plugin("callstack", with_suffix='_soot').ret_addr
        ret_state.regs._ip = ret_addr
        ret_var = ret_state.callstack.invoke_return_variable
        ret_state.scratch.guard = ret_state.se.true
        ret_state.history.jumpkind = 'Ijk_Ret'
        ret_state.memory.pop_stack_frame()
        ret_state.callstack.pop()
        
        if ret_var:
            # if available, move the return value to the Soot state

            if ret_var.type == 'void':
                # in this case, the 'invoke_return_variable' should not have been set
                l.warning("Return variable is available, but return type is set to void.")
            
            elif ret_var.type in ['float', 'double']:
                raise NotImplementedError()

            elif ret_var.type in ArchSoot.primitive_types.keys():
                # return value has a primitive type
                # => we need to manually cast the return value to the correct size, as this
                #    would be usually done by the java callee
                # 1. get return symbol from native state
                native_cc = self.native_cc_cls((self.native_simos.arch))
                ret_symbol = native_cc.get_return_val(native_state).to_claripy()
                # 2. lookup the size of the native type and extract value
                ret_var_native_size = ArchSoot.primitive_types[ret_var.type] 
                ret_value = ret_symbol.reversed.get_bytes(index=0, size=ret_var_native_size/8).reversed
                # 3. determine size of soot bitvector and resize bitvector
                # Note: smaller types than int's are stored as a 32-bit SootIntConstant 
                ret_var_soot_size = ret_var_native_size if ret_var_native_size >= 32 else 32
                if ret_var.type in ['char', 'boolean']:
                    # unsigned extend
                    ret_value = ret_value.zero_extend(ret_var_soot_size-ret_var_native_size)
                else:
                    # signed extend
                    ret_value = ret_value.sign_extend(ret_var_soot_size-ret_var_native_size)
                
            else:
                # reference type
                raise NotImplementedError()
                           
            l.debug("Assigning %s to return variable %s" % (str(ret_value), ret_var.local_name))
            ret_state.memory.store(ret_var, ret_value)
 
        return [ret_state]

    def get_clemory_addr_of_native_method(self, soot_method):
        """
        :param soot_method: Soot method descriptor of a native declared function.
        :return:  CLE address of the given method in a native library.
        """
        for name, symbol in self.native_symbols.items():
            if soot_method.matches_with_native_name(native_name=name):
                l.debug("Found native symbol '%s' @ %x matching Soot method '%s'" 
                        % (name, symbol.rebased_addr, soot_method))
                return symbol.rebased_addr
                
        else:
            native_symbols = "\n".join(self.native_symbols.keys())
            raise AngrSimOSError("No native method found that matches the Soot method '%s'.\
                                  \nAvailable symbols (prefix + encoded class path + encoded method name):\n%s"
                                  % (soot_method.name, native_symbols))
