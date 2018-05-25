import logging

from angr import SIM_PROCEDURES
from archinfo.arch_soot import (ArchSoot, SootAddressDescriptor,
                                SootAddressTerminator, SootMethodDescriptor)
from claripy import BVV

from ..calling_conventions import DEFAULT_CC
from ..engines.soot.values.arrayref import SimSootValue_ArrayRef
from ..engines.soot.values.local import SimSootValue_Local
from ..engines.soot import SimEngineSoot
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
                l.warning("Unsupported: Native libraries appear to require different SimOS's (%s) or Arch's (%s)." 
                          % (str(native_libs_arch), str(native_libs_simos)))
            # instantiate native SimOS
            if native_libs_simos:
                self.native_simos = native_libs_simos.pop()(self.project)
                self.native_simos.arch = native_libs_arch.pop()
                self.native_simos.configure_project()
            else:
                raise AngrSimOSError("Cannot instantiate SimOS for native libraries: No compatible SimOS found.")

            # Step 3: Match static JNI symbols from native libs
            self.native_symbols = {}
            for lib in self.native_libs:
                for name, symbol in lib.symbols_by_name.items():
                    if name.startswith(u'Java'):
                        self.native_symbols[name] = symbol

            # Step 4: Look up SimCC class of the native calling convention 
            self.native_cc_cls = DEFAULT_CC[self.native_simos.arch.name]

            # Step 5: Allocate memory for the return hook
            # => In order to return back from the Vex to the Soot engine, we hook the return address (see state_call).
            self.native_return_hook_addr = self.project.loader.extern_object.allocate()
            self.project.hook(self.native_return_hook_addr, SimEngineSoot.prepare_native_return_state)

            # Step 6: JNI interface functions
            # => During runtime, the native code can interact with the JVM through JNI interface functions.
            #    For this, the native code gets a JNIEnv interface pointer with every native call, which 
            #    "[...] points to a location that contains a pointer to a function table" and "each entry in 
            #    the function table points to a JNI function."
            # => In order to simulate this mechanism, we setup this structure in the native memory and hook all 
            #    table entries with SimProcedures, which then implement the effects of the interface functions.
            # i)   First we allocate memory for the JNIEnv pointer and the function table
            native_addr_size = self.native_simos.arch.bits/8
            self.jni_env = self.project.loader.extern_object.allocate(size=native_addr_size)
            self.jni_function_table = self.project.loader.extern_object.allocate(size=native_addr_size*len(jni_functions))
            # ii)  Then we hook each table entry with the corresponding sim procedure
            for idx, jni_function in enumerate(jni_functions):
                addr = self.jni_function_table + idx * native_addr_size
                if not jni_function:
                    self.project.hook(addr, SIM_PROCEDURES['java_jni']['NotImplemented'])
                else: 
                    self.project.hook(addr, SIM_PROCEDURES['java_jni'][jni_function])
            # iii) We store the targets of the JNIEnv and function pointer in memory.
            #      => This is done for a specific state (see state_blank)

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
            # Note: `addr` needs to be set to a `native address` (i.e. not an SootAddressDescriptor).
            #       This makes sure that the SimState is not in "Soot-mode".
            # TODO: use state_blank function from the native simos and not the super class
            state = super(SimJavaVM, self).state_blank(addr=0, **kwargs)
            # Let the target of the JNIEnv pointer point to the function table
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
            args = [state.se.StringS("cmd_arg", 1000) for _ in range(100)]
        # if the user provides only one arguments create a list
        elif not isinstance(args, list):
            args = [args]

        # Since command line arguments are stored into arrays in Java
        # and arrays are stored on the heap we need to allocate the array on the heap\
        # and return the reference
        size_ = len(args)
        type_ = "String[]"
        heap_alloc_id = state.memory.get_new_uuid()
        for idx, elem in enumerate(args):
            ref = SimSootValue_ArrayRef(heap_alloc_id, idx, type_, size_)
            state.memory.store(ref, elem)
        base_ref = SimSootValue_ArrayRef(heap_alloc_id, 0, type_, size_)
        local = SimSootValue_Local("param_0", type_)
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
        # *args contains the argument values together with their types
        # => extract values
        arg_values = tuple(arg for (arg, arg_type) in args)
        # Check if we need to setup a native call site
        if isinstance(addr, SootAddressDescriptor):
            # TODO:
            # If no args are provided, create symbolic bit vectors and constrain
            # the value w.r.t. to the type
            super(SimJavaVM, self).state_call(addr, *arg_values, **kwargs)
        
        else:
            # Create function prototype, so the SimCC know how to setup the call-site
            ret_type = kwargs.pop('ret_type')
            arg_types = tuple(arg_type for (arg, arg_type) in args)
            prototype = SimTypeFunction(arg_types, ret_type)
            native_cc = self.native_cc_cls(self.native_simos.arch, func_ty=prototype)
            # Setup native invoke_state
            invoke_state = self.native_simos.state_call(addr, *arg_values, 
                                                        ret_addr=self.native_return_hook_addr, 
                                                        cc=native_cc, **kwargs)
            invoke_state.scratch.invoke_native_cc = native_cc
            return invoke_state

    #
    # Helper
    #

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

    def generate_opaque_reference(self):
        """
        Native code cannot interact directly with Java objects, but needs to use JNI interface
        functions. For this, Java objects are getting referenced with opaque references.

        :return: Address, which can be used as an opaque reference.
        """
        return self.project.loader.extern_object.allocate()

    def get_native_type(self, java_type):
        """
        Maps the Java type to a SimTypeReg representation of its native counterpart.
        This type can be used to indicate the (well-defined) size of the native JNI type.

        :return: A SymTypeReg with the JNI size of the given type.
        """
        if java_type in ArchSoot.sizeof.keys():
            jni_type_size = ArchSoot.sizeof[java_type]

        elif java_type == "reference":
            jni_type_size = self.native_simos.arch.bits
        
        else:
            l.warning("Unknown type %s" % java_type)
            return None

        return SimTypeReg(size=jni_type_size)
