import logging

from angr import SIM_PROCEDURES
from archinfo.arch_soot import (ArchSoot, SootAddressDescriptor,
                                SootAddressTerminator, SootArgument)
from claripy import BVS, BVV, StringS

from ..calling_conventions import DEFAULT_CC, SimCCSoot
from ..engines.soot import SimEngineSoot
from ..engines.soot.expressions import SimSootExpr_NewArray
from ..engines.soot.values import SimSootValue_StringRef
from ..errors import AngrSimOSError
from ..procedures.java_jni import jni_functions
from ..sim_state import SimState
from ..sim_type import SimTypeFunction, SimTypeReg
from .simos import SimOS

l = logging.getLogger('angr.simos.JavaVM')


class SimJavaVM(SimOS):

    def __init__(self, *args, **kwargs):
        super(SimJavaVM, self).__init__(*args, name='JavaVM', **kwargs)

        # is the binary using JNI libraries?
        self.is_javavm_with_jni_support = self.project.loader.main_object.jni_support

        if self.is_javavm_with_jni_support:
            # Step 1: find all native libs
            self.native_libs = [obj for obj in self.project.loader.initial_load_objects
                                    if not isinstance(obj.arch, ArchSoot)]

            if len(self.native_libs) == 0:
                raise AngrSimOSError("No JNI lib was loaded. Is the jni_libs_ld_path set correctly?")

            # Step 2: determine and set the native SimOS
            from . import os_mapping  # import dynamically, since the JavaVM class is part of the os_mapping dict
            # for each native library get the Arch
            native_libs_arch = set([obj.arch.__class__ for obj in self.native_libs])
            # for each native library get the compatible SimOS
            native_libs_simos = set([os_mapping[obj.os] for obj in self.native_libs])
            # show warning, if more than one SimOS or Arch would be required
            if len(native_libs_simos) > 1 or len(native_libs_arch) > 1:
                l.warning("Native libraries appear to require different SimOS's (%s) or Arch's (%s).",
                          native_libs_simos, native_libs_arch)
            # instantiate native SimOS
            if native_libs_simos:
                self.native_simos = native_libs_simos.pop()(self.project)
                self.native_simos.arch = native_libs_arch.pop()()
                self.native_simos.configure_project()
            else:
                raise AngrSimOSError("Cannot instantiate SimOS for native libraries: No compatible SimOS found.")

            # Step 3: Match static JNI symbols from native libs
            self.native_symbols = {}
            for lib in self.native_libs:
                for name, symbol in lib.symbols_by_name.items():
                    if name.startswith(u'Java'):
                        self.native_symbols[name] = symbol

            # Step 4: Allocate memory for the return hook
            # => In order to return back from the Vex to the Soot engine, we hook the return address (see state_call).
            self.native_return_hook_addr = self.project.loader.extern_object.allocate()
            self.project.hook(self.native_return_hook_addr, SimEngineSoot.prepare_native_return_state)

            # Step 5: JNI interface functions
            # => During runtime, native code can interact with the JVM through JNI interface functions.
            #    For this, the native code gets the JNIEnv interface pointer with every native call, which
            #    "[...] points to a location that contains a pointer to a function table" and "each entry in
            #    the function table points to a JNI function."
            # => In order to simulate this mechanism, we setup this structure in the native memory and hook all
            #    table entries with SimProcedures, which then implement the effects of the interface functions.

            # i)   First we allocate memory for the JNIEnv pointer and the function table
            native_addr_size = self.native_simos.arch.bits/8
            function_table_size = native_addr_size*len(jni_functions)
            self.jni_env = self.project.loader.extern_object.allocate(native_addr_size)
            self.jni_function_table = self.project.loader.extern_object.allocate(function_table_size)
            # ii)  Then we hook each table entry with the corresponding sim procedure
            for idx, jni_function in enumerate(jni_functions.values()):
                addr = self.jni_function_table + idx * native_addr_size
                self.project.hook(addr, SIM_PROCEDURES['java_jni'][jni_function]())
            # iii) Lastly, we store the targets of the JNIEnv and function pointer in memory.
            #      => This is done for a specific state (see state_blank)

    #
    # States
    #

    def state_blank(self, addr=None, **kwargs): # pylint: disable=arguments-differ

        if not kwargs.get('mode', None): kwargs['mode'] = self.project._default_analysis_mode
        if not kwargs.get('arch', None):  kwargs['arch'] = self.arch
        if not kwargs.get('os_name', None): kwargs['os_name'] = self.name

        if self.is_javavm_with_jni_support:
            # If the JNI support is enabled (i.e. JNI libs are loaded), the SimState
            # needs to support both the Vex and the Soot engine. Therefore we start with
            # an initialized native state and extend this with the Soot initializations.
            # Note: Setting `addr` to a `native address` (i.e. not an SootAddressDescriptor).
            #       makes sure that the SimState is not in "Soot-mode".
            # TODO: use state_blank function from the native simos and not the super class
            state = super(SimJavaVM, self).state_blank(addr=0, **kwargs)
            native_addr_size = self.native_simos.arch.bits
            # Let the JNIEnv pointer point to the function table
            state.memory.store(addr=self.jni_env,
                               data=BVV(self.jni_function_table, native_addr_size),
                               endness=self.native_arch.memory_endness)
            # Initialize the function table
            # => Each entry usually contains the address of the function, but since we hook all functions
            #    with SimProcedures, we store the address of the corresonding hook instead.
            #    This, by construction, is exactly the address of the function table entry itself.
            for idx in range(len(jni_functions)):
                jni_function_addr = self.jni_function_table + idx * native_addr_size/8
                state.memory.store(addr=jni_function_addr,
                                   data=BVV(jni_function_addr, native_addr_size),
                                   endness=self.native_arch.memory_endness)

        else:
            # w/o JNI support, we can just use a blank state
            state = SimState(project=self.project, **kwargs)

        if not self.project.entry and not addr:
            raise ValueError("Failed to init blank state. Project entry is not set/invalid"
                             "and no address was provided.")

        # init state register
        state.regs._ip = addr if addr else self.project.entry
        state.regs._ip_binary = self.project.loader.main_object
        state.regs._invoke_return_target = None
        state.regs._invoke_return_variable = None

        # add empty stack frame
        state.memory.push_stack_frame()

        # create bottom of callstack
        new_frame = state.callstack.copy()
        new_frame.ret_addr = SootAddressTerminator()
        state.callstack.push(new_frame)

        # initialize class
        state.javavm_classloader.get_class(state.addr.method.class_name, init_class=True)

        return state

    def state_entry(self, *args, **kwargs): # pylint: disable=arguments-differ
        """
        Create an entry state.

        :param *args: List of SootArgument values (optional).
        """
        state = self.state_blank(**kwargs)
        # for the Java main method `public static main(String[] args)`,
        # we add symbolic cmdline arguments
        if not args and state.addr.method.name == 'main' and \
                        state.addr.method.params[0] == 'java.lang.String[]':
            cmd_line_args = SimSootExpr_NewArray.new_array(state, "java.lang.String", BVS('argc', 32))
            cmd_line_args.add_default_value_generator(self.generate_symbolic_cmd_line_arg)
            args = [SootArgument(cmd_line_args, "java.lang.String[]")]
            # for referencing the Java array, we need to know the array reference
            # => saves it in the globals dict
            state.globals['cmd_line_args'] = cmd_line_args
        # setup arguments
        state = self.state_call(state.addr, *args, base_state=state)
        return state

    @staticmethod
    def generate_symbolic_cmd_line_arg(state, max_length=1000):
        """
        Generates a new symbolic cmd line argument string.
        :return: The string reference.
        """
        str_ref = SimSootValue_StringRef(state.memory.get_new_uuid())
        state.memory.store(str_ref, StringS("cmd_line_arg", max_length))
        return str_ref

    def state_call(self, addr, *args, **kwargs):
        """
        Create a native or a Java call state.

        :param addr:    Soot or native addr of the invoke target.
        :param *args:   List of SootArgument values.
        """
        state = kwargs.pop('base_state')
        # check if we need to setup a native or a java callsite
        if isinstance(addr, SootAddressDescriptor):
            # JAVA CALLSITE
            ret_addr = kwargs.pop('ret_addr', SootAddressTerminator())
            cc = kwargs.pop('cc', SimCCSoot(self.arch))
            if state is None:
                state = self.state_blank(addr=addr, **kwargs)
            else:
                state = state.copy()
                state.regs.ip = addr
            cc.setup_callsite(state, ret_addr, args)
            return state

        else:
            # NATIVE CALLSITE
            # setup native argument values
            native_arg_values = []
            for arg in args:
                if arg.type in ArchSoot.primitive_types or \
                   arg.type == "JNIEnv":
                    # the value of primitive types and the JNIEnv pointer
                    # are just getting copied into the native memory
                    native_arg_value = arg.value
                else:
                    # argument has a relative type
                    # => map Java reference to an opaque reference, which the native code
                    #    can use to access the Java object through the JNI interface
                    native_arg_value = state.jni_references.create_new_reference(obj=arg.value)
                native_arg_values += [native_arg_value]

            # setup native return type
            ret_type = kwargs.pop('ret_type')
            native_ret_type = self.get_native_type(ret_type)

            # setup function prototype, so the SimCC know how to init the callsite
            arg_types = [self.get_native_type(arg.type) for arg in args]
            prototype = SimTypeFunction(args=arg_types, returnty=native_ret_type)
            native_cc = self.get_native_cc(func_ty=prototype)

            # setup native invoke state
            return self.native_simos.state_call(addr, *native_arg_values,
                                                base_state=state,
                                                ret_addr=self.native_return_hook_addr,
                                                cc=native_cc, **kwargs)

    #
    # MISC
    #

    @staticmethod
    def get_default_value_by_type(type_):
        """
        Java specify defaults values for primitive and reference types. This
        method returns the default value for a given type.

        :param str type_:   Name of type.
        :return:            Default value for this type.
        """
        if type_ in ['byte', 'char', 'short', 'int', 'boolean']:
            return BVV(0, 32)
        elif type_ == "long":
            return BVV(0, 64)
        else:
            l.error("Could not determine the default value for type %s.", type_)
            return None

    @staticmethod
    def cast_primitive(value, to_type):
        """
        Cast the value of primtive types.

        :param value:       Bitvector storing the primitive value.
        :param to_type:     Name of the targeted type.
        :return:            Resized value.
        """
        if to_type in ['float', 'double']:
            raise NotImplementedError('No support for floating-point arguments.')

        # lookup the type size and extract value
        value_size = ArchSoot.sizeof[to_type]
        value_extracted = value.reversed.get_bytes(index=0, size=value_size/8).reversed

        # determine size of Soot bitvector and resize bitvector
        # Note: smaller types than int's are stored in a 32-bit BV
        value_soot_size = value_size if value_size >= 32 else 32
        if to_type in ['char', 'boolean']:
            # unsigned extend
            return value_extracted.zero_extend(value_soot_size-value_size)
        # signed extend
        return value_extracted.sign_extend(value_soot_size-value_size)

    #
    # Helper JNI
    #

    def get_addr_of_native_method(self, soot_method):
        """
        Get address of the implementation from a native declared Java function.

        :param soot_method: Method descriptor of a native declared function.
        :return: CLE address of the given method.
        """
        for name, symbol in self.native_symbols.items():
            if soot_method.matches_with_native_name(native_method=name):
                l.debug("Found native symbol '%s' @ %x matching Soot method '%s'",
                        name, symbol.rebased_addr, soot_method)
                return symbol.rebased_addr

        native_symbols = "\n".join(self.native_symbols.keys())
        raise AngrSimOSError("No native method found that matches the Soot method '%s'."
                             "\nAvailable symbols (prefix + encoded class path + encoded method name):\n%s"
                             % soot_method.name, native_symbols)

    def get_native_type(self, java_type):
        """
        Maps the Java type to a SimTypeReg representation of its native
        counterpart. This type can be used to indicate the (well-defined) size
        of native JNI types.

        :return: A SymTypeReg with the JNI size of the given type.
        """
        if java_type in ArchSoot.sizeof.keys():
            jni_type_size = ArchSoot.sizeof[java_type]
        else:
            # if it's not a primitive type, we treat it as a reference
            jni_type_size = self.native_simos.arch.bits
        return SimTypeReg(size=jni_type_size)

    @property
    def native_arch(self):
        """
        :return: Arch of the native simos.
        """
        return self.native_simos.arch

    def get_native_cc(self, func_ty=None):
        """
        :return: SimCC object for the native simos.
        """
        native_cc_cls = DEFAULT_CC[self.native_simos.arch.name]
        return native_cc_cls(self.native_simos.arch, func_ty=func_ty)
