import logging

from angr import SIM_PROCEDURES, options
from archinfo.arch_soot import (ArchSoot, SootAddressDescriptor,
                                SootAddressTerminator, SootArgument,
                                SootNullConstant)
from claripy import BVS, BVV, StringS, StringV, FSORT_FLOAT, FSORT_DOUBLE, FPV, FPS
from claripy.ast.fp import FP, fpToIEEEBV
from claripy.ast.bv import BV

from ..calling_conventions import DEFAULT_CC, SimCCSoot
from ..engines.soot import SootMixin
from ..engines.soot.expressions import SimSootExpr_NewArray #, SimSootExpr_NewMultiArray
from ..engines.soot.values import (SimSootValue_ArrayRef,
                                   SimSootValue_StringRef,
                                   SimSootValue_ThisRef,
                                   SimSootValue_StaticFieldRef)
from ..errors import AngrSimOSError
from ..procedures.java_jni import jni_functions
from ..sim_state import SimState
from ..sim_type import SimTypeFunction, SimTypeNum
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
            native_libs_arch = {obj.arch.__class__ for obj in self.native_libs}
            # for each native library get the compatible SimOS
            native_libs_simos = {os_mapping[obj.os] for obj in self.native_libs}
            # show warning, if more than one SimOS or Arch would be required
            if len(native_libs_simos) > 1 or len(native_libs_arch) > 1:
                l.warning("Native libraries appear to require different SimOS's (%s) or Arch's (%s).",
                          native_libs_simos, native_libs_arch)
            # instantiate the native SimOS
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
            self.project.hook(self.native_return_hook_addr, prepare_native_return_state)

            # Step 5: JNI interface functions
            # => During runtime, native code can interact with the JVM through JNI interface functions.
            #    For this, the native code gets the JNIEnv interface pointer with every native call, which
            #    "[...] points to a location that contains a pointer to a function table" and "each entry in
            #    the function table points to a JNI function."
            # => In order to simulate this mechanism, we setup this structure in the native memory and hook all
            #    table entries with SimProcedures, which then implement the effects of the interface functions.

            # i)   First we allocate memory for the JNIEnv pointer and the function table
            native_addr_size = self.native_simos.arch.bits//8
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
        # enable support for string analysis
        add_options = kwargs.get('add_options', set())
        add_options.add(options.STRINGS_ANALYSIS)
        add_options.add(options.COMPOSITE_SOLVER)
        kwargs['add_options'] = add_options

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
            #    with SimProcedures, we store the address of the corresponding hook instead.
            #    This, by construction, is exactly the address of the function table entry itself.
            for idx in range(len(jni_functions)):
                jni_function_addr = self.jni_function_table + idx * native_addr_size//8
                state.memory.store(addr=jni_function_addr,
                                   data=BVV(jni_function_addr, native_addr_size),
                                   endness=self.native_arch.memory_endness)

        else:
            # w/o JNI support, we can just use a blank state
            state = SimState(project=self.project, **kwargs)

        if not self.project.entry and not addr:
            raise ValueError("Failed to init blank state. Project entry is not set/invalid "
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

        # initialize class containing the current method
        state.javavm_classloader.get_class(state.addr.method.class_name,
                                           init_class=True, step_func=kwargs.get('step_function', None))

        # initialize the Java environment
        # TODO move this to `state_full_init?
        self.init_static_field(state, "java.lang.System", "in", "java.io.InputStream")
        self.init_static_field(state, "java.lang.System", "out", "java.io.PrintStream")

        return state

    def state_entry(self, args=None, **kwargs): # pylint: disable=arguments-differ
        """
        Create an entry state.

        :param args: List of SootArgument values (optional).
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
        SootMixin.setup_arguments(state, args)
        return state

    @staticmethod
    def generate_symbolic_cmd_line_arg(state, max_length=1000):
        """
        Generates a new symbolic cmd line argument string.
        :return: The string reference.
        """
        str_ref = SimSootValue_StringRef(state.memory.get_new_uuid())
        str_sym = StringS("cmd_line_arg", max_length)
        state.solver.add(str_sym != StringV(""))
        state.memory.store(str_ref, str_sym)
        return str_ref

    def state_call(self, addr, *args, **kwargs):
        """
        Create a native or a Java call state.

        :param addr:    Soot or native addr of the invoke target.
        :param args:   List of SootArgument values.
        """
        state = kwargs.pop('base_state', None)
        # check if we need to setup a native or a java callsite
        if isinstance(addr, SootAddressDescriptor):
            # JAVA CALLSITE
            # ret addr precedence: ret_addr kwarg > base_state.addr > terminator
            ret_addr = kwargs.pop('ret_addr', state.addr if state else SootAddressTerminator())
            cc = kwargs.pop('cc', SimCCSoot(self.arch))
            if state is None:
                state = self.state_blank(addr=addr, **kwargs)
            else:
                state = state.copy()
                state.regs.ip = addr
            cc.setup_callsite(state, ret_addr, args, kwargs.pop('prototype', None))
            return state

        else:
            # NATIVE CALLSITE

            # setup native return type
            # TODO roll this into protytype
            ret_type = kwargs.pop('ret_type')
            native_ret_type = self.get_native_type(ret_type)

            # setup function prototype, so the SimCC know how to init the callsite
            prototype = kwargs.pop('prototype', None)
            if prototype is None:
                arg_types = [self.get_native_type(arg.type) for arg in args]
                prototype = SimTypeFunction(args=arg_types, returnty=native_ret_type)
            native_cc = kwargs.pop('cc', None)
            if native_cc is None:
                native_cc = self.get_native_cc()

            # setup native argument values
            native_arg_values = []
            for arg, arg_ty in zip(args, prototype.args):
                if arg.type in ArchSoot.primitive_types or \
                   arg.type == "JNIEnv":
                    # the value of primitive types and the JNIEnv pointer
                    # are just getting copied into the native memory
                    native_arg_value = arg.value
                    if self.arch.bits == 32 and arg.type == "long":
                        # On 32 bit architecture, long values (w/ 64 bit) are copied
                        # as two 32 bit integer
                        # TODO I _think_ all this logic can go away as long as the cc knows how to store large values
                        # TODO this has been mostly implemented 11 Dec 2021
                        # unfortunately no test cases hit this branch so I don't wanna touch it :(
                        upper = native_arg_value.get_bytes(0, 4)
                        lower = native_arg_value.get_bytes(4, 4)
                        idx = args.index(arg)
                        args = args[:idx] \
                               + (SootArgument(upper, 'int'), SootArgument(lower, 'int')) \
                               + args[idx+1:]
                        native_arg_values += [upper, lower]
                        continue
                    if type(arg.value) is BV and len(arg.value) > arg_ty.size:
                        # hack??? all small primitives are passed around as 32bit but cc won't like that
                        native_arg_value = native_arg_value[arg_ty.size - 1:0]
                else:
                    # argument has a relative type
                    # => map Java reference to an opaque reference, which the native code
                    #    can use to access the Java object through the JNI interface
                    native_arg_value = state.jni_references.create_new_reference(obj=arg.value)
                native_arg_values += [native_arg_value]

            # setup native invoke state
            return self.native_simos.state_call(addr, *native_arg_values,
                                                base_state=state,
                                                ret_addr=self.native_return_hook_addr,
                                                cc=native_cc, prototype=prototype, **kwargs)

    #
    # MISC
    #

    @staticmethod
    def get_default_value_by_type(type_, state):
        """
        Java specify defaults values for primitive and reference types. This
        method returns the default value for a given type.

        :param str type_:       Name of type.
        :param SimState state:  Current SimState.
        :return:                Default value for this type.
        """
        if options.ZERO_FILL_UNCONSTRAINED_MEMORY not in state.options:
            return SimJavaVM._get_default_symbolic_value_by_type(type_, state)
        return SimJavaVM._get_default_concrete_value_by_type(type_, state)

    @staticmethod
    def _get_default_symbolic_value_by_type(type_, state):
        if type_ in ['byte', 'char', 'short', 'int', 'boolean']:
            return BVS('default_value_{}'.format(type_), 32)
        if type_ == "long":
            return BVS('default_value_{}'.format(type_), 64)
        if type_ == 'float':
            return FPS('default_value_{}'.format(type_), FSORT_FLOAT)
        if type_ == 'double':
            return FPS('default_value_{}'.format(type_), FSORT_DOUBLE)
        if type_ == 'java.lang.String':
            return SimSootValue_StringRef.new_string(state, StringS('default_value_{}'.format(type_), 1000))
        if type_.endswith('[][]'):
            raise NotImplementedError
            # multiarray = SimSootExpr_NewMultiArray.new_array(self.state, element_type, size)
            # multiarray.add_default_value_generator(lambda s: SimSootExpr_NewMultiArray._generate_inner_array(s, element_type, sizes))
            # return  multiarray
        if type_.endswith('[]'):
            array = SimSootExpr_NewArray.new_array(state, type_[:-2], BVV(2, 32))
            return array
        return SimSootValue_ThisRef.new_object(state, type_, symbolic=True, init_object=False)

    @staticmethod
    def _get_default_concrete_value_by_type(type_, state=None): # pylint: disable=unused-argument
        if type_ in ['byte', 'char', 'short', 'int', 'boolean']:
            return BVV(0, 32)
        elif type_ == "long":
            return BVV(0, 64)
        elif type_ == 'float':
            return FPV(0, FSORT_FLOAT)
        elif type_ == 'double':
            return FPV(0, FSORT_DOUBLE)
        # not a primitive type
        # => treat it as a reference
        return SootNullConstant()

    @staticmethod
    def cast_primitive(state, value, to_type):
        """
        Cast the value of primtive types.

        :param value:       Bitvector storing the primitive value.
        :param to_type:     Name of the targeted type.
        :return:            Resized value.
        """
        if to_type in ['float', 'double']:
            if value.symbolic:
                # TODO extend support for floating point types
                l.warning('No support for symbolic floating-point arguments.'
                          'Value gets concretized.')
            value = float(state.solver.eval(value))
            sort = FSORT_FLOAT if to_type == 'float' else FSORT_DOUBLE
            return FPV(value, sort)

        elif to_type == 'int' and isinstance(value, FP):
            # TODO fix fpToIEEEBV in claripty
            l.warning('Converting FP to BV might provide incorrect results.')
            return fpToIEEEBV(value)[63:32]

        elif to_type == 'long' and isinstance(value, FP):
            # TODO fix fpToIEEEBV in claripty
            l.warning('Converting FP to BV might provide incorrect results.')
            return fpToIEEEBV(value)

        else:
            # lookup the type size and extract value
            value_size = ArchSoot.sizeof[to_type]
            value_extracted = value.reversed.get_bytes(index=0, size=value_size//8).reversed

            # determine size of Soot bitvector and resize bitvector
            # Note: smaller types than int's are stored in a 32-bit BV
            value_soot_size = value_size if value_size >= 32 else 32
            if to_type in ['char', 'boolean']:
                # unsigned extend
                return value_extracted.zero_extend(value_soot_size-value_extracted.size())
            # signed extend
            return value_extracted.sign_extend(value_soot_size-value_extracted.size())

    @staticmethod
    def init_static_field(state, field_class_name, field_name, field_type):
        """
        Initialize the static field with an allocated, but not initialized,
        object of the given type.

        :param state: State associated to the field.
        :param field_class_name: Class containing the field.
        :param field_name: Name of the field.
        :param field_type: Type of the field and the new object.
        """
        field_ref = SimSootValue_StaticFieldRef.get_ref(state, field_class_name,
                                                        field_name, field_type)
        field_val = SimSootValue_ThisRef.new_object(state, field_type)
        state.memory.store(field_ref, field_val)

    @staticmethod
    def get_cmd_line_args(state):
        args_array = state.globals['cmd_line_args']
        no_of_args = state.solver.eval(args_array.size)
        args = []
        for idx in range(no_of_args):
            array_ref = SimSootValue_ArrayRef(args_array, idx)
            str_ref = state.memory.load(array_ref)
            cmd_line_arg = state.memory.load(str_ref)
            args.append(cmd_line_arg)
        return args

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
        l.warning("No native method found that matches the Soot method '%s'. "
                  "Skipping statement.", soot_method.name)
        l.debug("Available symbols (prefix + encoded class path + encoded method "
                "name):\n%s", native_symbols)
        return None

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
        return SimTypeNum(size=jni_type_size)

    def get_method_native_type(self, method):
        return SimTypeFunction

    @property
    def native_arch(self):
        """
        :return: Arch of the native simos.
        """
        return self.native_simos.arch

    def get_native_cc(self):
        """
        :return: SimCC object for the native simos.
        """
        native_cc_cls = DEFAULT_CC[self.native_simos.arch.name]
        return native_cc_cls(self.native_simos.arch)

def prepare_native_return_state(native_state):
    """
    Hook target for native function call returns.

    Recovers and stores the return value from native memory and toggles the
    state, s.t. execution continues in the Soot engine.

    Note: Redirection needed for pickling.
    """
    return SootMixin.prepare_native_return_state(native_state)

from .. import sim_options as options
