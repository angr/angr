import logging

from archinfo.arch_arm import is_arm_arch

from ..analyses.cfg import CFGUtils
from ..calling_conventions import SimRegArg, SimStackArg, SimCC, DefaultCC
from ..sim_variable import SimStackVariable, SimRegisterVariable
from . import Analysis, register_analysis

l = logging.getLogger(name=__name__)


class CallingConventionAnalysis(Analysis):
    """
    Analyze the calling convention of functions.

    The calling convention of a function can be inferred at both its call sites and the function itself. At call sites,
    we consider all register and stack variables that are not alive after the function call as parameters to this
    function. In the function itself, we consider all register and stack variables that are read but without
    initialization as parameters. Then we synthesize the information from both locations and make a reasonable
    inference of calling convention of this function.
    """

    def __init__(self, func):

        self._function = func

        self._variable_manager = self.kb.variables

        self.cc = None

        self._analyze()

    def _analyze(self):
        """

        :return:
        """

        if self._function.is_simprocedure:
            self.cc = self._function.calling_convention
            if self.cc is None:
                # fallback to the default calling convention
                self.cc = DefaultCC[self.project.arch.name](self.project.arch)
            return
        if self._function.is_plt:
            self.cc = self._analyze_plt()
            return

        cc_0 = self._analyze_function()
        callsite_ccs = self._analyze_callsites()

        cc = self._merge_cc(cc_0, *callsite_ccs)

        if cc is None:
            l.warning('Cannot determine calling convention for %r.', self._function)

        self.cc = cc

    def _analyze_plt(self):
        """
        Get the calling convention for a PLT stub.

        :return:    A calling convention.
        """

        if len(self._function.jumpout_sites) != 1:
            l.warning("%r has more than one jumpout sites. It does not look like a PLT stub. Please report to GitHub.",
                      self._function)
            return None

        jo_site = self._function.jumpout_sites[0]

        successors = list(self._function.transition_graph.successors(jo_site))
        if len(successors) != 1:
            l.warning("%r has more than one successors. It does not look like a PLT stub. Please report to GitHub.",
                      self._function)
            return None

        real_func = self.kb.functions.get_by_addr(successors[0].addr)

        return real_func.calling_convention

    def _analyze_function(self):
        """
        Go over the variable information in variable manager for this function, and return all uninitialized
        register/stack variables.

        :return:
        """

        if self._function.is_simprocedure or self._function.is_plt:
            # we do not analyze SimProcedures or PLT stubs
            return None

        if not self._variable_manager.has_function_manager:
            l.warning("Please run variable recovery on %r before analyzing its calling convention.", self._function)
            return None

        vm = self._variable_manager[self._function.addr]

        input_variables = vm.input_variables()

        input_args = self._args_from_vars(input_variables)

        # TODO: properly decide sp_delta
        sp_delta = self.project.arch.bytes if self.project.arch.call_pushes_ret else 0

        cc = SimCC.find_cc(self.project.arch, list(input_args), sp_delta)

        if cc is None:
            l.warning('_analyze_function(): Cannot find a calling convention that fits the given arguments.')

        return cc

    def _analyze_callsites(self):  # pylint:disable=no-self-use
        """

        :return:
        """

        return []

    def _merge_cc(self, *cc_lst):  # pylint:disable=no-self-use

        # TODO: finish it

        return cc_lst[0]

    def _args_from_vars(self, variables):
        """


        :param list variables:
        :return:
        """

        args = set()
        if not self.project.arch.call_pushes_ret:
            ret_addr_offset = 0
        else:
            ret_addr_offset = self.project.arch.bytes

        for variable in variables:
            if isinstance(variable, SimStackVariable):
                # a stack variable. convert it to a stack argument.
                # TODO: deal with the variable base
                if variable.offset <= 0:
                    # skip the return address on the stack
                    # TODO: make sure it was the return address
                    continue
                arg = SimStackArg(variable.offset - ret_addr_offset, variable.size)
                args.add(arg)
            elif isinstance(variable, SimRegisterVariable):
                # a register variable, convert it to a register argument
                if not self._is_sane_register_variable(variable):
                    continue
                arg = SimRegArg(self.project.arch.register_size_names[(variable.reg, variable.size)], variable.size)
                args.add(arg)
            else:
                l.error('Unsupported type of variable %s.', type(variable))

        return args

    def _is_sane_register_variable(self, variable):
        """
        Filters all registers that are surly not members of function arguments.
        This can be seen as a workaround, since VariableRecoveryFast sometimes gives input variables of cc_ndep (which
        is a VEX-specific register) :-(

        :param SimRegisterVariable variable: The variable to test.
        :return:                             True if it is an acceptable function argument, False otherwise.
        :rtype:                              bool
        """

        arch = self.project.arch

        if arch.name == 'AARCH64':
            return 16 <= variable.reg < 80  # x0-x7

        elif arch.name == 'AMD64':
            return (24 <= variable.reg < 40 or  # rcx, rdx
                    64 <= variable.reg < 104 or  # rsi, rdi, r8, r9, r10
                    224 <= variable.reg < 480)  # xmm0-xmm7

        elif is_arm_arch(arch):
            return 8 <= variable.reg < 24  # r0-r3

        elif arch.name == 'MIPS32':
            return 24 <= variable.reg < 40  # a0-a3

        elif arch.name == 'PPC32':
            return 28 <= variable.reg < 60  # r3-r10

        elif arch.name == 'X86':
            return (8 <= variable.reg < 24 or  # eax, ebx, ecx, edx
                    160 <= variable.reg < 288)  # xmm0-xmm7

        else:
            l.critical('Unsupported architecture %s.', arch.name)
            return True

    @staticmethod
    def function_needs_variable_recovery(func):
        """
        Check if running variable recovery on the function is the only way to determine the calling convention of the
        this function.

        We do not need to run variable recovery to determine the calling convention of a function if:
        - The function is a SimProcedure.
        - The function is a PLT stub.
        - The function is a library function and we already know its prototype.

        :param func:    The function object.
        :return:        True if we must run VariableRecovery before we can determine what the calling convention of this
                        function is. False otherwise.
        :rtype:         bool
        """

        if func.is_simprocedure or func.is_plt:
            return False
        # TODO: Check SimLibraries
        return True

    @staticmethod
    def recover_calling_conventions(project, variable_recovery=False, kb=None):
        """
        Infer calling conventions for all functions in a project.

        :return:
        """
        if kb is None:
            kb = project.kb

        # get an ordering of functions based on the call graph
        sorted_funcs = CFGUtils.quasi_topological_sort_nodes(kb.functions.callgraph)

        for func_addr in reversed(sorted_funcs):
            func = kb.functions.get_by_addr(func_addr)
            if func.calling_convention is None:
                if func.alignment:
                    # skil all alignments
                    continue

                # if it's a normal function, we attempt to perform variable recovery
                if variable_recovery and CallingConventionAnalysis.function_needs_variable_recovery(func):
                    l.info("Performing variable recovery on %r...", func)
                    _ = project.analyses.VariableRecoveryFast(func, kb=kb)

                # determine the calling convention of each function
                cc_analysis = project.analyses.CallingConvention(func)
                if cc_analysis.cc is not None:
                    l.info("Determined calling convention for %r.", func)
                    func.calling_convention = cc_analysis.cc
                else:
                    l.info("Cannot determine calling convention for %r.", func)


register_analysis(CallingConventionAnalysis, "CallingConvention")
