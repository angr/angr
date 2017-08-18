
import logging

from ..calling_conventions import SimRegArg, SimStackArg, SimCC
from ..sim_variable import SimStackVariable, SimRegisterVariable
from . import Analysis, register_analysis

l = logging.getLogger('angr.analyses.calling_convention')


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

        cc_0 = self._analyze_function()
        callsite_ccs = self._analyze_callsites()

        cc = self._merge_cc(cc_0, *callsite_ccs)

        if cc is None:
            l.warning('Cannot determine calling convention.')

        self.cc = cc

    def _analyze_function(self):
        """
        Go over the variable information in variable manager for this function, and return all uninitialized
        register/stack variables.

        :return:
        """

        vm = self._variable_manager[self._function.addr]

        input_variables = vm.input_variables()

        input_args = self._args_from_vars(input_variables)

        # TODO: properly decide sp_delta
        sp_delta = self.project.arch.bits / 8 if self.project.arch.call_pushes_ret else 0

        cc = SimCC.find_cc(self.project.arch, input_args, sp_delta)

        if cc is None:
            l.warning('_analyze_function(): Cannot find a calling convention that fits the given arguments.')

        return cc

    def _analyze_callsites(self):
        """

        :return:
        """

        return []

    def _merge_cc(self, *cc_lst):

        # TODO: finish it

        return cc_lst[0]

    def _args_from_vars(self, variables):
        """


        :param list variables:
        :return:
        """

        args = []
        if not self.project.arch.call_pushes_ret:
            ret_addr_offset = 0
        else:
            ret_addr_offset = self.project.arch.bits / 8

        for variable in variables:
            if isinstance(variable, SimStackVariable):
                # a stack variable. convert it to a stack argument.
                # TODO: deal with the variable base
                if variable.offset == 0:
                    # skip the return address on the stack
                    # TODO: make sure it was the return address
                    continue
                arg = SimStackArg(variable.offset - ret_addr_offset, variable.size)
                args.append(arg)
            elif isinstance(variable, SimRegisterVariable):
                # a register variable, convert it to a register argument
                if not self._is_sane_register_variable(variable):
                    continue
                arg = SimRegArg(self.project.arch.register_size_names[(variable.reg, variable.size)], variable.size)
                args.append(arg)
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

        if arch.name == 'X86':
            return (variable.reg < 40  # cc_op
                    or 160 <= variable.reg < 288)

        elif arch.name == 'AMD64':
            return (variable.reg < 144  # cc_op
                    or 224 <= variable.reg <= 768)

        return True


register_analysis(CallingConventionAnalysis, "CallingConvention")
