from collections import defaultdict
from typing import Optional, Set, List, Tuple, Dict, TYPE_CHECKING
import logging

from archinfo.arch_arm import is_arm_arch

from ..calling_conventions import SimRegArg, SimStackArg, SimCC, DefaultCC
from ..sim_variable import SimStackVariable, SimRegisterVariable
from ..knowledge_plugins.key_definitions.atoms import Register
from ..knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from . import Analysis, register_analysis

if TYPE_CHECKING:
    from ..knowledge_plugins.functions import Function
    from ..knowledge_plugins.cfg import CFGModel
    from ..knowledge_plugins.key_definitions.uses import Uses
    from ..knowledge_plugins.key_definitions.definition import Definition
    from .reaching_definitions import ReachingDefinitionsAnalysis

l = logging.getLogger(name=__name__)


class CallSiteObserverControl:
    def __init__(self, func_addr: int, call_sites: List[Tuple[int,int]]):
        self.func_addr = func_addr
        self.call_site_block_addrs = set()
        self.call_site_ins_addrs = set()

        for block_addr, ins_addr in call_sites:
            self.call_site_block_addrs.add(block_addr)
            self.call_site_ins_addrs.add(ins_addr)

    def rda_observe_callback(self, ob_type, **kwargs):
        if ob_type == 'node':
            block_addr = kwargs.pop('addr', None)
            op_type = kwargs.pop('op_type', None)
            return block_addr in self.call_site_block_addrs and op_type == OP_AFTER
        elif ob_type == 'insn':
            ins_addr = kwargs.pop('addr', None)
            op_type = kwargs.pop('op_type', None)
            return ins_addr in self.call_site_ins_addrs and op_type == OP_BEFORE

        return False


class CallSiteFact:
    def __init__(self, return_value_used):
        self.return_value_used: bool = return_value_used


class CallingConventionAnalysis(Analysis):
    """
    Analyze the calling convention of functions.

    The calling convention of a function can be inferred at both its call sites and the function itself. At call sites,
    we consider all register and stack variables that are not alive after the function call as parameters to this
    function. In the function itself, we consider all register and stack variables that are read but without
    initialization as parameters. Then we synthesize the information from both locations and make a reasonable
    inference of calling convention of this function.

    :ivar _function:    The function to recover calling convention for.
    :ivar _variable_manager:    A handy accessor to the variable manager.
    :ivar _cfg:         A reference of the CFGModel of the current binary. It is used to discover call sites of the
                        current function in order to perform analysis at call sites.
    :ivar cc:           The recovered calling convention for the function.
    """

    def __init__(self, func: 'Function', cfg: Optional['CFGModel']=None):

        self._function = func
        self._variable_manager = self.kb.variables
        self._cfg = cfg

        self.cc: Optional[SimCC] = None

        self._analyze()

    def _analyze(self):
        """
        The major analysis routine.
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
        callsite_facts = self._analyze_callsites()

        cc = self._adjust_cc(cc_0, callsite_facts)

        if cc is None:
            l.warning('Cannot determine calling convention for %r.', self._function)

        self.cc = cc

    def _analyze_plt(self) -> Optional[SimCC]:
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

        try:
            real_func = self.kb.functions.get_by_addr(successors[0].addr)
        except KeyError:
            # the real function does not exist for some reason
            return None

        return real_func.calling_convention

    def _analyze_function(self) -> Optional[SimCC]:
        """
        Go over the variable information in variable manager for this function, and return all uninitialized
        register/stack variables.
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

        # TODO: properly determine sp_delta
        sp_delta = self.project.arch.bytes if self.project.arch.call_pushes_ret else 0

        cc = SimCC.find_cc(self.project.arch, list(input_args), sp_delta)

        if cc is None:
            l.warning('_analyze_function(): Cannot find a calling convention for %r that fits the given arguments.',
                      self._function)
        else:
            # reorder args
            args = self._reorder_args(input_args, cc)
            cc.args = args

        return cc

    def _analyze_callsites(self) -> List[CallSiteFact]:  # pylint:disable=no-self-use
        """
        Analyze all call sites of the function and determine the possible number of arguments and if the function
        returns anything or not.
        """

        if self._cfg is None:
            l.warning("CFG is not provided. Skip calling convention analysis at call sites.")
            return []

        node = self._cfg.get_any_node(self._function.addr)
        if node is None:
            l.warning("%r is not in the CFG. Skip calling convention analysis at call sites.", self._function)

        facts = [ ]
        call_sites = self._cfg.get_predecessors(node)

        call_sites_by_function: Dict['Function',List[Tuple[int,int]]] = defaultdict(list)
        for call_site in call_sites:
            if not self.project.kb.functions.contains_addr(call_site.function_address):
                continue
            caller = self.project.kb.functions[call_site.function_address]
            if caller.is_simprocedure:
                # do not analyze SimProcedures
                continue
            call_sites_by_function[caller].append((call_site.addr, call_site.instruction_addrs[-1]))

        call_sites_by_function = list(call_sites_by_function.items())[:5]

        rda_by_function: Dict[int,'ReachingDefinitionsAnalysis'] = {}
        for caller, call_site_tuples in call_sites_by_function:
            observer = CallSiteObserverControl(caller.addr, call_site_tuples)
            rda = self.project.analyses.ReachingDefinitions(subject=caller,
                                                            observe_callback=observer.rda_observe_callback)
            rda_by_function[caller.addr] = rda

        for caller, call_site_tuples in call_sites_by_function:
            for call_site_tuple in call_site_tuples:
                fact = self._analyze_callsite(caller.addr, call_site_tuple[0],
                                              rda_by_function[caller.addr])
                facts.append(fact)

        return facts

    def _analyze_callsite(self, caller_func_addr: int, caller_block_addr: int,
                          rda: 'ReachingDefinitionsAnalysis') -> CallSiteFact:

        fact = CallSiteFact(
            True, # by default we treat all return values as used
        )

        state = rda.observed_results[('node', caller_block_addr, 1)]
        all_uses: 'Uses' = rda.all_uses

        default_cc_cls = DefaultCC.get(self.project.arch.name, None)

        if default_cc_cls is not None:

            default_cc: SimCC = default_cc_cls(self.project.arch)
            all_defs: Set['Definition'] = state.register_definitions.get_all_variables()

            return_val = default_cc.RETURN_VAL
            if return_val is not None and isinstance(return_val, SimRegArg):
                return_reg_offset, _ = self.project.arch.registers[return_val.reg_name]

                # find the def of the return val
                try:
                    return_def = next(iter(d for d in all_defs
                                           if isinstance(d.atom, Register) and d.atom.reg_offset == return_reg_offset))
                except StopIteration:
                    return_def = None

                if return_def is not None:
                    # is it used?
                    uses = all_uses.get_uses(return_def)
                    if uses:
                        # the return value is used!
                        fact.return_value_used = True
                    else:
                        fact.return_value_used = False

            # TODO: Detect if arguments are used

        return fact

    def _adjust_cc(self, cc: SimCC, facts: List[CallSiteFact]):  # pylint:disable=no-self-use

        if cc is None:
            return cc

        # is the return value used anywhere?
        if facts and all(fact.return_value_used is False for fact in facts):
            cc.ret_val = None
        else:
            cc.ret_val = cc.RETURN_VAL

        return cc

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
                reg_name = self.project.arch.translate_register_name(variable.reg, size=variable.size)
                arg = SimRegArg(reg_name, variable.size)
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

    def _reorder_args(self, args, cc):
        """
        Reorder arguments according to the calling convention identified.

        :param set args:   A list of arguments that haven't been ordered.
        :param SimCC cc:    The identified calling convention.
        :return:            A reordered list of args.
        """

        reg_args = [ ]

        for reg_name in cc.ARG_REGS:
            try:
                arg = next(iter(a for a in args if isinstance(a, SimRegArg) and a.reg_name == reg_name))
            except StopIteration:
                # have we reached the end of the args list?
                if [ a for a in args if isinstance(a, SimRegArg) ]:
                    # nope
                    arg = SimRegArg(reg_name, self.project.arch.bytes)
                else:
                    break
            reg_args.append(arg)
            if arg in args:
                args.remove(arg)

        stack_args = sorted([a for a in args if isinstance(a, SimStackArg)], key=lambda a: a.stack_offset)
        args = [ a for a in args if not isinstance(a, SimStackArg) ]

        return reg_args + args + stack_args


register_analysis(CallingConventionAnalysis, "CallingConvention")
