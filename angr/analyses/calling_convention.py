# pylint:disable=no-self-use
from collections import defaultdict
from typing import Optional, Set, List, Tuple, Dict, Union, TYPE_CHECKING
import logging

import networkx

from pyvex.stmt import Put
from pyvex.expr import RdTmp
from archinfo.arch_arm import is_arm_arch, ArchARMHF

from ..calling_conventions import SimFunctionArgument, SimRegArg, SimStackArg, SimCC, DefaultCC
from ..sim_type import (
    SimTypeInt,
    SimTypeFunction,
    SimType,
    SimTypeLongLong,
    SimTypeShort,
    SimTypeChar,
    SimTypeBottom,
    SimTypeFloat,
    SimTypeDouble,
)
from ..sim_variable import SimStackVariable, SimRegisterVariable
from ..knowledge_plugins.key_definitions.atoms import Register, MemoryLocation, SpOffset
from ..knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ..knowledge_plugins.key_definitions.rd_model import ReachingDefinitionsModel
from ..knowledge_plugins.variables.variable_access import VariableAccessSort
from ..utils.constants import DEFAULT_STATEMENT
from .. import SIM_PROCEDURES
from .reaching_definitions import get_all_definitions
from .reaching_definitions.external_codeloc import ExternalCodeLocation
from . import Analysis, register_analysis, ReachingDefinitionsAnalysis
from .reaching_definitions.function_handler import FunctionHandler

if TYPE_CHECKING:
    from angr.code_location import CodeLocation
    from angr.analyses.reaching_definitions.dep_graph import DepGraph
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
    from ..knowledge_plugins.functions import Function
    from ..knowledge_plugins.cfg import CFGModel
    from ..knowledge_plugins.key_definitions.uses import Uses
    from ..knowledge_plugins.key_definitions.definition import Definition

l = logging.getLogger(name=__name__)


class CallSiteFact:
    """
    Store facts about each call site.
    """

    def __init__(self, return_value_used):
        self.return_value_used: bool = return_value_used
        self.args = []


class UpdateArgumentsOption:
    """
    Enums for controlling the argument updating behavior in _adjust_cc.
    """

    DoNotUpdate = 0
    AlwaysUpdate = 1
    UpdateWhenCCHasNoArgs = 2


class DummyFunctionHandler(FunctionHandler):
    """
    A function handler that is used during reaching definition analysis.
    """

    def handle_local_function(
        self,
        state: "ReachingDefinitionsState",
        function_address: int,
        call_stack: Optional[List],
        maximum_local_call_depth: int,
        visited_blocks: Set[int],
        dep_graph: "DepGraph",
        src_ins_addr: Optional[int] = None,
        codeloc: Optional["CodeLocation"] = None,
    ) -> Tuple[bool, "ReachingDefinitionsState", "Set[int]", "DepGraph"]:
        return False, state, visited_blocks, dep_graph


class CallingConventionAnalysis(Analysis):
    """
    Analyze the calling convention of a function and guess a probable prototype.

    The calling convention of a function can be inferred at both its call sites and the function itself. At call sites,
    we consider all register and stack variables that are not alive after the function call as parameters to this
    function. In the function itself, we consider all register and stack variables that are read but without
    initialization as parameters. Then we synthesize the information from both locations and make a reasonable
    inference of calling convention of this function.

    :ivar _function:    The function to recover calling convention for.
    :ivar _variable_manager:    A handy accessor to the variable manager.
    :ivar _cfg:         A reference of the CFGModel of the current binary. It is used to discover call sites of the
                        current function in order to perform analysis at call sites.
    :ivar analyze_callsites:    True if we should analyze all call sites of the current function to determine the
                                calling convention and arguments. This can be time-consuming if there are many call
                                sites to analyze.
    :ivar cc:           The recovered calling convention for the function.
    """

    def __init__(
        self,
        func: Optional["Function"],
        cfg: Optional["CFGModel"] = None,
        analyze_callsites: bool = False,
        caller_func_addr: Optional[int] = None,
        callsite_block_addr: Optional[int] = None,
        callsite_insn_addr: Optional[int] = None,
        func_graph: Optional = None,
    ):
        self._function = func
        self._variable_manager = self.kb.variables
        self._cfg = cfg
        self.analyze_callsites = analyze_callsites
        self.caller_func_addr = caller_func_addr
        self.callsite_block_addr = callsite_block_addr
        self.callsite_insn_addr = callsite_insn_addr
        self._func_graph = func_graph

        self.cc: Optional[SimCC] = None
        self.prototype: Optional[SimTypeFunction] = None

        if self._cfg is None and "CFGFast" in self.kb.cfgs:
            self._cfg = self.kb.cfgs["CFGFast"]

        if self._function is not None:
            # caller function analysis mode
            self._analyze()
        elif (
            self.analyze_callsites
            and self.caller_func_addr is not None
            and self.callsite_block_addr is not None
            and self.callsite_insn_addr is not None
        ):
            # callsite analysis mode
            self._analyze_callsite_only()
        else:
            raise TypeError(
                'You must specify a function to analyze, or specify "caller_func_addr",'
                ' "callsite_block_addr" and "callsite_insn_addr" to only analyze a call site.'
            )

        if self.prototype is not None:
            self.prototype = self.prototype.with_arch(self.project.arch)

    def _analyze(self):
        """
        The major analysis routine.
        """

        if self._function.is_simprocedure:
            hooker = self.project.hooked_by(self._function.addr)
            if isinstance(
                hooker,
                (
                    SIM_PROCEDURES["stubs"]["UnresolvableCallTarget"],
                    SIM_PROCEDURES["stubs"]["UnresolvableJumpTarget"],
                    SIM_PROCEDURES["stubs"]["UserHook"],
                ),
            ):
                return

            if self._function.prototype is None:
                # try our luck
                # we set ignore_binary_name to True because the binary name SimProcedures is "cle##externs" and does not
                # match any library name
                self._function.find_declaration(ignore_binary_name=True)

            self.cc = self._function.calling_convention
            self.prototype = self._function.prototype

            if self.cc is None or self.prototype is None:
                for include_callsite_preds in [False, True]:
                    callsite_facts = self._extract_and_analyze_callsites(
                        max_analyzing_callsites=1,
                        include_callsite_preds=include_callsite_preds,
                    )
                    cc = DefaultCC[self.project.arch.name](self.project.arch)
                    if self.prototype is None:
                        proto = SimTypeFunction([], None)
                    else:
                        proto = self.prototype
                    prototype = self._adjust_prototype(
                        proto,
                        callsite_facts,
                        update_arguments=UpdateArgumentsOption.AlwaysUpdate,
                    )
                    if prototype.args:
                        break
                self.cc = cc
                self.prototype = prototype
            return
        if self._function.is_plt:
            r = self._analyze_plt()
            if r is not None:
                self.cc, self.prototype = r
            return

        r = self._analyze_function()
        if r is None:
            l.warning("Cannot determine calling convention for %r.", self._function)
        else:
            # adjust prototype if needed
            cc, prototype = r
            if self.analyze_callsites:
                # only take the first 3 because running reaching definition analysis on all functions is costly
                callsite_facts = self._extract_and_analyze_callsites(max_analyzing_callsites=3)
                prototype = self._adjust_prototype(
                    prototype, callsite_facts, update_arguments=UpdateArgumentsOption.UpdateWhenCCHasNoArgs
                )

            self.cc = cc
            self.prototype = prototype

    def _analyze_callsite_only(self):
        for include_callsite_preds in [False, True]:
            callsite_facts = [
                self._analyze_callsite(
                    self.caller_func_addr,
                    self.callsite_block_addr,
                    self.callsite_insn_addr,
                    include_preds=include_callsite_preds,
                )
            ]
            cc = DefaultCC[self.project.arch.name](self.project.arch)
            prototype = SimTypeFunction([], None)
            prototype = self._adjust_prototype(
                prototype, callsite_facts, update_arguments=UpdateArgumentsOption.AlwaysUpdate
            )
            if prototype.args:
                break

        self.cc = cc
        self.prototype = prototype

    def _analyze_plt(self) -> Optional[Tuple[SimCC, SimTypeFunction]]:
        """
        Get the calling convention for a PLT stub.

        :return:    A calling convention.
        """

        if len(self._function.jumpout_sites) != 1:
            l.warning(
                "%r has more than one jumpout sites. It does not look like a PLT stub. Please report to GitHub.",
                self._function,
            )
            return None

        jo_site = self._function.jumpout_sites[0]

        successors = list(self._function.transition_graph.successors(jo_site))
        if len(successors) != 1:
            l.warning(
                "%r has more than one successors. It does not look like a PLT stub. Please report to GitHub.",
                self._function,
            )
            return None

        try:
            real_func = self.kb.functions.get_by_addr(successors[0].addr)
        except KeyError:
            # the real function does not exist for some reason
            real_func = None

        if real_func is not None:
            if real_func.is_simprocedure:
                if self.project.is_hooked(real_func.addr):
                    # prioritize the hooker
                    hooker = self.project.hooked_by(real_func.addr)
                    if hooker is not None and not hooker.is_stub:
                        return real_func.calling_convention, real_func.prototype
                if real_func.calling_convention and real_func.prototype:
                    return real_func.calling_convention, real_func.prototype
            else:
                return real_func.calling_convention, real_func.prototype

        if self.analyze_callsites:
            # determine the calling convention by analyzing its callsites
            callsite_facts = self._extract_and_analyze_callsites(max_analyzing_callsites=1)
            cc = DefaultCC[self.project.arch.name](self.project.arch)
            prototype = SimTypeFunction([], None)
            prototype = self._adjust_prototype(
                prototype, callsite_facts, update_arguments=UpdateArgumentsOption.AlwaysUpdate
            )
            return cc, prototype

        return None

    def _analyze_function(self) -> Optional[Tuple[SimCC, SimTypeFunction]]:
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
        input_args = self._args_from_vars(input_variables, vm)

        # TODO: properly determine sp_delta
        sp_delta = self.project.arch.bytes if self.project.arch.call_pushes_ret else 0

        input_args = list(input_args)  # input_args might be modified by find_cc()
        cc = SimCC.find_cc(self.project.arch, input_args, sp_delta)

        if cc is None:
            l.warning(
                "_analyze_function(): Cannot find a calling convention for %r that fits the given arguments.",
                self._function,
            )
            return None
        else:
            # reorder args
            args = self._reorder_args(input_args, cc)
            # guess the type of the return value -- it's going to be a wild guess...
            ret_type = self._guess_retval_type(cc, vm.ret_val_size)
            if self._function.name == "main" and self.project.arch.bits == 64 and isinstance(ret_type, SimTypeLongLong):
                # hack - main must return an int even in 64-bit binaries
                ret_type = SimTypeInt()
            prototype = SimTypeFunction([self._guess_arg_type(arg, cc) for arg in args], ret_type)

        return cc, prototype

    def _analyze_callsite(
        self,
        caller_addr: int,
        caller_block_addr: int,
        call_insn_addr: int,
        include_preds: bool = False,
    ) -> CallSiteFact:
        func = self.kb.functions[caller_addr]
        subgraph = self._generate_callsite_subgraph(func, caller_block_addr, include_preds=include_preds)

        rda = self.project.analyses[ReachingDefinitionsAnalysis].prep()(
            func,
            func_graph=subgraph,
            observation_points=[("insn", call_insn_addr, OP_BEFORE), ("node", caller_block_addr, OP_AFTER)],
            function_handler=DummyFunctionHandler(),
        )
        # rda_model: Optional[ReachingDefinitionsModel] = self.kb.defs.get_model(caller.addr)
        fact = self._collect_callsite_fact(caller_block_addr, call_insn_addr, rda.model)
        return fact

    def _extract_and_analyze_callsites(
        self,
        max_analyzing_callsites: int = 3,
        include_callsite_preds: bool = False,
    ) -> List[CallSiteFact]:  # pylint:disable=no-self-use
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

        facts = []
        in_edges = self._cfg.graph.in_edges(node, data=True)

        call_sites_by_function: Dict["Function", List[Tuple[int, int]]] = defaultdict(list)
        for src, _, data in in_edges:
            edge_type = data.get("jumpkind", "Ijk_Call")
            if edge_type != "Ijk_Call":
                continue
            if not self.kb.functions.contains_addr(src.function_address):
                continue
            caller = self.kb.functions[src.function_address]
            if caller.is_simprocedure:
                # do not analyze SimProcedures
                continue
            call_sites_by_function[caller].append((src.addr, src.instruction_addrs[-1]))

        call_sites_by_function_list = list(call_sites_by_function.items())[:max_analyzing_callsites]
        ctr = 0

        for caller, call_site_tuples in call_sites_by_function_list:
            if ctr >= max_analyzing_callsites:
                break

            # generate a subgraph that only contains the basic block that does the call and the basic block after the
            # call.
            for call_site_tuple in call_site_tuples:
                caller_block_addr, call_insn_addr = call_site_tuple
                fact = self._analyze_callsite(
                    caller.addr,
                    caller_block_addr,
                    call_insn_addr,
                    include_preds=include_callsite_preds,
                )
                facts.append(fact)

                ctr += 1
                if ctr >= max_analyzing_callsites:
                    break

        return facts

    def _generate_callsite_subgraph(
        self,
        func: "Function",
        callsite_block_addr: int,
        include_preds: bool = False,
    ) -> Optional[networkx.DiGraph]:
        func_graph = self._func_graph if self._func_graph is not None else func.graph

        the_block = next(iter(nn for nn in func_graph if nn.addr == callsite_block_addr), None)
        if the_block is None:
            return None

        subgraph = networkx.DiGraph()
        subgraph.add_node(the_block)

        if include_preds:
            # add a predecessor
            for src, _, data in func_graph.in_edges(the_block, data=True):
                if src is not the_block:
                    subgraph.add_edge(src, the_block, **data)
                    break  # only add the first non-cycle in-edge

        for _, dst, data in func_graph.out_edges(the_block, data=True):
            subgraph.add_edge(the_block, dst, **data)

            # If the target block contains only direct jump statements and has only one successor,
            # include its successor.

            # Re-lift the target block
            dst_bb = self.project.factory.block(dst.addr, func.get_block_size(dst.addr), opt_level=1)

            # If there is only one 'IMark' statement in vex --> the target block contains only direct jump
            if (
                len(dst_bb.vex.statements) == 1
                and dst_bb.vex.statements[0].tag == "Ist_IMark"
                and func.graph.out_degree(dst) == 1
            ):
                for _, jmp_dst, jmp_data in func_graph.out_edges(dst, data=True):
                    subgraph.add_edge(dst, jmp_dst, **jmp_data)

        return subgraph

    def _collect_callsite_fact(
        self,
        caller_block_addr: int,
        call_insn_addr: int,
        rda: ReachingDefinitionsModel,
    ) -> CallSiteFact:
        fact = CallSiteFact(
            True,  # by default we treat all return values as used
        )

        default_cc_cls = DefaultCC.get(self.project.arch.name, None)
        if default_cc_cls is not None:
            default_cc: SimCC = default_cc_cls(self.project.arch)
            self._analyze_callsite_return_value_uses(default_cc, caller_block_addr, rda, fact)
            self._analyze_callsite_arguments(default_cc, caller_block_addr, call_insn_addr, rda, fact)

        return fact

    def _analyze_callsite_return_value_uses(
        self, default_cc: SimCC, caller_block_addr: int, rda: ReachingDefinitionsModel, fact: CallSiteFact
    ) -> None:
        state = rda.observed_results[("node", caller_block_addr, OP_AFTER)]
        all_defs: Set["Definition"] = get_all_definitions(state.register_definitions)
        all_uses: "Uses" = rda.all_uses

        # determine if the return value is used
        return_val = default_cc.RETURN_VAL
        if return_val is not None and isinstance(return_val, SimRegArg):
            return_reg_offset, _ = self.project.arch.registers[return_val.reg_name]

            # find the def of the return val
            try:
                return_def = next(
                    iter(d for d in all_defs if isinstance(d.atom, Register) and d.atom.reg_offset == return_reg_offset)
                )
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

    def _analyze_callsite_arguments(
        self,
        default_cc: SimCC,
        caller_block_addr: int,
        call_insn_addr: int,
        rda: ReachingDefinitionsModel,
        fact: CallSiteFact,
    ) -> None:
        # determine if potential register and stack arguments are set
        state = rda.observed_results[("insn", call_insn_addr, OP_BEFORE)]
        defs_by_reg_offset: Dict[int, List["Definition"]] = defaultdict(list)
        all_reg_defs: Set["Definition"] = get_all_definitions(state.register_definitions)
        all_stack_defs: Set["Definition"] = get_all_definitions(state.stack_definitions)
        for d in all_reg_defs:
            if (
                isinstance(d.atom, Register)
                and not isinstance(d.codeloc, ExternalCodeLocation)
                and not (d.codeloc.block_addr == caller_block_addr and d.codeloc.stmt_idx == DEFAULT_STATEMENT)
            ):
                defs_by_reg_offset[d.offset].append(d)
        defined_reg_offsets = set(defs_by_reg_offset.keys())
        defs_by_stack_offset = {
            -d.atom.addr.offset: d
            for d in all_stack_defs
            if isinstance(d.atom, MemoryLocation) and isinstance(d.atom.addr, SpOffset)
        }

        arg_session = default_cc.arg_session(SimTypeInt().with_arch(self.project.arch))
        for _ in range(30):  # at most 30 arguments
            arg_loc = default_cc.next_arg(arg_session, SimTypeInt().with_arch(self.project.arch))
            if isinstance(arg_loc, SimRegArg):
                reg_offset = self.project.arch.registers[arg_loc.reg_name][0]
                # is it initialized?
                if reg_offset in defined_reg_offsets:
                    fact.args.append(arg_loc)
                else:
                    # no more arguments
                    break
            elif isinstance(arg_loc, SimStackArg):
                if arg_loc.stack_offset in defs_by_stack_offset:
                    fact.args.append(arg_loc)
                else:
                    # no more arguments
                    break
            else:
                break

    def _adjust_prototype(
        self,
        proto: Optional[SimTypeFunction],
        facts: List[CallSiteFact],
        update_arguments: int = UpdateArgumentsOption.DoNotUpdate,
    ) -> Optional[SimTypeFunction]:
        if proto is None:
            return None

        # is the return value used anywhere?
        if facts and all(fact.return_value_used is False for fact in facts):
            proto.returnty = None

        if update_arguments == UpdateArgumentsOption.AlwaysUpdate or (
            update_arguments == UpdateArgumentsOption.UpdateWhenCCHasNoArgs and not proto.args
        ):
            if len({len(fact.args) for fact in facts}) == 1:
                fact = next(iter(facts))
                proto.args = [self._guess_arg_type(arg) for arg in fact.args]

        return proto

    def _args_from_vars(self, variables: List, var_manager):
        """
        Derive function arguments from input variables.

        :param variables:
        :param var_manager: The variable manager of this function.
        :return:
        """

        args = set()
        if not self.project.arch.call_pushes_ret:
            ret_addr_offset = 0
        else:
            ret_addr_offset = self.project.arch.bytes

        reg_vars_with_single_access: List[SimRegisterVariable] = []

        for variable in variables:
            if isinstance(variable, SimStackVariable):
                # a stack variable. convert it to a stack argument.
                # TODO: deal with the variable base
                if self.project.arch.call_pushes_ret and variable.offset <= 0:
                    # skip the return address on the stack
                    # TODO: make sure it was the return address
                    continue
                if variable.offset - ret_addr_offset >= 0:
                    arg = SimStackArg(variable.offset - ret_addr_offset, variable.size)
                    args.add(arg)
            elif isinstance(variable, SimRegisterVariable):
                # a register variable, convert it to a register argument
                if not self._is_sane_register_variable(variable):
                    continue
                reg_name = self.project.arch.translate_register_name(variable.reg, size=variable.size)
                arg = SimRegArg(reg_name, variable.size)
                args.add(arg)

                accesses = var_manager.get_variable_accesses(variable)
                if len(accesses) == 1:
                    reg_vars_with_single_access.append(variable)
            else:
                l.error("Unsupported type of variable %s.", type(variable))

        # the function might be saving registers at the beginning and restoring them at the end
        # we should remove all registers that are strictly callee-saved and are not used anywhere in this function
        end_blocks = [(endpoint.addr, endpoint.size) for endpoint in self._function.endpoints_with_type["return"]]

        restored_reg_vars: Set[SimRegArg] = set()

        # is there any instruction that restores this register in any end blocks?
        if reg_vars_with_single_access:
            if self._function.returning is False:
                # no restoring is required if this function does not return
                for var_ in reg_vars_with_single_access:
                    reg_name = self.project.arch.translate_register_name(var_.reg, size=var_.size)
                    restored_reg_vars.add(SimRegArg(reg_name, var_.size))

            else:
                reg_offsets: Set[int] = {r.reg for r in reg_vars_with_single_access}
                for var_ in var_manager.get_variables(sort="reg"):
                    if var_.reg in (reg_offsets - {self.project.arch.ret_offset}):
                        # check if there is only a write to it
                        accesses = var_manager.get_variable_accesses(var_)
                        if len(accesses) == 1 and accesses[0].access_type == VariableAccessSort.WRITE:
                            found = False
                            for end_block_addr, end_block_size in end_blocks:
                                if end_block_addr <= accesses[0].location.ins_addr < end_block_addr + end_block_size:
                                    found = True
                                    break

                            if found:
                                reg_name = self.project.arch.translate_register_name(var_.reg, size=var_.size)
                                restored_reg_vars.add(SimRegArg(reg_name, var_.size))

        return args.difference(restored_reg_vars)

    def _is_sane_register_variable(self, variable: SimRegisterVariable) -> bool:
        """
        Filters all registers that are surly not members of function arguments.
        This can be seen as a workaround, since VariableRecoveryFast sometimes gives input variables of cc_ndep (which
        is a VEX-specific register) :-(

        :param variable: The variable to test.
        :return:         True if it is an acceptable function argument, False otherwise.
        :rtype:          bool
        """

        arch = self.project.arch

        if arch.name == "AARCH64":
            return 16 <= variable.reg < 80  # x0-x7

        elif arch.name == "AMD64":
            return 24 <= variable.reg < 40 or 64 <= variable.reg < 104  # rcx, rdx  # rsi, rdi, r8, r9, r10
            # 224 <= variable.reg < 480)  # xmm0-xmm7

        elif is_arm_arch(arch):
            if isinstance(arch, ArchARMHF):
                return 8 <= variable.reg < 24 or 128 <= variable.reg < 160  # r0 - 32  # s0 - s7, or d0 - d4
            else:
                return 8 <= variable.reg < 24  # r0-r3

        elif arch.name == "MIPS32":
            return 24 <= variable.reg < 40  # a0-a3

        elif arch.name == "MIPS64":
            return 48 <= variable.reg < 80 or 112 <= variable.reg < 208  # a0-a3 or t4-t7

        elif arch.name == "PPC32":
            return 28 <= variable.reg < 60  # r3-r10

        elif arch.name == "X86":
            return 8 <= variable.reg < 24 or 160 <= variable.reg < 288  # eax, ebx, ecx, edx  # xmm0-xmm7

        else:
            l.critical("Unsupported architecture %s.", arch.name)
            return True

    def _reorder_args(
        self, args: List[Union[SimRegArg, SimStackArg]], cc: SimCC
    ) -> List[Union[SimRegArg, SimStackArg]]:
        """
        Reorder arguments according to the calling convention identified.

        :param args:   A list of arguments that haven't been ordered.
        :param cc:    The identified calling convention.
        :return:            A reordered list of args.
        """

        reg_args = []

        # split args into two lists
        int_args = []
        fp_args = []
        for arg in args:
            if isinstance(arg, SimRegArg):
                if cc.FP_ARG_REGS and arg.reg_name in cc.FP_ARG_REGS:
                    fp_args.append(arg)
                else:
                    int_args.append(arg)

        # match int args first
        for reg_name in cc.ARG_REGS:
            try:
                arg = next(iter(a for a in int_args if isinstance(a, SimRegArg) and a.reg_name == reg_name))
            except StopIteration:
                # have we reached the end of the args list?
                if [a for a in int_args if isinstance(a, SimRegArg)]:
                    # nope
                    arg = SimRegArg(reg_name, self.project.arch.bytes)
                else:
                    break
            reg_args.append(arg)
            if arg in int_args:
                int_args.remove(arg)

        # match fp args later
        if fp_args:
            for reg_name in cc.FP_ARG_REGS:
                try:
                    arg = next(iter(a for a in fp_args if isinstance(a, SimRegArg) and a.reg_name == reg_name))
                except StopIteration:
                    # have we reached the end of the args list?
                    if [a for a in fp_args if isinstance(a, SimRegArg)]:
                        # nope
                        arg = SimRegArg(reg_name, self.project.arch.bytes)
                    else:
                        break
                reg_args.append(arg)
                if arg in fp_args:
                    fp_args.remove(arg)

        stack_args = sorted([a for a in args if isinstance(a, SimStackArg)], key=lambda a: a.stack_offset)
        return reg_args + int_args + fp_args + stack_args

    def _guess_arg_type(self, arg: SimFunctionArgument, cc: Optional[SimCC] = None) -> SimType:
        if cc is not None:
            if cc.FP_ARG_REGS and isinstance(arg, SimRegArg) and arg.reg_name in cc.FP_ARG_REGS:
                if arg.size == 4:
                    return SimTypeFloat()
                elif arg.size == 8:
                    return SimTypeDouble()

        if arg.size == 4:
            return SimTypeInt()
        elif arg.size == 8:
            return SimTypeLongLong()
        elif arg.size == 2:
            return SimTypeShort()
        elif arg.size == 1:
            return SimTypeChar()
        else:
            # Unsupported for now
            return SimTypeBottom()

    def _guess_retval_type(self, cc: SimCC, ret_val_size: Optional[int]) -> SimType:
        if cc.FP_RETURN_VAL:
            # examine the last block of the function and see which registers are assigned to
            if self._function.ret_sites:
                for ret_block in self._function.ret_sites:
                    irsb = self.project.factory.block(ret_block.addr, size=ret_block.size).vex
                    for stmt in irsb.statements:
                        if isinstance(stmt, Put):
                            if isinstance(stmt.data, RdTmp):
                                reg_size = irsb.tyenv.sizeof(stmt.data.tmp) // self.project.arch.byte_width
                                reg_name = self.project.arch.translate_register_name(stmt.offset, size=reg_size)
                                if reg_name == cc.FP_RETURN_VAL.reg_name:
                                    # possibly float
                                    return SimTypeFloat() if reg_size == 4 else SimTypeDouble()

        if ret_val_size is not None:
            if ret_val_size == 1:
                return SimTypeChar()
            elif ret_val_size == 2:
                return SimTypeShort()
            elif 3 <= ret_val_size <= 4:
                return SimTypeInt()
            elif 5 <= ret_val_size <= 8:
                return SimTypeLongLong()

        # fallback
        return SimTypeInt() if cc.arch.bits == 32 else SimTypeLongLong()


register_analysis(CallingConventionAnalysis, "CallingConvention")
