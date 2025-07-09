# pylint:disable=missing-class-docstring,too-many-boolean-expressions
from __future__ import annotations
from typing import Any
import string
import logging

import capstone
import networkx

import claripy

from angr.analyses import Analysis, AnalysesHub
from angr.errors import SimMemoryMissingError, AngrCallableMultistateError, AngrCallableError, AngrAnalysisError
from angr.calling_conventions import SimRegArg, default_cc
from angr.state_plugins.sim_action import SimActionData
from angr.sim_options import ZERO_FILL_UNCONSTRAINED_REGISTERS, ZERO_FILL_UNCONSTRAINED_MEMORY, TRACK_MEMORY_ACTIONS
from angr.sim_type import SimTypeFunction, SimTypeBottom, SimTypePointer
from angr.analyses.reaching_definitions import ObservationPointType
from angr.utils.graph import GraphUtils

from .irsb_reg_collector import IRSBRegisterCollector

_l = logging.getLogger(__name__)


STEP_LIMIT_FIND = 500
STEP_LIMIT_ANALYSIS = 5000


class StringDeobFuncDescriptor:
    """
    Describes a string deobfuscation function.
    """

    string_input_arg_idx: int
    string_output_arg_idx: int
    string_length_arg_idx: int | None
    string_null_terminating: bool | None

    def __init__(self):
        self.string_length_arg_idx = None
        self.string_null_terminating = None


class StringObfuscationFinder(Analysis):
    """
    An analysis that automatically finds string obfuscation routines.
    """

    def __init__(self):
        self.type1_candidates = []
        self.type2_candidates = []
        self.type3_candidates = []

        self.analyze()

    def analyze(self):
        _l.debug("Finding type 1 candidates.")
        self.type1_candidates = self._find_type1()
        _l.debug("Got %d type 1 candidates.", len(self.type1_candidates))

        _l.debug("Finding type 2 candidates.")
        self.type2_candidates = self._find_type2()
        _l.debug("Got %d type 2 candidates.", len(self.type2_candidates))

        _l.debug("Finding type 3 candidates.")
        self.type3_candidates = self._find_type3()
        _l.debug("Got %d type 3 candidates.", len(self.type3_candidates))
        _l.debug("Done.")

        if self.type1_candidates:
            for type1_func_addr, desc in self.type1_candidates:
                _l.debug("Analyzing type 1 candidates.")
                type1_deobfuscated, type1_string_loader_candidates = self._analyze_type1(type1_func_addr, desc)
                self.kb.obfuscations.type1_deobfuscated_strings.update(type1_deobfuscated)
                self.kb.obfuscations.type1_string_loader_candidates |= type1_string_loader_candidates

        if self.type2_candidates:
            for type2_func_addr, desc, string_candidates in self.type2_candidates:
                _l.debug("Analyzing type 2 candidates.")
                type2_string_loader_candidates = self._analyze_type2(
                    type2_func_addr, desc, {addr for addr, _, _ in string_candidates}
                )
                type2_deobfuscated_strings = {addr: s for addr, _, s in string_candidates}
                self.kb.obfuscations.type2_deobfuscated_strings.update(type2_deobfuscated_strings)
                self.kb.obfuscations.type2_string_loader_candidates |= type2_string_loader_candidates

        if self.type3_candidates:
            for type3_func_addr, desc in self.type3_candidates:
                _l.debug("Analyzing type 3 candidates.")
                type3_strings = self._analyze_type3(type3_func_addr, desc)
                self.kb.obfuscations.type3_deobfuscated_strings.update(type3_strings)

    def _find_type1(self) -> list[tuple[int, StringDeobFuncDescriptor]]:
        # Type 1 string deobfuscation functions
        # - Take a constant string or local string as input
        # - Output strings that are reasonable
        # - Do not call other functions (i.e., these functions are leaf functions)
        #
        # Type 1 string deobfuscation functions will decrypt each string once and for good.

        cfg = self.kb.cfgs.get_most_accurate()
        if cfg is None:
            raise AngrAnalysisError("StringObfuscationFinder needs a CFG for the analysis")

        arch = self.project.arch

        type1_candidates: list[tuple[int, StringDeobFuncDescriptor]] = []

        for func in self.project.kb.functions.values():
            if func.is_simprocedure or func.is_plt or func.is_alignment:
                continue

            if func.prototype is None or len(func.prototype.args) < 1:
                continue

            if len(func.arguments) != len(func.prototype.args):
                # function argument locations and function prototype arguments do not match
                continue

            if self.project.kb.functions.callgraph.out_degree[func.addr] != 0:
                continue

            # find its callsites and arguments
            callers = [
                pred for pred in self.project.kb.functions.callgraph.predecessors(func.addr) if pred != func.addr
            ]

            if not callers:
                continue

            if len(func.block_addrs_set) <= 2:
                # function is too small...
                continue
            if len(func.block_addrs_set) >= 50:
                # function is too big...
                continue

            # decompile this function and see if it "looks like" a deobfuscation function
            try:
                dec = self.project.analyses.Decompiler(func, cfg=cfg)
            except Exception:  # pylint:disable=broad-exception-caught
                continue
            if (
                dec.codegen is None
                or not dec.codegen.text
                or not self._like_type1_deobfuscation_function(dec.codegen.text)
            ):
                continue

            func_node = cfg.get_any_node(func.addr)
            if func_node is None:
                continue

            args_list = []
            for caller in callers:
                callsite_nodes = [
                    pred
                    for pred in cfg.get_predecessors(func_node)
                    if pred.function_address == caller and pred.instruction_addrs
                ]
                observation_points = []
                for callsite_node in callsite_nodes:
                    observation_points.append(
                        ("insn", callsite_node.instruction_addrs[-1], ObservationPointType.OP_BEFORE)
                    )
                rda = self.project.analyses.ReachingDefinitions(
                    self.project.kb.functions[caller],
                    observe_all=False,
                    observation_points=observation_points,
                )
                for callsite_node in callsite_nodes:
                    observ = rda.model.get_observation_by_insn(
                        callsite_node.instruction_addrs[-1],
                        ObservationPointType.OP_BEFORE,
                    )
                    if observ is None:
                        continue
                    # load values for each function argument
                    args: list[tuple[int, Any]] = []
                    for arg_idx, func_arg in enumerate(func.arguments):
                        # FIXME: We are ignoring all non-register function arguments until we see a test case where
                        # FIXME: stack-passing arguments are used
                        real_arg = func.prototype.args[arg_idx]
                        if isinstance(func_arg, SimRegArg):
                            reg_offset, reg_size = arch.registers[func_arg.reg_name]
                            arg_size = (
                                real_arg.size if real_arg.size is not None else reg_size
                            ) // self.project.arch.byte_width
                            try:
                                mv = observ.registers.load(reg_offset, size=arg_size)
                            except SimMemoryMissingError:
                                args.append((arg_idx, claripy.BVV(0xDEADBEEF, self.project.arch.bits)))
                                continue
                            arg_value = mv.one_value()
                            if arg_value is None:
                                arg_value = claripy.BVV(0xDEADBEEF, self.project.arch.bits)
                            args.append((arg_idx, arg_value))

                    # the args must have at least one concrete address that points to an initialized memory location
                    acceptable_args = False
                    for _, arg in args:
                        if arg is not None and arg.concrete:
                            v = arg.concrete_value
                            section = self.project.loader.find_section_containing(v)
                            if section is not None:
                                acceptable_args = True
                                break
                    if acceptable_args:
                        args_list.append(args)

            if not args_list:
                continue

            is_candidate = False
            desc = StringDeobFuncDescriptor()
            # now that we have good arguments, let's test the function!
            for args in args_list:
                func_call = self.project.factory.callable(
                    func.addr,
                    concrete_only=True,
                    cc=func.calling_convention,
                    prototype=func.prototype,
                    add_options={
                        ZERO_FILL_UNCONSTRAINED_MEMORY,
                        ZERO_FILL_UNCONSTRAINED_REGISTERS,
                    },
                    step_limit=STEP_LIMIT_FIND,
                )

                # before calling the function, let's record the crime scene
                values: list[tuple[int, int, bytes]] = []
                for arg_idx, arg in args:
                    if arg is not None and arg.concrete:
                        v = arg.concrete_value
                        section = self.project.loader.find_section_containing(v)
                        if section is not None:
                            values.append((arg_idx, v, self.project.loader.memory.load(v, 100)))

                try:
                    func_call(*[arg for _, arg in args])
                except (AngrCallableMultistateError, AngrCallableError):
                    continue

                if func_call.result_state is None:
                    continue

                # let's see what this amazing function has done
                # TODO: Support cases where input and output are using different function arguments
                for arg_idx, addr, old_value in values:
                    out = func_call.result_state.solver.eval(
                        func_call.result_state.memory.load(addr, size=len(old_value)), cast_to=bytes
                    )
                    if out == old_value:
                        continue
                    if self._is_string_reasonable(out):
                        # found it!
                        _l.debug("[+] Deobfuscated string by function %s: %s", repr(func), out)
                        is_candidate = True
                        desc.string_input_arg_idx = arg_idx
                        desc.string_output_arg_idx = arg_idx
                        desc.string_null_terminating = True  # FIXME
                        break

            if is_candidate:
                type1_candidates.append((func.addr, desc))

        return type1_candidates

    def _analyze_type1(self, func_addr: int, desc: StringDeobFuncDescriptor) -> tuple[dict, set]:
        """
        Analyze Type 1 string deobfuscation functions, determine the following information:

        - Deobfuscated strings, lengths, and their addresses
        - Functions that load deobfuscated strings

        :param func_addr:
        :param desc:
        :return:
        """

        deobfuscated_strings = {}

        arch = self.project.arch
        cfg = self.kb.cfgs.get_most_accurate()
        if cfg is None:
            raise AngrAnalysisError("StringObfuscationFinder needs a CFG for the analysis")

        func = self.kb.functions.get_by_addr(func_addr)
        func_node = cfg.get_any_node(func_addr)
        assert func_node is not None
        # Find all call sites for this function
        call_sites = cfg.get_predecessors(func_node)
        rda_cache = {}
        for callsite_node in call_sites:
            # dump arguments
            if callsite_node.function_address in rda_cache:
                rda = rda_cache[callsite_node.function_address]
            else:
                rda = self.project.analyses.ReachingDefinitions(
                    self.project.kb.functions[callsite_node.function_address],
                    observe_all=True,
                ).model
                rda_cache[callsite_node.function_address] = rda
            observ = rda.get_observation_by_insn(
                callsite_node.instruction_addrs[-1],
                ObservationPointType.OP_BEFORE,
            )
            if observ is None:
                continue
            args = []
            assert func.prototype is not None and len(func.arguments) == len(func.prototype.args)
            for func_arg, real_arg in zip(func.arguments, func.prototype.args):
                # FIXME: We are ignoring all non-register function arguments until we see a test case where
                # FIXME: stack-passing arguments are used
                if isinstance(func_arg, SimRegArg):
                    reg_offset, reg_size = arch.registers[func_arg.reg_name]
                    arg_size = (
                        real_arg.size if real_arg.size is not None else reg_size
                    ) // self.project.arch.byte_width
                    try:
                        mv = observ.registers.load(reg_offset, size=arg_size)
                    except SimMemoryMissingError:
                        args.append(claripy.BVV(0xDEADBEEF, self.project.arch.bits))
                        continue
                    v = mv.one_value()
                    if v is not None and v.concrete:
                        args.append(v)
                    else:
                        args.append(claripy.BVV(0xDEADBEEF, self.project.arch.bits))

            if None in args:
                _l.debug(
                    "At least one argument cannot be concretized. Skip the call at %#x.",
                    callsite_node.instruction_addrs[-1],
                )
                continue

            # call the function
            func_call = self.project.factory.callable(
                func.addr,
                concrete_only=True,
                cc=func.calling_convention,
                prototype=func.prototype,
                add_options={ZERO_FILL_UNCONSTRAINED_MEMORY, ZERO_FILL_UNCONSTRAINED_REGISTERS},
                step_limit=STEP_LIMIT_ANALYSIS,
            )
            try:
                func_call(*args)
            except AngrCallableMultistateError:
                _l.debug(
                    "State branching encountered during string deobfuscation. Skip the call at %#x.",
                    callsite_node.instruction_addrs[-1],
                )
                continue
            except AngrCallableError:
                _l.debug(
                    "No path returned. Skip the call at %#x.",
                    callsite_node.instruction_addrs[-1],
                )
                continue

            if func_call.result_state is None:
                continue

            # dump the decrypted string!
            output_addr = args[desc.string_output_arg_idx]
            length = args[desc.string_length_arg_idx].concrete_value if desc.string_length_arg_idx is not None else 256
            output_str = func_call.result_state.solver.eval(
                func_call.result_state.memory.load(output_addr, size=length),
                cast_to=bytes,
            )
            if desc.string_null_terminating and b"\x00" in output_str:
                output_str = output_str[: output_str.index(b"\x00")]
            deobfuscated_strings[output_addr.concrete_value] = output_str

        # for each deobfuscated string, we find its string loader function
        # an obvious candidate function is 0x140001ae4
        xrefs = self.kb.xrefs
        string_loader_candidates = set()
        for str_addr in deobfuscated_strings:
            xref_set = xrefs.get_xrefs_by_dst(str_addr)
            block_addrs = {xref.block_addr for xref in xref_set}
            for block_addr in block_addrs:
                if block_addr is None:
                    continue
                node = cfg.get_any_node(block_addr)
                if node is not None:
                    callees = list(self.kb.functions.callgraph.successors(node.function_address))
                    if callees:
                        #  string loader function should not call anything else
                        continue
                    string_loader_candidates.add(node.function_address)

        return deobfuscated_strings, string_loader_candidates

    def _find_type2(self) -> list[tuple[int, StringDeobFuncDescriptor, list[tuple[int, int, bytes]]]]:
        # Type 2 string deobfuscation functions
        # - Deobfuscates an entire table of encrypted strings
        # - May or may not take any arguments. All arguments should be concrete.
        #
        # Type 2 string deobfuscation functions will decrypt each string once and for good.

        cfg = self.kb.cfgs.get_most_accurate()
        if cfg is None:
            raise AngrAnalysisError("StringObfuscationFinder needs a CFG for the analysis")

        type2_candidates: list[tuple[int, StringDeobFuncDescriptor, list[tuple[int, int, bytes]]]] = []

        for func in self.project.kb.functions.values():
            if func.is_simprocedure or func.is_plt or func.is_alignment:
                continue

            if func.prototype is None or len(func.prototype.args) > 1:
                # FIXME: Handle deobfuscation functions that take arguments. Find such a case first
                continue

            if self.project.kb.functions.callgraph.out_degree[func.addr] != 0:
                continue

            # find its callsites and arguments
            callers = [
                pred for pred in self.project.kb.functions.callgraph.predecessors(func.addr) if pred != func.addr
            ]

            if not callers:
                continue

            if len(func.block_addrs_set) <= 2:
                # function is too small...
                continue
            if len(func.block_addrs_set) >= 50:
                # function is too big...
                continue

            # decompile this function and see if it "looks like" a deobfuscation function
            try:
                dec = self.project.analyses.Decompiler(func, cfg=cfg, expr_collapse_depth=64)
            except Exception:  # pylint:disable=broad-exception-caught
                continue
            if (
                dec.codegen is None
                or not dec.codegen.text
                or not self._like_type2_deobfuscation_function(dec.codegen.text)
            ):
                continue

            desc = StringDeobFuncDescriptor()
            # now that we have good arguments, let's test the function!
            func_call = self.project.factory.callable(
                func.addr,
                concrete_only=True,
                cc=func.calling_convention,
                prototype=func.prototype,
                add_options={TRACK_MEMORY_ACTIONS, ZERO_FILL_UNCONSTRAINED_MEMORY, ZERO_FILL_UNCONSTRAINED_REGISTERS},
                step_limit=STEP_LIMIT_FIND,
            )

            try:
                func_call()
            except (AngrCallableMultistateError, AngrCallableError):
                continue

            if func_call.result_state is None:
                continue

            # where are the reads and writes?
            all_global_reads = []
            all_global_writes = []
            for action in func_call.result_state.history.actions:
                if not isinstance(action, SimActionData):
                    continue
                if not action.actual_addrs:
                    if action.addr is None or not action.addr.ast.concrete:
                        continue
                    actual_addrs = [action.addr.ast.concrete_value]
                else:
                    actual_addrs = action.actual_addrs
                if action.type == "mem":
                    if action.action == "read":
                        for a in actual_addrs:
                            for size in range(action.size.ast // 8):
                                all_global_reads.append(a + size)
                    elif action.action == "write":
                        for a in actual_addrs:
                            for size in range(action.size.ast // 8):
                                all_global_writes.append(a + size)

            # find likely memory access regions
            all_global_reads = sorted(set(all_global_reads))
            all_global_writes = sorted(set(all_global_writes))
            all_global_write_set = set(all_global_writes)
            # TODO: Handle cases where reads and writes are not going to the same place
            region_candidates: list[tuple[int, int, bytes]] = []
            idx = 0
            while idx < len(all_global_reads):
                starting_offset = all_global_reads[idx]
                if starting_offset not in all_global_write_set:
                    idx += 1
                    continue

                stride = 0
                for j in range(idx + 1, len(all_global_reads)):
                    if (
                        all_global_reads[j] - all_global_reads[j - 1] == 1
                        and all_global_reads[j] in all_global_write_set
                    ):
                        stride += 1
                    else:
                        break
                if stride >= 5:
                    # got one region
                    section = self.project.loader.find_section_containing(starting_offset)
                    if section is not None:
                        initial_data = self.project.loader.memory.load(starting_offset, stride)
                        end_data = func_call.result_state.solver.eval(
                            func_call.result_state.memory.load(starting_offset, stride), cast_to=bytes
                        )
                        if initial_data != end_data and self._is_string_reasonable(end_data):
                            region_candidates.append((starting_offset, stride, end_data))
                    idx += stride
                else:
                    idx += 1

            if region_candidates:
                type2_candidates.append((func.addr, desc, region_candidates))

        return type2_candidates

    def _analyze_type2(
        self, func_addr: int, desc: StringDeobFuncDescriptor, table_addrs: set[int]  # pylint:disable=unused-argument
    ) -> set:
        """
        Analyze Type 2 string deobfuscation functions, determine the following information:

        - Functions that load deobfuscated strings

        :param func_addr:
        :param desc:
        :return:
        """

        cfg = self.kb.cfgs.get_most_accurate()
        if cfg is None:
            raise AngrAnalysisError("StringObfuscationFinder needs a CFG for the analysis")

        # for each string table address, we find its string loader function
        # an obvious candidate function is 0x140001b20
        xrefs = self.kb.xrefs
        string_loader_candidates = set()
        for table_addr in table_addrs:
            xref_set = xrefs.get_xrefs_by_dst(table_addr)
            block_addrs = {xref.block_addr for xref in xref_set}
            for block_addr in block_addrs:
                if block_addr is None:
                    continue
                node = cfg.get_any_node(block_addr)
                if node is not None:
                    callees = list(self.kb.functions.callgraph.successors(node.function_address))
                    if callees:
                        #  string loader function should not call anything else
                        continue
                    string_loader_candidates.add(node.function_address)

        return string_loader_candidates

    def _find_type3(self) -> list[tuple[int, StringDeobFuncDescriptor]]:
        # Type 3 string deobfuscation functions
        # - Uses a buffer in the stack frame of its parent function
        # - Before the call, the values in the buffer or the struct are initialized during runtime
        # - The entire call can be simulated (it does not involve any other functions that angr does not support or do
        #   not have a SimProcedure for)

        cfg = self.kb.cfgs.get_most_accurate()
        if cfg is None:
            raise AngrAnalysisError("StringObfuscationFinder needs a CFG for the analysis")

        functions = self.kb.functions
        callgraph_digraph = networkx.DiGraph(functions.callgraph)

        sorted_funcs = GraphUtils.quasi_topological_sort_nodes(callgraph_digraph)
        tree_has_unsupported_funcs = {}
        function_candidates = []
        for func_addr in sorted_funcs:
            if functions.get_by_addr(func_addr).is_simprocedure:
                # is this a stub SimProcedure?
                hooker = self.project.hooked_by(func_addr)
                if hooker is not None and hooker.is_stub:
                    tree_has_unsupported_funcs[func_addr] = True
            else:
                # which functions does it call?
                callees = list(callgraph_digraph.successors(func_addr))
                if any(tree_has_unsupported_funcs.get(callee, False) is True for callee in callees):
                    tree_has_unsupported_funcs[func_addr] = True
                else:
                    function_candidates.append(functions.get_by_addr(func_addr))

        type3_functions = []

        for func in function_candidates:
            if not 8 <= len(func.block_addrs_set) < 14:
                continue

            # if it has a prototype recovered, it must have four arguments
            if func.prototype is not None and len(func.prototype.args) != 4:
                continue

            # the function must call some other functions
            if callgraph_digraph.out_degree[func.addr] == 0:
                continue

            # take a look at its call sites
            func_node = cfg.get_any_node(func.addr)
            if func_node is None:
                continue
            call_sites = cfg.get_predecessors(func_node, jumpkind="Ijk_Call")
            if not call_sites:
                continue

            # examine the first 100 call sites and see if any of them sets up enough constants
            valid = False
            for i in range(min(100, len(call_sites))):
                call_site_block = self.project.factory.block(call_sites[i].addr)
                if self._is_block_setting_constants_to_stack(call_site_block):
                    valid = True
                    break
            if not valid:
                continue

            # take a look at the content
            try:
                dec = self.project.analyses.Decompiler(func, cfg=cfg)
            except Exception:  # pylint:disable=broad-exception-caught
                # catch all exceptions
                continue
            if dec.codegen is None or not dec.codegen.text:
                continue
            if not self._like_type3_deobfuscation_function(dec.codegen.text):
                continue

            # examine the first 100 call sites and see if any of them returns a valid string
            valid = False
            for i in range(min(100, len(call_sites))):
                call_site_block = self.project.factory.block(call_sites[i].addr)
                if not self._is_block_setting_constants_to_stack(call_site_block):
                    continue

                # simulate an execution to see if it really works
                data = self._type3_prepare_and_execute(
                    func.addr, call_sites[i].addr, call_sites[i].function_address, cfg
                )
                if data is None:
                    continue
                if len(data) > 3 and all(chr(x) in string.printable for x in data):
                    valid = True
                    break

            if valid:
                desc = StringDeobFuncDescriptor()
                desc.string_output_arg_idx = 0
                desc.string_length_arg_idx = 1
                desc.string_null_terminating = False
                type3_functions.append((func.addr, desc))

        return type3_functions

    def _analyze_type3(
        self, func_addr: int, desc: StringDeobFuncDescriptor  # pylint:disable=unused-argument
    ) -> dict[int, bytes]:
        """
        Analyze Type 3 string deobfuscation functions, determine the following information:

        - The call sites
        - For each call site, the actual de-obfuscated content (in bytes)

        Decompiler will output the following code:

        *ptr = strdup("The deobfuscated string");
        *(ptr+8) = the string length;

        :param func_addr:
        :param desc:
        :return:
        """

        cfg = self.kb.cfgs.get_most_accurate()
        if cfg is None:
            raise AngrAnalysisError("StringObfuscationFinder needs a CFG for the analysis")

        call_sites = cfg.get_predecessors(cfg.get_any_node(func_addr))
        callinsn2content = {}
        for idx, call_site in enumerate(call_sites):
            _l.debug("Analyzing type 3 candidate call site %#x (%d/%d)...", call_site.addr, idx + 1, len(call_sites))
            data = self._type3_prepare_and_execute(func_addr, call_site.addr, call_site.function_address, cfg)
            if data:
                callinsn2content[call_site.instruction_addrs[-1]] = data
            # print(hex(call_site.addr), data)

        return callinsn2content

    #
    # Type 1 helpers
    #

    @staticmethod
    def _like_type1_deobfuscation_function(code: str) -> bool:
        return bool("^" in code or ">>" in code or "<<" in code)

    #
    # Type 2 helpers
    #

    @staticmethod
    def _like_type2_deobfuscation_function(code: str) -> bool:
        return bool(
            ("^" in code or ">>" in code or "<<" in code) and ("do" in code or "while" in code or "for" in code)
        )

    #
    # Type 3 helpers
    #

    @staticmethod
    def _like_type3_deobfuscation_function(code: str) -> bool:
        return bool(
            ("^" in code or ">>" in code or "<<" in code or "~" in code)
            and ("do" in code or "while" in code or "for" in code)
        )

    def _type3_prepare_and_execute(self, func_addr: int, call_site_addr: int, call_site_func_addr: int, cfg):
        blocks_at_callsite = [call_site_addr]

        # backtrack from call site to include all previous consecutive blocks
        while True:
            pred_and_jumpkinds = cfg.get_predecessors_and_jumpkinds(
                cfg.get_any_node(call_site_addr), excluding_fakeret=False
            )
            if len(pred_and_jumpkinds) == 1:
                pred, jumpkind = pred_and_jumpkinds[0]
                if (
                    cfg.graph.out_degree[pred] == 1
                    and pred.addr + pred.size == call_site_addr
                    and jumpkind == "Ijk_Boring"
                ):
                    blocks_at_callsite.insert(0, pred.addr)
                    call_site_addr = pred.addr
                    continue
            break

        # take a look at the call-site block to see what registers are used
        reg_reads = set()
        for block_addr in blocks_at_callsite:
            reg_collector = IRSBRegisterCollector(self.project)
            reg_collector.process(state=None, block=self.project.factory.block(block_addr))
            reg_reads |= set(reg_collector.reg_reads)

        # run constant propagation to track constant registers
        prop = self.project.analyses.Propagator(
            func=self.kb.functions.get_by_addr(call_site_func_addr),
            only_consts=True,
            do_binops=True,
            vex_cross_insn_opt=True,
            load_callback=None,
            cache_results=True,
            key_prefix="cfg_intermediate",
        )

        # execute the block at the call site
        state = self.project.factory.blank_state(
            addr=call_site_addr,
            add_options={ZERO_FILL_UNCONSTRAINED_REGISTERS, ZERO_FILL_UNCONSTRAINED_MEMORY},
        )
        # setup sp and bp, just in case
        state.regs._sp = 0x7FFF0000
        bp_set = False
        prop_state = prop.model.input_states.get(call_site_addr, None)
        if prop_state is not None:
            for reg_offset, reg_width in reg_reads:
                if reg_offset == state.arch.sp_offset:
                    continue
                if reg_width < 8:
                    # at least a byte
                    continue
                con = prop_state.load_register(reg_offset, reg_width // 8)
                if isinstance(con, claripy.ast.Base) and con.op == "BVV":
                    state.registers.store(reg_offset, claripy.BVV(con.concrete_value, reg_width))
                    if reg_offset == state.arch.bp_offset:
                        bp_set = True
        if not bp_set:
            state.regs._bp = 0x7FFF3000
        simgr = self.project.factory.simgr(state)

        # step until the call instruction
        for idx, block_addr in enumerate(blocks_at_callsite):
            if idx == len(blocks_at_callsite) - 1:
                inst = self.project.factory.block(block_addr).instructions
                simgr.step(num_inst=inst - 1)
            else:
                simgr.step()
            if not simgr.active:
                return None

        in_state = simgr.active[0]

        cc = default_cc(self.project.arch.name, self.project.simos.name)(self.project.arch)
        cc.STACKARG_SP_BUFF = 0  # disable shadow stack space because the binary code already sets it if needed
        cc.STACK_ALIGNMENT = 1  # disable stack address aligning because the binary code already sets it if needed
        prototype_0 = SimTypeFunction([], SimTypePointer(pts_to=SimTypeBottom(label="void"))).with_arch(
            self.project.arch
        )
        callable_0 = self.project.factory.callable(
            func_addr,
            concrete_only=True,
            base_state=in_state,
            cc=cc,
            prototype=prototype_0,
            add_options={ZERO_FILL_UNCONSTRAINED_MEMORY, ZERO_FILL_UNCONSTRAINED_REGISTERS},
            step_limit=STEP_LIMIT_ANALYSIS,
        )

        try:
            ret_value = callable_0()
        except (AngrCallableMultistateError, AngrCallableError):
            return None

        out_state = callable_0.result_state

        # figure out what was written
        ptr = out_state.memory.load(ret_value, size=self.project.arch.bytes, endness=self.project.arch.memory_endness)
        size = out_state.memory.load(ret_value + 8, size=4, endness=self.project.arch.memory_endness)
        # TODO: Support lists with varied-length elements
        data = out_state.memory.load(ptr, size=size, endness="Iend_BE")
        if data.symbolic:
            return None

        return out_state.solver.eval(data, cast_to=bytes)

    @staticmethod
    def _is_block_setting_constants_to_stack(block, threshold: int = 5) -> bool:
        insn_setting_consts = 0
        for insn in block.capstone.insns:
            if (
                insn.mnemonic.startswith("mov")
                and len(insn.operands) == 2
                and insn.operands[0].type == capstone.x86.X86_OP_MEM
                and insn.operands[0].mem.base in {capstone.x86.X86_REG_RSP, capstone.x86.X86_REG_RBP}
                and insn.operands[1].type == capstone.x86.X86_OP_IMM
            ):
                insn_setting_consts += 1
        return insn_setting_consts >= threshold

    @staticmethod
    def _is_string_reasonable(s: bytes) -> bool:
        # test if the string is printable and is free of nonsense characters

        # TODO: Ask a local LLM
        s = s.replace(b"\x00", b"")
        return all(chr(ch) in string.printable for ch in s)


AnalysesHub.register_default("StringObfuscationFinder", StringObfuscationFinder)
