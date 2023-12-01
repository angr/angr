from typing import List, Optional, Tuple, Any, Dict, Set
import string
import logging

import claripy

from angr import sim_options
from angr.analyses import Analysis, AnalysesHub
from angr.errors import SimMemoryMissingError, AngrCallableMultistateError, AngrCallableError
from angr.calling_conventions import SimRegArg
from angr.analyses.reaching_definitions import ObservationPointType

_l = logging.getLogger(__name__)


class StringDeobFuncDescriptor:
    def __init__(self):
        self.string_input_arg_idx = None
        self.string_output_arg_idx = None
        self.string_length_arg_idx = None
        self.string_null_terminating: Optional[bool] = None


class StringObfuscationFinder(Analysis):
    """
    An analysis that automatically finds string obfuscation routines.
    """

    def __init__(self):
        self.type1_candidates = []
        self.type2_candidates = []

        self.analyze()

    def analyze(self):
        self.type1_candidates = self._find_type1()
        self.type2_candidates = self._find_type2()

        if self.type1_candidates:
            for type1_func_addr, desc in self.type1_candidates:
                type1_deobfuscated, type1_string_loader_candidates = self._analyze_type1(type1_func_addr, desc)
                self.kb.obfuscations.type1_deobfuscated_strings.update(type1_deobfuscated)
                self.kb.obfuscations.type1_string_loader_candidates |= type1_string_loader_candidates

        if self.type2_candidates:
            for type2_func_addr, desc, string_candidates in self.type2_candidates:
                type2_string_loader_candidates = self._analyze_type2(
                    type2_func_addr, desc, {addr for addr, _, _ in string_candidates}
                )
                type2_deobfuscated_strings = dict((addr, s) for addr, _, s in string_candidates)
                self.kb.obfuscations.type2_deobfuscated_strings.update(type2_deobfuscated_strings)
                self.kb.obfuscations.type2_string_loader_candidates |= type2_string_loader_candidates

    def _find_type1(self) -> List[Tuple[int, StringDeobFuncDescriptor]]:
        # Type 1 string deobfuscation functions
        # - Take a constant string or local string as input
        # - Output strings that are reasonable
        # - Do not call other functions (i.e., these functions are leaf functions)
        #
        # Type 1 string deobfuscation functions will decrypt each string once and for good.

        cfg = self.kb.cfgs.get_most_accurate()
        arch = self.project.arch

        type1_candidates: List[Tuple[int, StringDeobFuncDescriptor]] = []

        for func in self.project.kb.functions.values():
            if func.is_simprocedure or func.is_plt or func.is_alignment:
                continue

            if func.prototype is None or len(func.prototype.args) < 1:
                continue

            if self.project.kb.functions.callgraph.out_degree[func.addr] != 0:
                continue

            # find its callsites and arguments
            callers = list(
                pred for pred in self.project.kb.functions.callgraph.predecessors(func.addr) if pred != func.addr
            )

            if not callers:
                continue

            # decompile this function and see if it "looks like" a deobfuscation function
            dec = self.project.analyses.Decompiler(func, cfg=cfg)
            if dec.codegen is not None:
                if not self._like_type1_deobfuscation_function(dec.codegen.text):
                    continue

            args_list = []
            for caller in callers:
                rda = self.project.analyses.ReachingDefinitions(
                    self.project.kb.functions[caller],
                    observe_all=True,
                )
                for callsite_node in cfg.get_predecessors(cfg.get_any_node(func.addr)):
                    if callsite_node.function_address == caller:
                        observ = rda.model.get_observation_by_insn(
                            callsite_node.instruction_addrs[-1],
                            ObservationPointType.OP_BEFORE,
                        )
                        # load values for each function argument
                        args: List[Tuple[int, Any]] = []
                        for arg_idx, func_arg in enumerate(func.arguments):
                            # FIXME: We are ignoring all non-register function arguments until we see a test case where
                            # FIXME: stack-passing arguments are used
                            if isinstance(func_arg, SimRegArg):
                                reg_offset, reg_size = arch.registers[func_arg.reg_name]
                                try:
                                    mv = observ.registers.load(reg_offset, size=reg_size)
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
                callable = self.project.factory.callable(
                    func.addr, concrete_only=True, cc=func.calling_convention, prototype=func.prototype
                )

                # before calling the function, let's record the crime scene
                values: List[Tuple[int, int, bytes]] = []
                for arg_idx, arg in args:
                    if arg is not None and arg.concrete:
                        v = arg.concrete_value
                        section = self.project.loader.find_section_containing(v)
                        if section is not None:
                            values.append((arg_idx, v, self.project.loader.memory.load(v, 100)))

                try:
                    callable(*[arg for _, arg in args])
                except (AngrCallableMultistateError, AngrCallableError):
                    continue

                # let's see what this amazing function has done
                # TODO: Support cases where input and output are using different function arguments
                for arg_idx, addr, old_value in values:
                    out = callable.result_state.solver.eval(
                        callable.result_state.memory.load(addr, size=len(old_value)), cast_to=bytes
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

    def _analyze_type1(self, func_addr: int, desc: StringDeobFuncDescriptor) -> Tuple[Dict, Set]:
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
            args = []
            for func_arg in func.arguments:
                # FIXME: We are ignoring all non-register function arguments until we see a test case where
                # FIXME: stack-passing arguments are used
                if isinstance(func_arg, SimRegArg):
                    reg_offset, reg_size = arch.registers[func_arg.reg_name]
                    try:
                        mv = observ.registers.load(reg_offset, size=reg_size)
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
            callable = self.project.factory.callable(
                func.addr, concrete_only=True, cc=func.calling_convention, prototype=func.prototype
            )
            try:
                callable(*args)
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

            # dump the decrypted string!
            output_addr = args[desc.string_output_arg_idx]
            length = args[desc.string_length_arg_idx].concrete_value if desc.string_length_arg_idx is not None else 256
            output_str = callable.result_state.solver.eval(
                callable.result_state.memory.load(output_addr, size=length),
                cast_to=bytes,
            )
            if desc.string_null_terminating:
                if b"\x00" in output_str:
                    output_str = output_str[: output_str.index(b"\x00")]
            deobfuscated_strings[output_addr.concrete_value] = output_str

        # for each deobfuscated string, we find its string loader function
        # an obvious candidate function is 0x140001ae4
        xrefs = self.kb.xrefs
        string_loader_candidates = set()
        for str_addr in deobfuscated_strings:
            xref_set = xrefs.get_xrefs_by_dst(str_addr)
            block_addrs = set(xref.block_addr for xref in xref_set)
            for block_addr in block_addrs:
                node = cfg.get_any_node(block_addr)
                if node is not None:
                    callees = list(self.kb.functions.callgraph.successors(node.function_address))
                    if callees:
                        #  string loader function should not call anything else
                        continue
                    string_loader_candidates.add(node.function_address)

        return deobfuscated_strings, string_loader_candidates

    def _find_type2(self) -> List[Tuple[int, StringDeobFuncDescriptor, List[Tuple[int, int, bytes]]]]:
        # Type 2 string deobfuscation functions
        # - Deobfuscates an entire table of encrypted strings
        # - May or may not take any arguments. All arguments should be concrete.
        #
        # Type 2 string deobfuscation functions will decrypt each string once and for good.

        cfg = self.kb.cfgs.get_most_accurate()

        type2_candidates: List[Tuple[int, StringDeobFuncDescriptor, List[Tuple[int, int, bytes]]]] = []

        for func in self.project.kb.functions.values():
            if func.is_simprocedure or func.is_plt or func.is_alignment:
                continue

            if func.prototype is None or len(func.prototype.args) > 1:
                # FIXME: Handle deobfuscation functions that take arguments. Find such a case first
                continue

            if self.project.kb.functions.callgraph.out_degree[func.addr] != 0:
                continue

            # find its callsites and arguments
            callers = list(
                pred for pred in self.project.kb.functions.callgraph.predecessors(func.addr) if pred != func.addr
            )

            if not callers:
                continue

            # decompile this function and see if it "looks like" a deobfuscation function
            dec = self.project.analyses.Decompiler(func, cfg=cfg)
            if dec.codegen is not None:
                if not self._like_type2_deobfuscation_function(dec.codegen.text):
                    continue

            desc = StringDeobFuncDescriptor()
            # now that we have good arguments, let's test the function!
            callable = self.project.factory.callable(
                func.addr,
                concrete_only=True,
                cc=func.calling_convention,
                prototype=func.prototype,
                add_options={sim_options.TRACK_MEMORY_ACTIONS},
            )

            try:
                callable()
            except (AngrCallableMultistateError, AngrCallableError):
                continue

            # where are the reads and writes?
            all_global_reads = []
            all_global_writes = []
            for action in callable.result_state.history.actions:
                if not action.actual_addrs:
                    if not action.addr.ast.concrete:
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
            region_candidates: List[Tuple[int, int, bytes]] = []
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
                        end_data = callable.result_state.solver.eval(
                            callable.result_state.memory.load(starting_offset, stride), cast_to=bytes
                        )
                        if initial_data != end_data and self._is_string_reasonable(end_data):
                            region_candidates.append((starting_offset, stride, end_data))
                    idx += stride
                else:
                    idx += 1

            if region_candidates:
                type2_candidates.append((func.addr, desc, region_candidates))

        return type2_candidates

    def _analyze_type2(self, func_addr: int, desc: StringDeobFuncDescriptor, table_addrs: Set[int]) -> Set:
        """
        Analyze Type 2 string deobfuscation functions, determine the following information:

        - Functions that load deobfuscated strings

        :param func_addr:
        :param desc:
        :return:
        """

        cfg = self.kb.cfgs.get_most_accurate()

        # for each string table address, we find its string loader function
        # an obvious candidate function is 0x140001b20
        xrefs = self.kb.xrefs
        string_loader_candidates = set()
        for table_addr in table_addrs:
            xref_set = xrefs.get_xrefs_by_dst(table_addr)
            block_addrs = set(xref.block_addr for xref in xref_set)
            for block_addr in block_addrs:
                node = cfg.get_any_node(block_addr)
                if node is not None:
                    callees = list(self.kb.functions.callgraph.successors(node.function_address))
                    if callees:
                        #  string loader function should not call anything else
                        continue
                    string_loader_candidates.add(node.function_address)

        return string_loader_candidates

    @staticmethod
    def _like_type1_deobfuscation_function(code: str) -> bool:
        if "^" in code or ">>" in code or "<<" in code:
            return True
        return False

    @staticmethod
    def _like_type2_deobfuscation_function(code: str) -> bool:
        if ("^" in code or ">>" in code or "<<" in code) and ("do" in code or "while" in code or "for" in code):
            return True
        return False

    @staticmethod
    def _is_string_reasonable(s: bytes) -> bool:
        # test if the string is printable and is free of nonsense characters

        # TODO: Ask a local LLM
        s = s.replace(b"\x00", b"")
        return all(chr(ch) in string.printable for ch in s)


AnalysesHub.register_default("StringObfuscationFinder", StringObfuscationFinder)
