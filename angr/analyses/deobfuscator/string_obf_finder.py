import string
from typing import List

import claripy

from angr.analyses import Analysis, AnalysesHub
from angr.errors import SimMemoryMissingError, AngrCallableMultistateError
from angr.calling_conventions import SimRegArg
from angr.analyses.reaching_definitions import ObservationPointType


class StringObfuscationFinder(Analysis):
    """
    An analysis that automatically finds string obfuscation routines.
    """

    def __init__(self):
        self.type1_candidates = []

        self.analyze()

    def analyze(self):
        self.type1_candidates = self._find_type1()

    def _find_type1(self):
        # Type 1 string obfuscation functions
        # - Take a constant string or local string as input
        # - Output strings that are reasonable
        # - Do not call other functions (i.e., these functions are leaf functions)

        cfg = self.project.kb.cfgs.get_most_accurate()
        arch = self.project.arch

        type1_candidates: List[int] = []

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
                        args = []
                        for func_arg in func.arguments:
                            assert isinstance(func_arg, SimRegArg)
                            reg_offset, reg_size = arch.registers[func_arg.reg_name]
                            try:
                                mv = observ.registers.load(reg_offset, size=reg_size)
                            except SimMemoryMissingError:
                                args.append(None)
                                continue
                            args.append(mv.one_value())

                        # the args must have at least one concrete address that points to an initialized memory location
                        acceptable_args = False
                        for arg in args:
                            if arg is not None and arg.concrete:
                                v = arg.concrete_value
                                section = self.project.loader.find_section_containing(v)
                                if section is not None:
                                    acceptable_args = True
                        if acceptable_args:
                            args_list.append(args)

            if not args_list:
                continue

            is_candidate = False
            # now that we have good arguments, let's test the function!
            for args in args_list:
                callable = self.project.factory.callable(
                    func.addr, concrete_only=True, cc=func.calling_convention, prototype=func.prototype
                )

                # before calling the function, let's record the crime scene
                values = []
                for arg in args:
                    if arg is not None and arg.concrete:
                        v = arg.concrete_value
                        section = self.project.loader.find_section_containing(v)
                        if section is not None:
                            values.append((v, self.project.loader.memory.load(v, 100)))

                try:
                    callable(*args)
                except AngrCallableMultistateError:
                    continue

                # let's see what this amazing function has done
                for addr, old_value in values:
                    out = callable.result_state.solver.eval(
                        callable.result_state.memory.load(addr, size=len(old_value)), cast_to=bytes
                    )
                    if out == old_value:
                        continue
                    if not self._is_string_reasonable(old_value) and self._is_string_reasonable(out):
                        # found it!
                        print(f"[+] Deobfuscated string by function {func:r}: {out}")
                        is_candidate = True
                        break

            if is_candidate:
                type1_candidates.append(func.addr)

        return type1_candidates

    def _like_type1_deobfuscation_function(self, code: str) -> bool:
        if "^" in code or ">>" in code or "<<" in code:
            return True
        return False

    def _is_string_reasonable(self, s: bytes) -> bool:
        # test if the string is printable and is free of nonsense characters

        # TODO: Ask a local LLM
        s = s.replace(b"\x00", b"")
        return all(chr(ch) in string.printable for ch in s)


AnalysesHub.register_default("StringObfuscationFinder", StringObfuscationFinder)
