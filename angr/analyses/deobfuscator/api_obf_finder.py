from typing import List, Tuple, Any, Dict
from enum import IntEnum
import string

import networkx

import claripy

from angr import SIM_LIBRARIES
from angr.calling_conventions import SimRegArg
from angr.errors import SimMemoryMissingError
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType
from angr.sim_type import SimTypePointer, SimTypeChar
from angr.analyses import Analysis, AnalysesHub
from angr.procedures.definitions import SimSyscallLibrary


class APIObfuscationType(IntEnum):
    TYPE_1 = 0


class APIDeobFuncDescriptor:
    def __init__(self, type_: APIObfuscationType, func_addr=None, libname_argidx=None, funcname_argidx=None):
        self.type = type_
        self.func_addr = func_addr
        self.libname_argidx = libname_argidx
        self.funcname_argidx = funcname_argidx


class APIObfuscationFinder(Analysis):
    """
    An analysis that automatically finds API "obfuscation" routines.

    Currently, we support the following API "obfuscation" styles:

    - sub_A("dll_name", "api_name) where sub_a ends up calling LoadLibrary.
    """

    def __init__(self):
        self.type1_candidates = []

        self.analyze()

    def analyze(self):
        self.type1_candidates = self._find_type1()

        if self.type1_candidates:
            for desc in self.type1_candidates:
                type1_deobfuscated = self._analyze_type1(desc.func_addr, desc)
                self.kb.obfuscations.type1_deobfuscated_apis.update(type1_deobfuscated)

    def _find_type1(self):
        cfg = self.kb.cfgs.get_most_accurate()
        load_library_funcs = []

        if "LoadLibraryA" in self.kb.functions:
            load_library_funcs += list(self.kb.functions.get_by_name("LoadLibraryA"))
        if "LoadLibraryW" in self.kb.functions:
            load_library_funcs += list(self.kb.functions.get_by_name("LoadLibraryW"))
        if "LoadLibrary" in self.kb.functions:
            load_library_funcs += list(self.kb.functions.get_by_name("LoadLibrary"))

        load_library_funcs = [func for func in load_library_funcs if func.is_simprocedure]

        if not load_library_funcs:
            return

        # find callers of each load library func, up to three callers back
        callgraph = self.kb.functions.callgraph
        candidates = []
        for load_library_func in load_library_funcs:
            subtree = self._build_caller_subtree(callgraph, load_library_func.addr, 3)
            for _, succs in networkx.bfs_successors(subtree, load_library_func.addr):
                for succ_addr in succs:
                    func = self.kb.functions.get_by_addr(succ_addr)
                    likely, info = self._is_likely_type1_func(func, cfg)
                    if likely:
                        candidates.append((func, info))

        descs = []
        for func_addr, info in candidates:
            desc = APIDeobFuncDescriptor(
                APIObfuscationType.TYPE_1,
                func_addr=func_addr,
                libname_argidx=info["libname_arg_idx"],
                funcname_argidx=info["funcname_arg_idx"],
            )
            descs.append(desc)

        return descs

    def _is_likely_type1_func(self, func, cfg):
        if func.prototype is None:
            return False, None
        if len(func.prototype.args) < 2:
            return False, None

        arch = self.project.arch
        valid_apiname_charset = set(ord(ch) for ch in (string.ascii_letters + string.digits + "._"))

        # decompile the function to get a prototype with types
        dec = self.project.analyses.Decompiler(func, cfg=cfg)

        char_ptr_args = [
            idx
            for (idx, arg) in enumerate(func.prototype.args)
            if isinstance(arg, SimTypePointer) and isinstance(arg.pts_to, SimTypeChar)
        ]
        if len(char_ptr_args) != 2:
            return False, None

        libname_arg_idx = None
        funcname_arg_idx = None
        # who's calling it?
        caller_addrs = sorted({pred.addr for pred in cfg.get_predecessors(cfg.get_any_node(func.addr))})
        for caller_addr in caller_addrs:
            if not self.kb.functions.contains_addr(caller_addr):
                continue

            # what arguments are used to call this function with?
            callsite_nodes = [
                pred
                for pred in cfg.get_predecessors(cfg.get_any_node(func.addr))
                if pred.function_address == caller_addr and pred.instruction_addrs
            ]
            observation_points = []
            for callsite_node in callsite_nodes:
                observation_points.append(("insn", callsite_node.instruction_addrs[-1], ObservationPointType.OP_BEFORE))
            rda = self.project.analyses.ReachingDefinitions(
                self.kb.functions[caller_addr],
                observe_all=False,
                observation_points=observation_points,
            )
            for callsite_node in callsite_nodes:
                observ = rda.model.get_observation_by_insn(
                    callsite_node.instruction_addrs[-1],
                    ObservationPointType.OP_BEFORE,
                )
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
                acceptable_args = True
                arg_strs: List[Tuple[int, str]] = []
                for idx, arg in args:
                    if arg is not None and arg.concrete:
                        v = arg.concrete_value
                        section = self.project.loader.find_section_containing(v)
                        if section is not None:
                            # what string is it?
                            max_size = min(64, section.max_addr - v)
                            try:
                                value = self.project.loader.memory.load(v, max_size)
                            except KeyError:
                                acceptable_args = False
                                break
                            if b"\x00" in value:
                                value = value[: value.index(b"\x00")]
                            if not all(ch in valid_apiname_charset for ch in value):
                                acceptable_args = False
                                break
                            arg_strs.append((idx, value.decode("utf-8")))
                if acceptable_args:
                    libname_arg_idx, funcname_arg_idx = None, None
                    assert len(arg_strs) == 2
                    for arg_idx, name in arg_strs:
                        if self.is_libname(name):
                            libname_arg_idx = arg_idx
                        elif self.is_apiname(name):
                            funcname_arg_idx = arg_idx

                    if libname_arg_idx is not None and funcname_arg_idx is not None:
                        break

            if libname_arg_idx is not None and funcname_arg_idx is not None:
                break

        if libname_arg_idx is not None and funcname_arg_idx is not None:
            return True, {"libname_arg_idx": libname_arg_idx, "funcname_arg_idx": funcname_arg_idx}
        return False, None

    def _analyze_type1(self, func_addr, desc: APIDeobFuncDescriptor) -> Dict:
        raise NotImplementedError()

    @staticmethod
    def _build_caller_subtree(callgraph: networkx.DiGraph, func_addr: int, max_level: int) -> networkx.DiGraph:
        tree = networkx.DiGraph()

        if func_addr not in callgraph:
            return tree

        queue = [(0, func_addr)]
        traversed = {func_addr}
        while queue:
            level, addr = queue.pop(0)
            for pred in callgraph.predecessors(addr):
                if pred not in traversed and level + 1 <= max_level:
                    traversed.add(pred)
                    queue.append((level + 1, pred))
                    tree.add_edge(addr, pred)

        return tree

    @staticmethod
    def is_libname(name: str) -> bool:
        name = name.lower()
        if name in SIM_LIBRARIES:
            return True
        if "." not in name:
            return (name + ".dll") in SIM_LIBRARIES or (name + ".exe") in SIM_LIBRARIES
        return False

    @staticmethod
    def is_apiname(name: str) -> bool:
        for lib in SIM_LIBRARIES.values():
            if not isinstance(lib, SimSyscallLibrary) and lib.has_prototype(name):
                return True
        return False


AnalysesHub.register_default("APIObfuscationFinder", APIObfuscationFinder)
