# pylint:disable=no-self-use
from __future__ import annotations

import logging
from collections import defaultdict, deque
from collections.abc import Mapping
from typing import TYPE_CHECKING

import capstone
import networkx
import pypcode
from archinfo import ArchError, ArchPcode
from pyvex.expr import Get, RdTmp
from pyvex.stmt import Put, WrTmp

from angr import ailment
from angr.analyses.analysis import Analysis, register_analysis
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis, get_all_definitions
from angr.calling_conventions import (
    SimCC,
    SimCCMicrosoftThiscall,
    SimCCUsercall,
    SimFunctionArgument,
    SimRegArg,
    SimStackArg,
    default_cc,
)
from angr.code_location import ExternalCodeLocation
from angr.codenode import BlockNode
from angr.engines.pcode.lifter import IRSB as PcodeIRSB
from angr.errors import AngrError, SimTranslationError
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register, SpOffset
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.rd_model import ReachingDefinitionsModel
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag
from angr.knowledge_plugins.variables.variable_access import VariableAccessSort
from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal, VariableType
from angr.procedures import SIM_PROCEDURES
from angr.sim_type import (
    PointerDisposition,
    SimType,
    SimTypeBottom,
    SimTypeChar,
    SimTypeCppFunction,
    SimTypeDouble,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeInt,
    SimTypeInt128,
    SimTypeLongLong,
    SimTypePointer,
    SimTypeReg,
    SimTypeShort,
    parse_cpp_file,
)
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr.utils.constants import DEFAULT_STATEMENT
from angr.utils.ssa import get_reg_offset_base, get_reg_offset_base_and_size

from .fact_collector import KIND_REG, KIND_STACKVAL, FactCollector
from .utils import is_sane_register_variable

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel
    from angr.knowledge_plugins.key_definitions.definition import Definition
    from angr.knowledge_plugins.key_definitions.uses import Uses

l = logging.getLogger(name=__name__)

_PCODE_RETVAL_USE_MAX_STATES = 64
_PCODE_RETVAL_USE_MAX_OPS = 4096
_PCODE_ARG_SETUP_MAX_STATES = 128
_PCODE_ARG_SETUP_MAX_OPS = 8192
_PCODE_VALUE_INDEPENDENT_SELF_OPS = frozenset(
    {
        pypcode.OpCode.BOOL_XOR,
        pypcode.OpCode.INT_EQUAL,
        pypcode.OpCode.INT_LESSEQUAL,
        pypcode.OpCode.INT_LESS,
        pypcode.OpCode.INT_NOTEQUAL,
        pypcode.OpCode.INT_SBORROW,
        pypcode.OpCode.INT_SLESSEQUAL,
        pypcode.OpCode.INT_SLESS,
        pypcode.OpCode.INT_SUB,
        pypcode.OpCode.INT_XOR,
    }
)


class CallSiteFact:
    """
    Store facts about each call site.
    """

    def __init__(self, return_value_used):
        self.return_value_used: bool = return_value_used
        self.return_value_forwarded: bool = False
        self.args = []


class UpdateArgumentsOption:
    """
    Enums for controlling the argument updating behavior in _adjust_cc.
    """

    DoNotUpdate = 0
    AlwaysUpdate = 1
    UpdateWhenCCHasNoArgs = 2


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
    :ivar _collect_facts:       True if we should run FunctionFactCollector to collect input arguments and return
                                value size. False if input arguments and return value size are provided by the user.
    """

    def __init__(
        self,
        func: Function | int | str | None,
        cfg: CFGModel | None = None,
        analyze_callsites: bool = False,
        caller_func_addr: int | None = None,
        callsite_block_addr: int | None = None,
        callsite_insn_addr: int | None = None,
        func_graph: networkx.DiGraph | None = None,
        input_args: list[SimRegArg | SimStackArg] | None = None,
        retval_size: int | None = None,
        extra_pop: int | None = None,
        collect_facts: bool = False,
        collect_facts_arg_uses: bool = False,
        collect_facts_arg_passthru: bool = False,
    ):
        if func is not None and not isinstance(func, Function):
            func = self.kb.functions[func]
        self._function = func
        self._variable_manager = self.kb.variables
        self._cfg = cfg
        self.analyze_callsites = analyze_callsites
        self.caller_func_addr = caller_func_addr
        self.callsite_block_addr = callsite_block_addr
        self.callsite_insn_addr = callsite_insn_addr
        self._func_graph = func_graph
        self._input_args = input_args
        self._unused_args: list[SimRegArg] = []
        self._retval_size = retval_size
        self._retval_size_indeterminate = False
        self._extra_pop: int | None = extra_pop
        self._return_address_size: int | None = None
        self._return_address_size_ambiguous = False
        self._collect_facts = collect_facts
        self._collect_facts_arg_uses = collect_facts_arg_uses
        self._collect_facts_arg_passthru = collect_facts_arg_passthru
        self._callsites = {}
        self._pointer_arg_derefs = {}

        if self._retval_size is not None and self._input_args is None:
            # retval size will be ignored if input_args is not specified - user error?
            raise TypeError(
                "input_args must be provided to use retval_size. Otherwise please set both input_args and "
                "retval_size to None."
            )

        self.cc: SimCC | None = None
        self.prototype: SimTypeFunction | None = None
        self.prototype_libname: str | None = None
        self.proto_from_symbol: bool = False

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

        assert self._function is not None

        cpp_symbol_result: tuple[SimCC, SimTypeCppFunction, str | None] | None = None
        demangled_name = self._function.demangled_name
        if demangled_name != self._function.name:
            r_demangled = self._analyze_demangled_name(demangled_name)
            if r_demangled is not None:
                # Itanium names usually omit the return type, and a qualified name does
                # not distinguish a namespace/static function from a non-static member.
                # parse_cpp_file() consequently carries a possible-this placeholder.
                # Do not let that incomplete declaration bypass callee/callsite analysis;
                # refine it with machine facts below. Declarations that encode an explicit
                # calling convention (such as Microsoft C++ symbols) remain authoritative.
                demangled_cc, demangled_proto, demangled_libname = r_demangled
                if isinstance(demangled_proto, SimTypeCppFunction) and demangled_proto.convention is None:
                    cpp_symbol_result = demangled_cc, demangled_proto, demangled_libname
                else:
                    self.cc, self.prototype, self.prototype_libname = r_demangled
                    self.proto_from_symbol = True
                    return

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

            if (
                hooker is not None
                and hooker.cc is not None
                and hooker.is_function
                and not hooker.guessed_prototype
                and hooker.prototype is not None
            ):
                # copy the calling convention and prototype from the SimProcedure instance
                self.cc = hooker.cc
                self.prototype = hooker.prototype
                self.prototype_libname = hooker.library_name
                self.proto_from_symbol = True
                return

            if self._function.prototype is None:
                # try our luck
                # we set ignore_binary_name to True because the binary name SimProcedures is "cle##externs" and does not
                # match any library name
                self._function.find_declaration(ignore_binary_name=True)

            self.cc = self._function.calling_convention
            self.prototype = self._function.prototype
            self.prototype_libname = self._function.prototype_libname

            if self.cc is None or self.prototype is None:
                for include_callsite_preds in [False, True]:
                    callsite_facts = self._extract_and_analyze_callsites(
                        max_analyzing_callsites=1,
                        include_callsite_preds=include_callsite_preds,
                    )
                    cc_cls = default_cc(
                        self.project.arch.name,
                        platform=(
                            self.project.simos.name
                            if self.project is not None and self.project.simos is not None
                            else None
                        ),
                    )
                    cc = cc_cls(self.project.arch) if cc_cls is not None else None
                    prototype = None
                    if callsite_facts:
                        if self.prototype is None:
                            proto = SimTypeFunction([], SimTypeBottom(label="void"))
                        else:
                            proto = self.prototype
                        prototype = self._adjust_prototype(
                            proto,
                            callsite_facts,
                            update_arguments=UpdateArgumentsOption.AlwaysUpdate,
                        )
                        if prototype.args:
                            break
                self.cc = cc  # type: ignore
                self.prototype = prototype  # type: ignore
            return
        if self._function.is_plt:
            r_plt = self._analyze_plt()
            if r_plt is not None:
                self.cc, self.prototype, self.prototype_libname, proto_guessed = r_plt
                self.proto_from_symbol = not proto_guessed
            return

        # we gotta analyze the function properly
        if self._collect_facts and self._input_args is None and self._retval_size is None:
            facts = self.project.analyses[FactCollector].prep(kb=self.kb)(
                self._function,
                track_arg_uses=self._collect_facts_arg_uses,
                track_arg_passthru=self._collect_facts_arg_passthru,
            )
            self._input_args = facts.input_args
            self._retval_size = facts.retval_size
            self._retval_size_indeterminate = facts.retval_size_indeterminate
            self._callsites = facts.callsites
            self._pointer_arg_derefs = facts.pointer_arg_derefs
            self._unused_args = facts.unused_args
            self._extra_pop = facts.extra_pop
            self._return_address_size = facts.return_address_size
            self._return_address_size_ambiguous = facts.return_address_size_ambiguous

        r = self._analyze_function()
        if r is None:
            l.warning("Cannot determine calling convention for %r.", self._function)
            if cpp_symbol_result is not None:
                self.cc, self.prototype, self.prototype_libname = cpp_symbol_result
                self.proto_from_symbol = True
        else:
            # adjust prototype if needed
            cc, prototype = r
            if self.analyze_callsites:
                # only take the first 3 because running reaching definition analysis on all functions is costly
                callsite_facts = self._extract_and_analyze_callsites(max_analyzing_callsites=3)
                prototype = (
                    self._adjust_prototype(
                        prototype, callsite_facts, update_arguments=UpdateArgumentsOption.UpdateWhenCCHasNoArgs
                    )
                    if prototype is not None
                    else None
                )

            if cpp_symbol_result is not None and prototype is not None:
                prototype = self._refine_cpp_symbol_prototype(prototype, cpp_symbol_result[1])
            self.cc = cc
            self.prototype = prototype

    @staticmethod
    def _refine_cpp_symbol_prototype(
        machine_proto: SimTypeFunction, symbol_proto: SimTypeCppFunction
    ) -> SimTypeFunction:
        """Merge encoded C++ types only where machine ABI arity disambiguates them.

        The parser's first pointer is a *possible* ``this``.  If machine facts recover
        one fewer arguments, the qualified name was a namespace/static function and the
        placeholder is removed.  If arity agrees it is retained.  Any other disagreement
        keeps the machine-derived arguments.  A non-Bottom encoded template return may
        refine the return type; ordinary Itanium names keep the machine-derived return.
        """
        machine_args = tuple(machine_proto.args or ())
        symbol_args = tuple(symbol_proto.args or ())
        if len(symbol_args) == len(machine_args):
            selected = symbol_args
        elif len(symbol_args) == len(machine_args) + 1 and symbol_args and isinstance(symbol_args[0], SimTypePointer):
            selected = symbol_args[1:]
        else:
            selected = machine_args
        # Opaque C++ classes cannot be laid out by a calling convention.  Preserve the
        # machine-derived slot for those arguments; only scalar/reference or pointer
        # types from the linkage name are safe refinements.
        args = tuple(
            sym if isinstance(sym, (SimTypeReg, SimTypePointer)) else machine
            for machine, sym in zip(machine_args, selected)
        )
        symbol_ret = symbol_proto.returnty
        ret = (
            symbol_ret
            if symbol_ret is not None
            and not isinstance(symbol_ret, SimTypeBottom)
            and isinstance(symbol_ret, (SimTypeReg, SimTypePointer))
            else machine_proto.returnty
        )
        return SimTypeFunction(args, ret, variadic=machine_proto.variadic)

    def _analyze_callsite_only(self):
        assert self.caller_func_addr is not None
        assert self.callsite_block_addr is not None
        assert self.callsite_insn_addr is not None
        cc, prototype = None, None

        for include_callsite_preds in [False, True]:
            fact = self._analyze_callsite(
                self.caller_func_addr,
                self.callsite_block_addr,
                self.callsite_insn_addr,
                include_preds=include_callsite_preds,
            )
            if fact is None:
                continue
            callsite_facts = [fact]
            cc_cls = default_cc(
                self.project.arch.name,
                platform=(
                    self.project.simos.name if self.project is not None and self.project.simos is not None else None
                ),
            )
            cc = cc_cls(self.project.arch) if cc_cls is not None else None
            prototype = SimTypeFunction([], None)
            prototype = self._adjust_prototype(
                prototype, callsite_facts, update_arguments=UpdateArgumentsOption.AlwaysUpdate
            )
            if prototype.args:
                break

        self.cc = cc
        self.prototype = prototype

    def _analyze_plt(self) -> tuple[SimCC, SimTypeFunction | None, str | None, bool | None] | None:
        """
        Get the calling convention for a PLT stub.

        :return:    A calling convention, the function type, as well as the library name if available.
        """
        assert self._function is not None

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
            if real_func.calling_convention is None:
                cc_cls = default_cc(self.project.arch.name)
                if cc_cls is None:
                    # can't determine the default calling convention for this architecture
                    return None
                cc = cc_cls(self.project.arch)
            else:
                cc = real_func.calling_convention
            if real_func.is_simprocedure:
                if self.project.is_hooked(real_func.addr):
                    # prioritize the hooker
                    hooker = self.project.hooked_by(real_func.addr)
                    if hooker is not None and hooker.is_function and not hooker.guessed_prototype:
                        # we only take the prototype from the SimProcedure if
                        # - the SimProcedure is a function
                        # - the prototype of the SimProcedure is not guessed
                        return cc, hooker.prototype, hooker.library_name, False
                if real_func.prototype is not None:
                    return cc, real_func.prototype, real_func.prototype_libname, real_func.is_prototype_guessed
            else:
                return cc, real_func.prototype, real_func.prototype_libname, real_func.is_prototype_guessed

        if self.analyze_callsites:
            # determine the calling convention by analyzing its callsites
            callsite_facts = self._extract_and_analyze_callsites(max_analyzing_callsites=1)
            cc_cls = default_cc(self.project.arch.name)
            if cc_cls is None:
                # can't determine the default calling convention for this architecture
                return None
            cc = cc_cls(self.project.arch)
            prototype = SimTypeFunction([], None)
            prototype = self._adjust_prototype(
                prototype, callsite_facts, update_arguments=UpdateArgumentsOption.AlwaysUpdate
            )
            return cc, prototype, None, True

        return None

    def _analyze_demangled_name(self, name: str) -> tuple[SimCC, SimTypeFunction, str | None] | None:
        """
        Analyze a function with a demangled name. Only C++ names are supported for now.

        :param name:    The demangled name of the function.
        :return:        A tuple of the calling convention, the function type, and the library name if available.
        """
        parsed, _ = parse_cpp_file(name)
        if not parsed or len(parsed) != 1:
            return None
        proto = next(iter(parsed.values()))
        if (
            isinstance(proto, SimTypeCppFunction)
            and self.project.simos.name == "Win32"
            and self.project.arch.name == "X86"
            and proto.convention == "__thiscall"
        ):
            cc_cls = SimCCMicrosoftThiscall
        else:
            cc_cls = default_cc(self.project.arch.name, self.project.simos.name)
            assert cc_cls is not None
        cc = cc_cls(self.project.arch)
        return cc, proto, None

    def _analyze_function(self) -> tuple[SimCC, SimTypeFunction] | None:
        """
        Go over the variable information in variable manager for this function, and return all uninitialized
        register/stack variables.
        """
        assert self._function is not None

        if self._function.is_simprocedure or self._function.is_plt:
            # we do not analyze SimProcedures or PLT stubs
            return None

        if self._input_args is None:
            if not self._variable_manager.has_function_manager(self._function.addr):
                l.warning("Please run variable recovery on %r before analyzing its calling convention.", self._function)
                return None
            vm = self._variable_manager[self._function.addr]
            retval_size = vm.ret_val_size
            input_variables = vm.input_variables()
            input_args = self._args_from_vars(input_variables, vm)
            ordered_input_args = sorted(input_args, key=self._argument_location_sort_key)
        else:
            ordered_input_args = list(self._input_args)
            input_args = set(self._input_args)
            retval_size = self._retval_size

        # check if this function is a variadic function
        if self.project.arch.name == "AMD64":
            is_variadic, fixed_args = self.is_va_start_amd64(self._function)
        else:
            is_variadic = False
            fixed_args = None

        if self._return_address_size_ambiguous:
            l.warning(
                "_analyze_function(): Function %r mixes return-address widths.",
                self._function,
            )
            return None
        sp_delta = (
            self._return_address_size
            if self._return_address_size is not None
            else self.project.arch.bytes
            if self.project.arch.call_pushes_ret
            else 0
        )

        full_input_args = self._consolidate_input_args(input_args)
        fallback_input_args = set(full_input_args)
        full_input_args_copy = list(full_input_args)  # input_args might be modified by find_cc()
        cc = SimCC.find_cc(
            self.project.arch,
            full_input_args_copy,
            sp_delta,
            platform=self.project.simos.name,
            unused_hint=self._unused_args,
            extra_pop=self._extra_pop,
        )

        # update input_args according to the difference between full_input_args and full_input_args_copy
        for a in full_input_args:
            if a not in full_input_args_copy and a in input_args:
                input_args.remove(a)

        if cc is None:
            cc = self._infer_pcode_win16_usercall(
                ordered_input_args,
                fallback_input_args,
                retval_size,
            )
            if cc is None:
                l.warning(
                    "_analyze_function(): Cannot find a calling convention for %r that fits the given arguments.",
                    self._function,
                )
                return None
        # reorder args
        args = list(cc.args) if isinstance(cc, SimCCUsercall) else self._reorder_args(input_args, cc)
        if fixed_args is not None:
            args = args[:fixed_args]

        # generate an index for arg uses
        arg_uses: defaultdict[tuple[int, int], list[tuple[Function | None, int]]] = defaultdict(list)
        for target, cargs in self._callsites.values():
            for idx, carg in enumerate(cargs):
                if carg is not None and carg[0] in (KIND_STACKVAL, KIND_REG) and carg[2] == 0:
                    arg_uses[(carg[0], carg[1])].append((target, idx))
        for carg, use in self._pointer_arg_derefs.items():
            if carg is not None and carg[0] in (KIND_STACKVAL, KIND_REG):
                arg_uses[(carg[0], carg[1])].append((None, use))

        # guess the type of the return value -- it's going to be a wild guess...
        ret_type = (
            None
            if retval_size is None and self._retval_size_indeterminate
            else self._guess_retval_type(cc, retval_size)
        )
        if self._function.name == "main" and self.project.arch.bits == 64 and isinstance(ret_type, SimTypeLongLong):
            # hack - main must return an int even in 64-bit binaries
            ret_type = SimTypeInt()
        prototype = SimTypeFunction(
            [self._guess_arg_type(arg, cc, arg_uses) for arg in args], ret_type, variadic=is_variadic
        )

        return cc, prototype

    def _argument_location_sort_key(self, arg: SimFunctionArgument) -> tuple[int, int, int]:
        if isinstance(arg, SimRegArg):
            return 0, arg.check_offset(self.project.arch), arg.size
        if isinstance(arg, SimStackArg):
            return 1, arg.stack_offset, arg.size
        return 2, 0, arg.size

    @staticmethod
    def _pcode_varnode_byte_keys(varnode) -> set[tuple[str, int]]:
        space_name = varnode.space.name
        if space_name not in {"register", "unique"}:
            return set()
        offset = int(varnode.offset)
        return {(space_name, offset + index) for index in range(int(varnode.size))}

    @classmethod
    def _reverse_pcode_register_dependencies(
        cls,
        dependencies: frozenset[tuple[str, int]],
        operations,
        abi_return_bytes: frozenset[tuple[str, int]],
        caller_saved_bytes: frozenset[tuple[str, int]],
    ) -> frozenset[tuple[str, int]] | None:
        """Trace one register value backwards through a p-code block.

        ``None`` means an opaque call could have clobbered a still-live ABI
        register.  Direct calls define the platform's scalar and overflow return
        locations; other caller-saved locations deliberately remain unknown.
        """

        current = set(dependencies)
        for op in reversed(operations):
            if op.opcode in {pypcode.OpCode.CALL, pypcode.OpCode.CALLIND}:
                is_direct = op.opcode == pypcode.OpCode.CALL and bool(op.inputs) and op.inputs[0].space.name == "ram"
                if is_direct:
                    current.difference_update(abi_return_bytes)
                if not current.isdisjoint(caller_saved_bytes):
                    return None
                continue

            if op.output is None:
                continue
            output_bytes = cls._pcode_varnode_byte_keys(op.output)
            overlap = current.intersection(output_bytes)
            if not overlap:
                continue
            current.difference_update(overlap)

            # A load is itself an explicit definition of the destination. Its
            # address influences the selected value, but does not make that
            # destination an uninitialized register input.
            if op.opcode == pypcode.OpCode.LOAD:
                continue

            same_inputs = (
                len(op.inputs) == 2
                and op.inputs[0].space.name == op.inputs[1].space.name
                and int(op.inputs[0].offset) == int(op.inputs[1].offset)
                and int(op.inputs[0].size) == int(op.inputs[1].size)
            )
            if same_inputs and op.opcode in _PCODE_VALUE_INDEPENDENT_SELF_OPS:
                continue

            # Over-approximating every output byte as depending on every input
            # byte can reject a valid helper, but cannot invent one.
            for varnode in op.inputs:
                current.update(cls._pcode_varnode_byte_keys(varnode))

        return frozenset(current)

    def _pcode_register_setup_is_proven(
        self,
        caller: Function,
        transfer_node: BlockNode,
        transfer_insn_addr: int,
        arg: SimRegArg,
        abi_return_bytes: frozenset[tuple[str, int]],
        caller_saved_bytes: frozenset[tuple[str, int]],
    ) -> bool:
        """Prove that every path to one transfer defines ``arg`` first."""

        arg_offset = arg.check_offset(self.project.arch)
        entry_bytes = frozenset(("register", arg_offset + index) for index in range(arg.size))
        worklist = deque([(transfer_node, entry_bytes, True)])
        traversed: set[tuple[BlockNode, frozenset[tuple[str, int]], bool]] = set()
        total_ops = 0

        while worklist:
            node, dependencies, is_transfer_block = worklist.popleft()
            state_key = node, dependencies, is_transfer_block
            if state_key in traversed:
                continue
            if len(traversed) >= _PCODE_ARG_SETUP_MAX_STATES:
                return False
            traversed.add(state_key)

            if not isinstance(node, BlockNode) or node.size is None or node.size <= 0:
                return False
            block_size = transfer_insn_addr - node.addr if is_transfer_block else node.size
            if block_size < 0:
                return False
            if block_size:
                try:
                    irsb = self.project.factory.block(node.addr, size=block_size).vex
                except AngrError:
                    return False
                if not isinstance(irsb, PcodeIRSB) or irsb.jumpkind == "Ijk_NoDecode":
                    return False
                total_ops += len(irsb._ops)
                if total_ops > _PCODE_ARG_SETUP_MAX_OPS:
                    return False
                traced = self._reverse_pcode_register_dependencies(
                    dependencies,
                    irsb._ops,
                    abi_return_bytes,
                    caller_saved_bytes,
                )
                if traced is None:
                    return False
                dependencies = traced

            # Unique-space temporaries may not cross a block boundary. An
            # unresolved one means lifting/data flow was incomplete.
            if any(space_name == "unique" for space_name, _ in dependencies):
                return False
            if dependencies.isdisjoint(entry_bytes):
                continue

            predecessors = [
                predecessor
                for predecessor in caller.graph.predecessors(node)
                if isinstance(predecessor, BlockNode) and predecessor.size is not None and predecessor.size > 0
            ]
            if not predecessors:
                return False
            worklist.extend((predecessor, dependencies, False) for predecessor in predecessors)

        return True

    def _is_direct_near_pcode_transfer(
        self,
        source: BlockNode,
        transfer_insn_addr: int,
        target_addr: int,
        edge_type: str,
    ) -> bool:
        if source.size is None or source.size <= 0:
            return False
        try:
            block = self.project.factory.block(source.addr, size=source.size)
            irsb = block.vex
        except AngrError:
            return False
        if not isinstance(irsb, PcodeIRSB):
            return False

        expected_mnemonic = "CALL" if edge_type == "call" else "JMP"
        instruction = next(
            (insn for insn in block.disassembly.insns if insn.address == transfer_insn_addr),
            None,
        )
        if instruction is None or instruction.mnemonic.upper() != expected_mnemonic:
            # In particular, reject CALLF/JMPF and every indirect spelling.
            return False

        expected_opcode = pypcode.OpCode.CALL if edge_type == "call" else pypcode.OpCode.BRANCH
        in_transfer_instruction = False
        for op in irsb._ops:
            if op.opcode == pypcode.OpCode.IMARK:
                in_transfer_instruction = bool(op.inputs) and int(op.inputs[0].offset) == transfer_insn_addr
                continue
            if not in_transfer_instruction or op.opcode not in {
                pypcode.OpCode.BRANCH,
                pypcode.OpCode.BRANCHIND,
                pypcode.OpCode.CALL,
                pypcode.OpCode.CALLIND,
            }:
                continue
            return (
                op.opcode == expected_opcode
                and bool(op.inputs)
                and op.inputs[0].space.name == "ram"
                and int(op.inputs[0].offset) == target_addr
            )
        return False

    def _pcode_win16_incoming_transfers(self) -> list[tuple[Function, BlockNode, int]] | None:
        """Collect every exact direct near transfer recorded by the function graph.

        A callgraph predecessor without an exact entry transfer commonly denotes
        an overlapping/shared-tail function.  That is not enough evidence for a
        custom register ABI, so the entire inference fails closed.
        """

        assert self._function is not None
        try:
            caller_addrs = list(self.kb.functions.callgraph.predecessors(self._function.addr))
        except networkx.NetworkXError:
            return None
        if not caller_addrs:
            return None

        transfers: list[tuple[Function, BlockNode, int]] = []
        seen: set[tuple[int, int, int]] = set()
        for caller_addr in caller_addrs:
            if not self.kb.functions.contains_addr(caller_addr):
                return None
            caller = self.kb.functions[caller_addr]
            caller_transfers: list[tuple[Function, BlockNode, int]] = []
            for source, destination, data in caller.transition_graph.edges(data=True):
                if destination.addr != self._function.addr or not isinstance(source, BlockNode):
                    continue
                edge_type = data.get("type")
                if edge_type == "transition":
                    if not data.get("outside", False):
                        continue
                elif edge_type != "call":
                    continue
                transfer_insn_addr = data.get("ins_addr")
                if not isinstance(transfer_insn_addr, int) or not self._is_direct_near_pcode_transfer(
                    source,
                    transfer_insn_addr,
                    self._function.addr,
                    edge_type,
                ):
                    return None
                key = caller.addr, source.addr, transfer_insn_addr
                if key not in seen:
                    seen.add(key)
                    caller_transfers.append((caller, source, transfer_insn_addr))
            if not caller_transfers:
                return None
            transfers.extend(caller_transfers)
        return transfers or None

    def _infer_pcode_win16_usercall(
        self,
        ordered_input_args: list[SimRegArg | SimStackArg],
        input_args: set[SimRegArg | SimStackArg],
        retval_size: int | None,
    ) -> SimCCUsercall | None:
        """Infer an exact Win16 usercall only from closed machine-code evidence.

        Standard registered conventions remain authoritative. This fallback is
        considered only when they reject real register inputs, and only when all
        CFG-recorded incoming transfers are direct near CALL/JMP instructions
        whose callers definitely establish every register location.
        """

        if (
            not isinstance(self.project.arch, ArchPcode)
            or self.project.arch.name != "x86:LE:16:Protected Mode"
            or self.project.simos.name != "Win16"
            or self._function is None
        ):
            return None

        register_args = [arg for arg in input_args if isinstance(arg, SimRegArg)]
        if not register_args:
            return None
        if self._return_address_size not in {None, 2}:
            return None
        if self._extra_pop not in {None, 0} and not (
            self._return_address_size is None and self._extra_pop == -self.project.arch.bytes
        ):
            return None
        if retval_size is not None and not 1 <= retval_size <= 4:
            return None

        transfers = self._pcode_win16_incoming_transfers()
        if transfers is None:
            return None

        default_cc_cls = default_cc(self.project.arch.name, platform=self.project.simos.name)
        if default_cc_cls is None:
            return None
        platform_cc = default_cc_cls(self.project.arch)

        def register_bytes(location: SimFunctionArgument | None) -> set[tuple[str, int]]:
            result: set[tuple[str, int]] = set()
            if location is None:
                return result
            for part in location.get_footprint():
                if isinstance(part, SimRegArg):
                    offset = part.check_offset(self.project.arch)
                    result.update(("register", offset + index) for index in range(part.size))
            return result

        abi_return_bytes = frozenset(
            register_bytes(platform_cc.RETURN_VAL) | register_bytes(platform_cc.OVERFLOW_RETURN_VAL)
        )
        caller_saved_bytes: set[tuple[str, int]] = set()
        for reg_name in platform_cc.CALLER_SAVED_REGS:
            try:
                offset, size = self.project.arch.registers[reg_name]
            except KeyError:
                return None
            caller_saved_bytes.update(("register", offset + index) for index in range(size))
        frozen_caller_saved_bytes = frozenset(caller_saved_bytes)

        for caller, transfer_node, transfer_insn_addr in transfers:
            for arg in register_args:
                if not self._pcode_register_setup_is_proven(
                    caller,
                    transfer_node,
                    transfer_insn_addr,
                    arg,
                    abi_return_bytes,
                    frozen_caller_saved_bytes,
                ):
                    return None

        ordered_args: list[SimRegArg | SimStackArg] = []
        for arg in ordered_input_args:
            if arg in input_args and arg not in ordered_args:
                ordered_args.append(arg)
        ordered_args.extend(
            sorted(
                (arg for arg in input_args if arg not in ordered_args),
                key=self._argument_location_sort_key,
            )
        )

        if retval_size is None:
            return_location = None
        else:
            return_type: SimType
            if retval_size == 1:
                return_type = SimTypeChar()
            elif retval_size == 2:
                return_type = SimTypeShort()
            else:
                return_type = SimTypeInt()
            return_location = platform_cc.return_val(return_type.with_arch(self.project.arch))

        cc = SimCCUsercall(self.project.arch, ordered_args, return_location)
        # SimCCUsercall describes the exact locations; copy the surrounding near
        # ABI contract so stack accounting, return analysis, and call rewriting
        # keep the same machine semantics as ordinary Win16 near calls.
        for attribute in (
            "STACKARG_SP_DIFF",
            "STACKARG_SP_BUFF",
            "STACK_ALIGNMENT",
            "CALLER_SAVED_REGS",
            "RETURN_ADDR",
            "RETURN_VAL",
            "OVERFLOW_RETURN_VAL",
            "FP_RETURN_VAL",
        ):
            setattr(cc, attribute, getattr(platform_cc, attribute))
        cc.CALLEE_CLEANUP = False
        return cc

    def _analyze_callsite(
        self,
        caller_addr: int,
        caller_block_addr: int,
        call_insn_addr: int,
        include_preds: bool = False,
    ) -> CallSiteFact | None:
        func = self.kb.functions[caller_addr]
        subgraph = self._generate_callsite_subgraph(func, caller_block_addr, include_preds=include_preds)
        if subgraph is None:
            # failed to generate a subgraph when the caller block cannot be found in the function graph
            return None

        observation_points: list = [("insn", call_insn_addr, OP_BEFORE), ("node", caller_block_addr, OP_AFTER)]

        # find the return site
        caller_block = next(iter(bb for bb in subgraph if bb.addr == caller_block_addr))
        return_site_block = next(iter(subgraph.successors(caller_block)), None)
        if return_site_block is not None:
            observation_points.append(("node", return_site_block.addr, OP_AFTER))
        subgraph_addrs = {node.addr for node in subgraph}
        observation_points.extend(
            ("node", ret_site.addr, OP_AFTER)
            for ret_site in func.ret_sites
            if ret_site.addr in subgraph_addrs and ("node", ret_site.addr, OP_AFTER) not in observation_points
        )

        rda = self.project.analyses[ReachingDefinitionsAnalysis].prep()(
            func,
            func_graph=subgraph,
            observation_points=observation_points,
        )
        # rda_model: Optional[ReachingDefinitionsModel] = self.kb.defs.get_model(caller.addr)
        return self._collect_callsite_fact(func, caller_block, call_insn_addr, rda.model)

    def _extract_and_analyze_callsites(
        self,
        max_analyzing_callsites: int = 3,
        include_callsite_preds: bool = False,
    ) -> list[CallSiteFact]:  # pylint:disable=no-self-use
        """
        Analyze all call sites of the function and determine the possible number of arguments and if the function
        returns anything or not.
        """

        assert self._function is not None

        if self._cfg is None:
            l.warning("CFG is not provided. Skip calling convention analysis at call sites.")
            return []

        node = self._cfg.get_any_node(self._function.addr)
        if node is None:
            l.warning("%r is not in the CFG. Skip calling convention analysis at call sites.", self._function)

        facts = []
        in_edges = self._cfg.graph.in_edges(node, data=True)

        call_sites_by_function: dict[Function, list[tuple[int, int]]] = defaultdict(list)

        if len(in_edges) == 1:
            src, _, data = next(iter(in_edges))
            if (
                data.get("jumpkind", "Ijk_Call") == "Ijk_Boring"
                and self.kb.functions.contains_addr(src.function_address)
                and self.kb.functions[src.function_address].is_plt
            ):
                # find callers to the PLT stub instead
                in_edges = self._cfg.graph.in_edges(src, data=True)

        for src, _, data in sorted(in_edges, key=lambda x: x[0].addr):
            edge_type = data.get("jumpkind", "Ijk_Call")
            if not (edge_type == "Ijk_Call" or (edge_type == "Ijk_Boring" and self._cfg.graph.out_degree[src] == 1)):
                continue
            if not self.kb.functions.contains_addr(src.function_address):
                continue
            caller = self.kb.functions[src.function_address]
            if caller.is_simprocedure or caller.is_alignment:
                # do not analyze SimProcedures or alignment stubs
                continue
            if src.instruction_addrs:
                call_sites_by_function[caller].append((src.addr, src.instruction_addrs[-1]))

        call_sites_by_function_list = sorted(call_sites_by_function.items(), key=lambda x: x[0].addr)[
            :max_analyzing_callsites
        ]
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
                if fact is None:
                    continue
                facts.append(fact)

                ctr += 1
                if ctr >= max_analyzing_callsites:
                    break

        return facts

    def _generate_callsite_subgraph(
        self,
        func: Function,
        callsite_block_addr: int,
        include_preds: bool = False,
    ) -> networkx.DiGraph | None:
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
            dst_block_size = func.get_block_size(dst.addr)
            if dst_block_size is not None and dst_block_size > 0:
                dst_bb = self.project.factory.block(dst.addr, dst_block_size, opt_level=1)
                try:
                    vex_block = dst_bb.vex
                except SimTranslationError:
                    # failed to lift the block
                    continue

                # If there is only one 'IMark' statement in vex --> the target block contains only direct jump
                if (
                    len(vex_block.statements) == 1
                    and vex_block.statements[0].tag == "Ist_IMark"
                    and func.graph.out_degree(dst) == 1
                ):
                    for _, jmp_dst, jmp_data in func_graph.out_edges(dst, data=True):
                        subgraph.add_edge(dst, jmp_dst, **jmp_data)

        return subgraph

    def _collect_callsite_fact(
        self,
        caller: Function,
        caller_block,
        call_insn_addr: int,
        rda: ReachingDefinitionsModel,
    ) -> CallSiteFact:
        fact = CallSiteFact(
            True,  # by default we treat all return values as used
        )

        default_cc_cls = default_cc(
            self.project.arch.name,
            platform=self.project.simos.name if self.project is not None and self.project.simos is not None else None,
        )
        if default_cc_cls is not None:
            cc: SimCC = default_cc_cls(self.project.arch)
            if isinstance(self.project.arch, ArchPcode):
                # ReachingDefinitionsAnalysis currently executes VEX statements. A PcodeIRSB intentionally exposes
                # no VEX statements, so its empty result cannot prove that an ABI return register is unused.
                self._analyze_pcode_callsite_return_value_uses(cc, caller, caller_block, fact)
            else:
                self._analyze_callsite_return_value_uses(cc, caller, caller_block.addr, rda, fact)
            self._analyze_callsite_arguments(cc, caller_block, call_insn_addr, rda, fact)

        return fact

    @staticmethod
    def _pcode_register_byte_range(varnode) -> range | None:
        if varnode.space.name != "register":
            return None
        offset = int(varnode.offset)
        return range(offset, offset + int(varnode.size))

    @classmethod
    def _pcode_op_reads_return_value(cls, op, live_return_bytes: set[int]) -> bool:
        overlapping_inputs = [
            varnode
            for varnode in op.inputs
            if (byte_range := cls._pcode_register_byte_range(varnode)) is not None
            and not live_return_bytes.isdisjoint(byte_range)
        ]
        if not overlapping_inputs:
            return False

        # SLEIGH emits flag calculations before the destination write for instructions such as `sub ax, ax`.
        # Equal-input operations in this set have a result that is independent of the input value, so none of those
        # reads consume the old return value. The eventual AX write below then kills it.
        if op.opcode in _PCODE_VALUE_INDEPENDENT_SELF_OPS and len(op.inputs) == 2:
            left, right = op.inputs
            if (
                left.space.name == right.space.name
                and int(left.offset) == int(right.offset)
                and int(left.size) == int(right.size)
            ):
                return False

        return True

    def _analyze_pcode_callsite_return_value_uses(
        self,
        cc: SimCC,
        caller: Function,
        caller_block,
        fact: CallSiteFact,
    ) -> None:
        """Boundedly prove whether a p-code caller consumes, forwards, or kills an ABI return register.

        The initial ``return_value_used=True`` is deliberately retained whenever lifting, control flow, or the
        traversal bound leaves the answer indeterminate. Only a closed traversal where every surviving value is
        overwritten can classify the return as unused.
        """

        return_val = cc.RETURN_VAL
        if not isinstance(return_val, SimRegArg):
            return

        return_offset = return_val.check_offset(self.project.arch)
        initial_live_bytes = frozenset(range(return_offset, return_offset + return_val.size))
        if not initial_live_bytes:
            return

        caller_graph = caller.graph
        callsite_node = next(
            (
                node
                for node in caller_graph
                if node.addr == caller_block.addr
                and (getattr(caller_block, "size", None) is None or node.size == caller_block.size)
            ),
            None,
        )
        if callsite_node is None:
            return

        continuations = [
            dst
            for _, dst, data in caller_graph.out_edges(callsite_node, data=True)
            if data.get("type") == "fake_return"
        ]
        if not continuations:
            return

        worklist = deque((node, initial_live_bytes) for node in continuations)
        traversed: set[tuple[BlockNode, frozenset[int]]] = set()
        total_ops = 0
        return_value_forwarded = False
        indeterminate = False

        while worklist:
            node, initial_node_live_bytes = worklist.popleft()
            state_key = node, initial_node_live_bytes
            if state_key in traversed:
                continue
            if len(traversed) >= _PCODE_RETVAL_USE_MAX_STATES:
                indeterminate = True
                break
            traversed.add(state_key)

            if not isinstance(node, BlockNode) or node.size is None or node.size <= 0:
                indeterminate = True
                continue
            try:
                irsb = self.project.factory.block(node.addr, size=node.size).vex
            except AngrError:
                indeterminate = True
                continue
            if not isinstance(irsb, PcodeIRSB) or not irsb._ops or irsb.jumpkind == "Ijk_NoDecode":
                indeterminate = True
                continue

            live_return_bytes = set(initial_node_live_bytes)
            path_finished = False
            for op in irsb._ops:
                total_ops += 1
                if total_ops > _PCODE_RETVAL_USE_MAX_OPS:
                    indeterminate = True
                    path_finished = True
                    break

                if self._pcode_op_reads_return_value(op, live_return_bytes):
                    fact.return_value_used = True
                    fact.return_value_forwarded = False
                    return

                if op.output is not None:
                    output_byte_range = self._pcode_register_byte_range(op.output)
                    if output_byte_range is not None:
                        live_return_bytes.difference_update(output_byte_range)

                if op.opcode in {pypcode.OpCode.CALL, pypcode.OpCode.CALLIND}:
                    # A later call defines a fresh value in the ABI return register. Any surviving bytes from the
                    # callsite under analysis are dead at this point.
                    live_return_bytes.clear()

                if not live_return_bytes:
                    path_finished = True
                    break

                if op.opcode == pypcode.OpCode.RETURN:
                    return_value_forwarded = True
                    path_finished = True
                    break

            if path_finished:
                continue

            if irsb.jumpkind == "Ijk_Ret":
                return_value_forwarded = True
                continue

            successors = list(caller_graph.successors(node))
            if not successors:
                indeterminate = True
                continue
            worklist.extend((successor, frozenset(live_return_bytes)) for successor in successors)

        if indeterminate:
            return

        fact.return_value_used = False
        fact.return_value_forwarded = return_value_forwarded

    def _analyze_callsite_return_value_uses(
        self,
        cc: SimCC,
        caller: Function,
        caller_block_addr: int,
        rda: ReachingDefinitionsModel,
        fact: CallSiteFact,
    ) -> None:
        all_defs: set[Definition] = {
            def_
            for def_ in rda.all_uses._uses_by_definition
            if (
                (def_.codeloc.block_addr == caller_block_addr and def_.codeloc.stmt_idx == DEFAULT_STATEMENT)
                or any(isinstance(tag, ReturnValueTag) for tag in def_.tags)
            )
        }
        callsite_result = rda.observed_results.get(("node", caller_block_addr, OP_AFTER), None)
        if callsite_result is not None:
            # Definitions without explicit uses are absent from Uses. Include the live definitions immediately after
            # the call so an untouched ABI return value can still be recognized at the caller's return site.
            all_defs.update(
                def_
                for def_ in get_all_definitions(callsite_result.registers)
                if (
                    (def_.codeloc.block_addr == caller_block_addr and def_.codeloc.stmt_idx == DEFAULT_STATEMENT)
                    or any(isinstance(tag, ReturnValueTag) for tag in def_.tags)
                )
            )
        all_uses: Uses = rda.all_uses

        # determine if the return value is used
        return_val = cc.RETURN_VAL
        if return_val is not None and isinstance(return_val, SimRegArg):
            return_reg_offset, _ = self.project.arch.registers[return_val.reg_name]

            # find the def of the return val
            try:
                return_def = next(
                    iter(d for d in all_defs if isinstance(d.atom, Register) and d.atom.reg_offset == return_reg_offset)
                )
            except StopIteration:
                return_def = None
                fact.return_value_used = False

            if return_def is not None:
                # is it used?
                uses = all_uses.get_uses(return_def)
                if uses:
                    # the return value is used!
                    fact.return_value_used = True
                else:
                    # A wrapper can return a callee's value without ever reading the ABI return register in VEX:
                    #
                    #     call callee
                    #     ret
                    #
                    # Record forwarding when the call's definition is still the reaching definition at one of the
                    # caller's return sites. This preserves a locally proven callee return without using ambiguous
                    # `call; ret` wrappers to upgrade a locally proven void function.
                    fact.return_value_used = False
                    fact.return_value_forwarded = any(
                        return_def
                        in get_all_definitions(rda.observed_results[("node", ret_site.addr, OP_AFTER)].registers)
                        for ret_site in caller.ret_sites
                        if ("node", ret_site.addr, OP_AFTER) in rda.observed_results
                    )

    def _analyze_callsite_arguments(
        self,
        cc: SimCC,
        caller_block,
        call_insn_addr: int,
        rda: ReachingDefinitionsModel,
        fact: CallSiteFact,
    ) -> None:
        # determine if potential register and stack arguments are set
        observation_key = "insn", call_insn_addr, OP_BEFORE
        state = rda.observed_results.get(observation_key)
        if state is None:
            # the observation state is not found. it can happen if call_insn_addr is incorrect, which may happen (but
            # rarely) on incorrect CFGs.
            return

        defs_by_reg_offset: dict[int, list[Definition]] = defaultdict(list)
        all_reg_defs: set[Definition] = get_all_definitions(state.registers)
        all_stack_defs: set[Definition] = get_all_definitions(state.stack)
        indirect_target_reg_offsets = self._indirect_call_target_register_offsets(caller_block, call_insn_addr)
        for d in all_reg_defs:
            if (
                isinstance(d.atom, Register)
                and not isinstance(d.codeloc, ExternalCodeLocation)
                and not (d.codeloc.block_addr == caller_block.addr and d.codeloc.stmt_idx == DEFAULT_STATEMENT)
            ):
                # do an extra check because of how entry and callN work on Xtensa
                if isinstance(caller_block, ailment.Block) and self._likely_saving_temp_reg(
                    caller_block, d, all_reg_defs
                ):
                    continue
                defs_by_reg_offset[d.offset].append(d)
        defined_reg_offsets = set(defs_by_reg_offset.keys())
        sp_offset = 0
        if self.project.arch.bits in {32, 64}:
            # Calculate the offsets between sp and stack defs
            sp_offset = state.get_sp_offset()
            if sp_offset is None:
                # We can not find the sp_offset when sp is concrete
                # e.g.,
                # LDR     R2, =0x20070000
                # STR     R1, [R3,#0x38]
                # MOV     SP, R2
                # In this case, just assume sp_offset = 0
                sp_offset = 0
        defs_by_stack_offset = {
            d.atom.addr.offset - sp_offset: d
            for d in all_stack_defs
            if isinstance(d.atom, MemoryLocation) and isinstance(d.atom.addr, SpOffset)
        }

        default_type_cls = SimTypeInt if self.project.arch.bits == 32 else SimTypeLongLong
        arg_session = cc.arg_session(default_type_cls().with_arch(self.project.arch))
        temp_args: list[SimFunctionArgument | None] = []
        expected_args: list[SimFunctionArgument] = []
        for _ in range(30):  # at most 30 arguments
            arg_loc = cc.next_arg(arg_session, default_type_cls().with_arch(self.project.arch))
            expected_args.append(arg_loc)
            if isinstance(arg_loc, SimRegArg):
                reg_offset = self.project.arch.registers[arg_loc.reg_name][0]
                # is it initialized?
                if reg_offset in defined_reg_offsets and reg_offset not in indirect_target_reg_offsets:
                    temp_args.append(arg_loc)
                else:
                    # no more arguments
                    temp_args.append(None)
            elif isinstance(arg_loc, SimStackArg):
                if arg_loc.stack_offset - cc.STACKARG_SP_DIFF in defs_by_stack_offset:
                    temp_args.append(arg_loc)
                else:
                    # no more arguments
                    break
            else:
                break

        if None in temp_args:
            # we be very conservative here and ignore all arguments starting from the first missing one
            first_none_idx = temp_args.index(None)
            fact.args = temp_args[:first_none_idx]
        else:
            fact.args = temp_args

    def _indirect_call_target_register_offsets(self, caller_block, call_insn_addr: int) -> set[int]:
        """
        Find registers that only appear initialized at a call site because they hold the indirect call target.

        A register can be both an ABI argument register and the machine operand of an indirect call. Treating the
        target use as evidence for an additional argument produces a spurious trailing argument whose value is the
        callback itself.
        """
        block_size = getattr(caller_block, "size", None)
        if block_size is None:
            block_size = getattr(caller_block, "original_size", None)
        try:
            block = self.project.factory.block(caller_block.addr, size=block_size)
            irsb = block.vex
        except SimTranslationError:
            return set()

        if irsb.jumpkind != "Ijk_Call":
            return set()

        try:
            capstone_insns = block.capstone.insns
        except (ArchError, AttributeError, capstone.CsError):
            capstone_insns = ()

        for insn in capstone_insns:
            if insn.address != call_insn_addr or not insn.insn.operands:
                continue
            target_operand = insn.insn.operands[0]
            if target_operand.type == capstone.CS_OP_REG:
                target_reg_name = insn.insn.reg_name(target_operand.reg)
                try:
                    return {self.project.arch.get_register_offset(target_reg_name)}
                except ValueError:
                    break

        if isinstance(irsb.next, Get):
            return {irsb.next.offset}
        if not isinstance(irsb.next, RdTmp):
            return set()

        target_tmps = {irsb.next.tmp}
        changed = True
        while changed:
            changed = False
            for stmt in reversed(irsb.statements):
                if (
                    isinstance(stmt, WrTmp)
                    and stmt.tmp in target_tmps
                    and isinstance(stmt.data, RdTmp)
                    and stmt.data.tmp not in target_tmps
                ):
                    target_tmps.add(stmt.data.tmp)
                    changed = True

        target_reg_offsets = {
            stmt.offset
            for stmt in irsb.statements
            if isinstance(stmt, Put) and isinstance(stmt.data, RdTmp) and stmt.data.tmp in target_tmps
        }
        if target_reg_offsets:
            return target_reg_offsets

        return {
            stmt.data.offset
            for stmt in irsb.statements
            if isinstance(stmt, WrTmp) and stmt.tmp in target_tmps and isinstance(stmt.data, Get)
        }

    def _adjust_prototype(
        self,
        proto: SimTypeFunction,
        facts: list[CallSiteFact],
        update_arguments: int = UpdateArgumentsOption.DoNotUpdate,
    ) -> SimTypeFunction:
        # is the return value used anywhere?
        if facts:
            if all(not fact.return_value_used and not fact.return_value_forwarded for fact in facts) and (
                proto.returnty is None or isinstance(proto.returnty, SimTypeBottom)
            ):
                # A caller that discards a result cannot prove that the callee does not return one. Preserve a
                # concrete return type recovered from the callee body (or an authoritative declaration); call-site
                # facts may only resolve an otherwise unknown return type to void.
                proto.returnty = SimTypeBottom(label="void")
            elif (
                any(fact.return_value_used for fact in facts)
                or (proto.returnty is None and any(fact.return_value_forwarded for fact in facts))
            ) and (proto.returnty is None or isinstance(proto.returnty, SimTypeBottom)):
                returnty = {32: SimTypeInt, 16: SimTypeShort, 64: SimTypeLongLong}.get(
                    self.project.arch.bits, SimTypeInt
                )(signed=True)
                proto.returnty = returnty.with_arch(self.project.arch)

        if (
            update_arguments == UpdateArgumentsOption.AlwaysUpdate
            or (update_arguments == UpdateArgumentsOption.UpdateWhenCCHasNoArgs and not proto.args)
        ) and len({len(fact.args) for fact in facts}) == 1:
            fact = next(iter(facts))
            proto.args = tuple(
                self._guess_arg_type(arg) if arg is not None else SimTypeInt().with_arch(self.project.arch)
                for arg in fact.args
            )

        return proto

    def _args_from_vars(self, variables: list, var_manager: VariableManagerInternal):
        """
        Derive function arguments from input variables.

        :param variables:
        :param var_manager: The variable manager of this function.
        :return:
        """

        assert self._function is not None

        args = set()
        ret_addr_offset = 0 if not self.project.arch.call_pushes_ret else self.project.arch.bytes

        reg_vars_with_single_access: list[SimRegisterVariable] = []

        def_cc = default_cc(
            self.project.arch.name,
            platform=self.project.simos.name if self.project is not None and self.project.simos is not None else None,
        )
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
                if not is_sane_register_variable(self.project.arch, variable.reg, variable.size, def_cc=def_cc):
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

        restored_reg_vars: set[SimRegArg] = set()

        # is there any instruction that restores this register in any end blocks?
        if reg_vars_with_single_access:
            if self._function.returning is False:
                # no restoring is required if this function does not return
                for var_ in reg_vars_with_single_access:
                    reg_name = self.project.arch.translate_register_name(var_.reg, size=var_.size)
                    restored_reg_vars.add(SimRegArg(reg_name, var_.size))

            else:
                reg_offsets: set[int] = {r.reg for r in reg_vars_with_single_access}
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
                        if (
                            len(accesses) == 1
                            and accesses[0].access_type == VariableAccessSort.READ
                            and accesses[0].location.block_addr == self._function.addr
                            and (
                                (block := self.project.factory.block(self._function.addr)).vex.jumpkind != "Ijk_Call"
                                or accesses[0].location.ins_addr
                                != block.instruction_addrs[-1 - bool(self.project.arch.branch_delay_slot)]
                            )
                        ):
                            # check if there is only a store to the stack which is never used
                            dests = var_manager.find_variables_by_insn(
                                accesses[0].location.ins_addr, VariableType.MEMORY
                            )
                            if dests is not None and len(dests) == 1 and isinstance(dests[0][0], SimStackVariable):
                                accesses2 = var_manager.get_variable_accesses(dests[0][0])
                                if len(accesses2) == 1:
                                    reg_name = self.project.arch.translate_register_name(var_.reg, size=var_.size)
                                    restored_reg_vars.add(SimRegArg(reg_name, var_.size))
                                    break

        return args.difference(restored_reg_vars)

    def _consolidate_input_args(self, input_args: set[SimRegArg | SimStackArg]) -> set[SimRegArg | SimStackArg]:
        """
        Consolidate register arguments by converting partial registers to full registers on certain architectures.

        :param input_args:  A set of input arguments.
        :return:            A set of consolidated input args.
        """

        if self.project.arch.name in {"AMD64", "X86"}:
            new_input_args = set()
            for a in input_args:
                if isinstance(a, SimRegArg) and a.size < self.project.arch.bytes:
                    # use complete registers on AMD64 and X86
                    reg_offset, reg_size = self.project.arch.registers[a.reg_name]
                    full_reg_offset, full_reg_size = get_reg_offset_base_and_size(
                        reg_offset, self.project.arch, size=reg_size
                    )
                    full_reg_name = self.project.arch.translate_register_name(full_reg_offset, size=full_reg_size)
                    arg = SimRegArg(full_reg_name, full_reg_size)
                    if arg not in new_input_args:
                        new_input_args.add(arg)
                else:
                    new_input_args.add(a)
            return new_input_args

        return set(input_args)

    def _reorder_args(self, args: set[SimRegArg | SimStackArg], cc: SimCC) -> list[SimRegArg | SimStackArg]:
        """
        Reorder arguments according to the calling convention identified.

        :param args:   A set of arguments that haven't been ordered.
        :param cc:    The identified calling convention.
        :return:            A reordered list of args.
        """

        def _is_same_reg(rn0: str, rn1: str) -> bool:
            """
            Check if rn0 and rn1 belong to the same base register.

            :param rn0:     Register name of the first register.
            :param rn1:     Register name of the second register.
            :return:        True if they belong to the same base register; False otherwise.
            """
            if rn0 == rn1:
                return True
            off0, sz0 = self.project.arch.registers[rn0]
            full_off0 = get_reg_offset_base(off0, self.project.arch, sz0)
            off1, sz1 = self.project.arch.registers[rn1]
            full_off1 = get_reg_offset_base(off1, self.project.arch, sz1)
            return full_off0 == full_off1

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

        initial_stack_args = sorted([a for a in args if isinstance(a, SimStackArg)], key=lambda a: a.stack_offset)
        # ensure stack args are consecutive if necessary
        if cc.STACKARG_SP_DIFF is not None and initial_stack_args:
            arg_by_offset = {a.stack_offset: a for a in initial_stack_args}
            init_stackarg_offset = cc.STACKARG_SP_DIFF + cc.STACKARG_SP_BUFF
            int_arg_size = self.project.arch.bytes
            for stackarg_offset in range(init_stackarg_offset, max(arg_by_offset), int_arg_size):
                if stackarg_offset not in arg_by_offset:
                    arg_by_offset[stackarg_offset] = SimStackArg(stackarg_offset, int_arg_size)
            stack_args = [arg_by_offset[offset] for offset in sorted(arg_by_offset)]
        else:
            stack_args = initial_stack_args

        stack_int_args = [a for a in stack_args if not a.is_fp]
        stack_fp_args = [a for a in stack_args if a.is_fp]
        # match int args first
        for reg_name in cc.ARG_REGS:
            try:
                arg = next(iter(a for a in int_args if isinstance(a, SimRegArg) and _is_same_reg(a.reg_name, reg_name)))
            except StopIteration:
                # have we reached the end of the args list?
                if [a for a in int_args if isinstance(a, SimRegArg)] or len(stack_int_args) > 0:
                    # haven't reached the end yet or there are stack args
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
                    arg = next(
                        iter(a for a in fp_args if isinstance(a, SimRegArg) and _is_same_reg(a.reg_name, reg_name))
                    )
                except StopIteration:
                    # have we reached the end of the args list?
                    if [a for a in fp_args if isinstance(a, SimRegArg)] or len(stack_fp_args) > 0:
                        # haven't reached the end yet or there are stack args
                        arg = SimRegArg(reg_name, self.project.arch.bytes)
                    else:
                        break
                reg_args.append(arg)
                if arg in fp_args:
                    fp_args.remove(arg)

        return reg_args + int_args + fp_args + stack_args

    def _guess_arg_type(
        self,
        arg: SimFunctionArgument,
        cc: SimCC | None = None,
        arg_uses: Mapping[tuple[int, int], list[tuple[Function | None, int]]] | None = None,
    ) -> SimType:
        if cc is not None and cc.FP_ARG_REGS and isinstance(arg, SimRegArg) and arg.reg_name in cc.FP_ARG_REGS:
            if arg.size == 4:
                return SimTypeFloat()
            if arg.size == 8:
                return SimTypeDouble()

        if cc is not None and arg.size == cc.arch.bytes:
            if isinstance(arg, SimRegArg):
                key = (KIND_REG, cc.arch.registers[arg.reg_name][0])
            elif isinstance(arg, SimStackArg):
                key = (KIND_STACKVAL, arg.stack_offset)
            else:
                key = (-1, -1)
            proposed_ptr_ty = set()
            proposed_disposition = 0
            for func, use in (arg_uses or {}).get(key, ()):
                if func is None:
                    proposed_disposition |= use
                elif func.prototype is not None:
                    passed_ty = func.prototype.args[use]
                    if isinstance(passed_ty, SimTypePointer):
                        proposed_ptr_ty.add(passed_ty.pts_to)
                        match passed_ty.disposition:
                            case PointerDisposition.OUT | PointerDisposition.OUTMAYBE:
                                proposed_disposition |= 2
                            case PointerDisposition.IN:
                                proposed_disposition |= 1
                            case PointerDisposition.IN_OUT | PointerDisposition.IN_OUTMAYBE:
                                proposed_disposition |= 3

            if proposed_ptr_ty or proposed_disposition:
                ptr_ty = SimTypeBottom() if len(proposed_ptr_ty) != 1 else next(iter(proposed_ptr_ty))
                disposition = (
                    PointerDisposition.UNKNOWN
                    if proposed_disposition == 0
                    else (
                        PointerDisposition.IN
                        if proposed_disposition == 1
                        else (
                            PointerDisposition.OUTMAYBE if proposed_disposition == 2 else PointerDisposition.IN_OUTMAYBE
                        )
                    )
                )
                return SimTypePointer(ptr_ty, disposition=disposition)

        if arg.size == 8:
            return SimTypeLongLong()
        if arg.size == 4:
            return SimTypeInt()
        if arg.size == 2:
            return SimTypeShort()
        if arg.size == 1:
            return SimTypeChar()
        # Unsupported for now
        return SimTypeBottom()

    def _guess_retval_type(self, cc: SimCC, ret_val_size: int | None) -> SimType:
        assert self._function is not None

        if cc.FP_RETURN_VAL and self._function.ret_sites:
            # examine the last block of the function and see which registers are assigned to
            for ret_block in self._function.ret_sites:
                fpretval_updated, retval_updated = False, False
                fp_reg_size = 0
                try:
                    irsb = self.project.factory.block(ret_block.addr, size=ret_block.size).vex
                except SimTranslationError:
                    # failed to lift the block
                    continue
                for stmt in irsb.statements:
                    if isinstance(stmt, Put) and isinstance(stmt.data, RdTmp):
                        reg_size = irsb.tyenv.sizeof(stmt.data.tmp) // self.project.arch.byte_width  # type: ignore
                        reg_name = self.project.arch.translate_register_name(stmt.offset, size=reg_size)
                        if isinstance(cc.FP_RETURN_VAL, SimRegArg) and reg_name == cc.FP_RETURN_VAL.reg_name:
                            fpretval_updated = True
                            fp_reg_size = reg_size
                        elif isinstance(cc.RETURN_VAL, SimRegArg) and reg_name == cc.RETURN_VAL.reg_name:
                            retval_updated = True

                if fpretval_updated and not retval_updated:
                    # possibly float
                    return SimTypeFloat() if fp_reg_size == 4 else SimTypeDouble()

        if ret_val_size is not None:
            if ret_val_size == 1:
                return SimTypeChar()
            if ret_val_size == 2:
                return SimTypeShort()
            if 3 <= ret_val_size <= 4:
                return SimTypeInt()
            if 5 <= ret_val_size <= 8:
                return SimTypeLongLong()
            if self.project.is_rust_binary and 9 <= ret_val_size <= 16:
                return SimTypeInt128()

        return SimTypeBottom(label="void")

    @staticmethod
    def _likely_saving_temp_reg(ail_block: ailment.Block, d: Definition, all_reg_defs: set[Definition]) -> bool:
        if (
            d.codeloc.block_addr == ail_block.addr
            and d.codeloc.stmt_idx is not None
            and d.codeloc.stmt_idx < len(ail_block.statements)
        ):
            stmt = ail_block.statements[d.codeloc.stmt_idx]
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.Register):
                src_offset = stmt.src.reg_offset
                src_reg_def = next(
                    iter(
                        d_ for d_ in all_reg_defs if isinstance(d_.atom, Register) and d_.atom.reg_offset == src_offset
                    ),
                    None,
                )
                if src_reg_def is not None and isinstance(src_reg_def.codeloc, ExternalCodeLocation):
                    return True
        return False

    def is_va_start_amd64(self, func: Function) -> tuple[bool, int | None]:
        # TODO: test this approach more widely
        # this will definitely not work on functions with more than 5 fixed args
        if func.startpoint is None:
            return False, None

        head = func.startpoint

        # compare instructions
        allowed_spilled_regs = [
            capstone.x86.X86_REG_RDI,
            capstone.x86.X86_REG_RSI,
            capstone.x86.X86_REG_RDX,
            capstone.x86.X86_REG_RCX,
            capstone.x86.X86_REG_R8,
            capstone.x86.X86_REG_R9,
        ]
        stores: list[tuple[int, int, int, int]] = []
        for i, insn in enumerate(self.project.factory.block(head.addr, size=head.size).capstone.insns):
            if not (
                insn.mnemonic == "mov"
                and insn.operands[0].type == capstone.x86.X86_OP_MEM
                and insn.operands[0].mem.base in (capstone.x86.X86_REG_RSP, capstone.x86.X86_REG_RBP)
                and insn.operands[0].mem.index == 0
                and insn.operands[1].type == capstone.x86.X86_OP_REG
                and insn.operands[1].reg in allowed_spilled_regs
            ):
                continue
            idx = allowed_spilled_regs.index(insn.operands[1].reg)
            base, disp = insn.operands[0].mem.base, insn.operands[0].mem.disp
            if stores and stores[-1] != (i - 1, idx - 1, base, disp - 8):
                return False, None
            stores.append((i, idx, base, disp))

        if not stores:
            return False, None

        if stores[-1][1] != len(allowed_spilled_regs) - 1:
            return False, None

        base = stores[0][2]
        disp_min = stores[0][3]
        disp_max = stores[-1][3]
        num_fixed = stores[0][1]
        zero_disp = stores[0][3] - 8 * num_fixed

        for blk in func.blocks:
            for insn in blk.capstone.insns:
                for opidx, op in enumerate(insn.operands):
                    if op.type == capstone.x86.X86_OP_MEM and op.mem.base == base:
                        if op.mem.disp == zero_disp and not (insn.mnemonic == "lea" and opidx == 1):
                            # referencing the zero_disp in a non-lea way
                            return False, None
                        if disp_min <= op.mem.disp <= disp_max and not (
                            blk.addr == func.addr and insn.mnemonic == "mov" and opidx == 0
                        ):
                            # referencing the spills outside of writing them in the first block
                            return False, None

        return True, num_fixed


register_analysis(CallingConventionAnalysis, "CallingConvention")
