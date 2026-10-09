# pylint:disable=no-self-use
from __future__ import annotations

import contextlib
import copy
import logging
from collections import defaultdict
from collections.abc import Mapping
from typing import TYPE_CHECKING

import archinfo
import capstone
import networkx
from pyvex.expr import Binop, Get, IRExpr, Load, Qop, RdTmp, Triop, Unop
from pyvex.expr import Const as VexConst
from pyvex.stmt import IMark, Put, PutI, WrTmp

from angr import ailment
from angr.analyses.analysis import Analysis, register_analysis
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis, get_all_definitions
from angr.calling_conventions import (
    SimCC,
    SimCCMicrosoftThiscall,
    SimCCS390X,
    SimCCSyscall,
    SimFunctionArgument,
    SimRegArg,
    SimStackArg,
    default_cc_for_project,
    go_cc_class_for_project,
    project_language,
)
from angr.code_location import ExternalCodeLocation
from angr.errors import SimTranslationError
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register, SpOffset
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.rd_model import ReachingDefinitionsModel
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag
from angr.knowledge_plugins.variables.variable_access import VariableAccessSort
from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal, VariableType
from angr.procedures import SIM_LIBRARIES, SIM_PROCEDURES
from angr.procedures.definitions import SimSyscallLibrary
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
    SimTypeLongDouble,
    SimTypeLongLong,
    SimTypeNum,
    SimTypePointer,
    SimTypeReg,
    SimTypeShort,
    parse_cpp_file,
)
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr.utils.constants import DEFAULT_STATEMENT
from angr.utils.ssa import get_reg_offset_base, get_reg_offset_base_and_size
from angr.utils.vex import block_branch_ins_addr
from angr.utils.x87 import X87StackModel

from .fact_collector import KIND_REG, KIND_STACKVAL, FactCollector, FactData
from .utils import is_sane_register_variable, merge_overlapping_register_spans, reg_arg_from_span

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel
    from angr.knowledge_plugins.key_definitions.definition import Definition
    from angr.knowledge_plugins.key_definitions.uses import Uses

l = logging.getLogger(name=__name__)


class CallSiteFact:
    """
    Store facts about each call site.
    """

    def __init__(self, return_value_used):
        self.return_value_used: bool = return_value_used
        self.return_fp_size: int | None = None  # 4=float, 8=double; None=integer/unknown
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
        flavor: str | None = None,
    ):
        """
        :param flavor:  The decompilation flavor whose callee prototypes are consulted (None: the default flavor).
        """
        if func is not None and not isinstance(func, Function):
            func = self.kb.functions[func]
        self._function = func
        self._flavor = flavor
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
        self._retval_incidental: bool | None = None
        # x87 stack pointer at each return site and x87 arguments, computed on demand by _x87_scan
        self._x87_ret_ftops: dict[int, int | None] | None = None
        self._x87_args: tuple[int, bool] | None = None
        self._extra_pop: int | None = extra_pop
        self._collect_facts = collect_facts
        self._collect_facts_arg_uses = collect_facts_arg_uses
        self._collect_facts_arg_passthru = collect_facts_arg_passthru
        self._callsites: dict[int, tuple[Function, list[FactData]]] = {}
        self._pushed_arg_callsites: dict[int, tuple[Function, list[FactData]]] = {}
        self._pointer_arg_derefs = {}
        self._pointer_arg_deref_sizes: dict[FactData, int] = {}
        self._retval_arg: SimRegArg | None = None

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
                    cc_cls = default_cc_for_project(self.project, syscall=self._function.is_syscall)
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
                track_arg_passthru=self._collect_facts_arg_passthru or self.project.arch.name == "X86",
                flavor=self._flavor,
            )
            self._input_args = facts.input_args
            self._retval_size = facts.retval_size
            self._retval_incidental = facts.retval_incidental
            self._callsites = facts.callsites
            self._pushed_arg_callsites = facts.pushed_arg_callsites
            self._pointer_arg_derefs = facts.pointer_arg_derefs
            self._pointer_arg_deref_sizes = facts.pointer_arg_deref_sizes
            self._retval_arg = facts.retval_arg
            self._unused_args = facts.unused_args
            self._extra_pop = facts.extra_pop

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
            if prototype is not None:
                prototype = self._apply_x87_args(cc, prototype)
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

    def _callsite_target_is_syscall(self) -> bool:
        """Does the call at this call site target a syscall?

        A syscall target is not an edge of the caller's transition graph; it is what
        ``Function.get_call_target`` resolves the call-site block to.
        """
        assert self.caller_func_addr is not None
        try:
            caller = self.kb.functions.get_by_addr(self.caller_func_addr)
        except KeyError:
            return False
        target = caller.get_call_target(self.callsite_block_addr)
        return target is not None and self.project.simos.is_syscall_addr(target)

    def _analyze_callsite_only(self):
        assert self.caller_func_addr is not None
        assert self.callsite_block_addr is not None
        assert self.callsite_insn_addr is not None
        cc, prototype = None, None

        callee_is_syscall = self._callsite_target_is_syscall()
        for include_callsite_preds in [False, True]:
            fact = self._analyze_callsite(
                self.caller_func_addr,
                self.callsite_block_addr,
                self.callsite_insn_addr,
                include_preds=include_callsite_preds,
                callee_is_syscall=callee_is_syscall,
            )
            if fact is None:
                continue
            callsite_facts = [fact]
            cc_cls = default_cc_for_project(self.project, syscall=callee_is_syscall)
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
                cc_cls = default_cc_for_project(self.project)
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
                real_proto = real_func.get_prototype(self._flavor)
                if real_proto is not None:
                    return cc, real_proto, real_func.prototype_libname, False
            else:
                return cc, real_func.get_prototype(self._flavor), real_func.prototype_libname, False

        if self.analyze_callsites:
            # determine the calling convention by analyzing its callsites
            callsite_facts = self._extract_and_analyze_callsites(max_analyzing_callsites=1)
            cc_cls = default_cc_for_project(self.project)
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
        if isinstance(self.project.arch, archinfo.ArchS390X) and isinstance(proto, SimTypeFunction):
            # GCC mangles the 128-bit s390x long double as "g" (__float128); "e" ("long double") only comes from
            # -mlong-double-64 code (e.g., libstdc++'s compat symbols), where it is a plain double
            proto = proto.copy()
            proto.args = tuple(
                SimTypeDouble(label=arg.label) if isinstance(arg, SimTypeLongDouble) else arg for arg in proto.args
            )
            if isinstance(proto.returnty, SimTypeLongDouble):
                proto.returnty = SimTypeDouble(label=proto.returnty.label)
        if (
            isinstance(proto, SimTypeCppFunction)
            and self.project.simos.name == "Win32"
            and self.project.arch.name == "X86"
            and proto.convention == "__thiscall"
        ):
            cc_cls = SimCCMicrosoftThiscall
        else:
            cc_cls = default_cc_for_project(self.project)
            assert cc_cls is not None
        cc = cc_cls(self.project.arch)
        return cc, proto, None

    def _forced_cc_cls(self) -> type[SimCC] | None:
        """
        A calling convention that this function is known to use regardless of what its arguments look like.

        The only case so far is Go's legacy all-stack ABI0, which the gc linker marks by suffixing the symbol with
        ".abi0". ABI0 and ABIInternal are indistinguishable from the arguments alone, since stack arguments are valid
        under both.
        """
        if (
            self._function is not None
            and self._function.name is not None
            and self._function.name.endswith(".abi0")
            and self.project.is_go_binary
        ):
            return go_cc_class_for_project(self.project, abi0=True)
        return None

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
        else:
            input_args = set(self._input_args)
            retval_size = self._retval_size

        # check if this function is a variadic function
        if self.project.arch.name == "AMD64":
            is_variadic, fixed_args = self.is_va_start_amd64(self._function)
            if self.has_va_xmm_save_area_amd64(self._function):
                # xmm0-7 are only read to fill the va_start register save area; they are not FP arguments
                input_args = {
                    a
                    for a in input_args
                    if not (
                        isinstance(a, SimRegArg) and self._is_fp_reg_offset(self.project.arch.registers[a.reg_name][0])
                    )
                }
        else:
            is_variadic = False
            fixed_args = None

        # TODO: properly determine sp_delta
        sp_delta = self.project.arch.bytes if self.project.arch.call_pushes_ret else 0

        # a slice of a vector register at an unnamed offset (ymm10+4) can never be an argument
        input_args = type(input_args)(
            a for a in input_args if not (isinstance(a, SimRegArg) and a.reg_name not in self.project.arch.registers)
        )
        full_input_args = self._consolidate_input_args(input_args)
        full_input_args_copy = list(full_input_args)  # input_args might be modified by find_cc()
        forced_cc_cls = self._forced_cc_cls()
        if forced_cc_cls is not None:
            forced_cc_cls._match(self.project.arch, full_input_args_copy, sp_delta, self._unused_args, self._extra_pop)
            cc = forced_cc_cls(self.project.arch)
        else:
            language = project_language(self.project)
            # Go: the one convention the binary's Go release uses
            go_cc = go_cc_class_for_project(self.project) if language == "go" else None
            cc = SimCC.find_cc(
                self.project.arch,
                full_input_args_copy,
                sp_delta,
                platform=self.project.simos.name,
                unused_hint=self._unused_args,
                extra_pop=self._extra_pop,
                language=language,
                candidates=[go_cc] if go_cc is not None else None,
            )

        for a in full_input_args:
            if a not in full_input_args_copy and a in input_args:
                input_args.remove(a)

        if cc is None:
            l.warning(
                "_analyze_function(): Cannot find a calling convention for %r that fits the given arguments.",
                self._function,
            )
            return None
        # Normalize FP sub-register names (e.g. xmm0lq -> xmm0) before
        # reordering so they match the CC's FP_ARG_REGS.  Skip when ALL FP arg
        # slots are occupied -- that indicates runtime/crt startup noise, not
        # genuine FP parameters.
        fp_reg_args = [
            a
            for a in input_args
            if isinstance(a, SimRegArg)
            and self._is_fp_reg_offset(self.project.arch.registers.get(a.reg_name, (None,))[0])
        ]
        if fp_reg_args and (
            not cc.FP_ARG_REGS
            or len(fp_reg_args) < len(cc.FP_ARG_REGS)
            or isinstance(self.project.arch, archinfo.ArchS390X)
        ):
            input_args = self._consolidate_input_args(input_args, for_matching=False)
        args = self._reorder_args(input_args, cc)
        if fixed_args is not None:
            args = args[:fixed_args]
        args = self._reorder_args_by_library_prototype(args, cc)

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
        ret_type = self._guess_retval_type(cc, retval_size)
        if self._function.name == "main" and self.project.arch.bits == 64 and isinstance(ret_type, SimTypeLongLong):
            # hack - main must return an int even in 64-bit binaries
            ret_type = SimTypeInt()

        if self.project.arch.name == "X86":
            args = self._apply_i386_cdecl_fp_arg_adjustments(args)

        arg_types = [self._guess_arg_type(arg, cc, arg_uses) for arg in args]
        if (
            self._retval_arg is not None
            and retval_size == self.project.arch.bytes
            and self._retval_arg in args
            and isinstance(ret_type, SimTypeLongLong)
        ):
            # the function returns one of its pointer arguments (sret-style hidden result pointer, strcpy's dest)
            passthru_ty = arg_types[args.index(self._retval_arg)]
            if isinstance(passthru_ty, SimTypePointer):
                ret_type = passthru_ty
        prototype = SimTypeFunction(arg_types, ret_type, variadic=is_variadic)

        return cc, prototype

    def _analyze_callsite(
        self,
        caller_addr: int,
        caller_block_addr: int,
        call_insn_addr: int,
        include_preds: bool = False,
        callee_is_syscall: bool = False,
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

        rda = self.project.analyses[ReachingDefinitionsAnalysis].prep()(
            func,
            func_graph=subgraph,
            observation_points=observation_points,
            flavor=self._flavor,
        )
        # rda_model: Optional[ReachingDefinitionsModel] = self.kb.defs.get_model(caller.addr)
        return self._collect_callsite_fact(caller_block, call_insn_addr, rda.model, callee_is_syscall=callee_is_syscall)

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
        caller_block,
        call_insn_addr: int,
        rda: ReachingDefinitionsModel,
        callee_is_syscall: bool = False,
    ) -> CallSiteFact:
        fact = CallSiteFact(
            True,  # by default we treat all return values as used
        )

        # Whose convention describes these argument slots: the syscall convention when this call
        # site targets a syscall, or when the function being analyzed is itself one.
        syscall = callee_is_syscall or (self._function is not None and self._function.is_syscall)
        default_cc_cls = default_cc_for_project(self.project, syscall=syscall)
        if default_cc_cls is not None:
            cc: SimCC = default_cc_cls(self.project.arch)
            self._analyze_callsite_return_value_uses(cc, caller_block.addr, rda, fact)
            self._analyze_callsite_arguments(cc, caller_block, call_insn_addr, rda, fact)

        return fact

    def _analyze_callsite_return_value_uses(
        self, cc: SimCC, caller_block_addr: int, rda: ReachingDefinitionsModel, fact: CallSiteFact
    ) -> None:
        all_defs: set[Definition] = {
            def_
            for def_ in rda.all_uses._uses_by_definition
            if (
                (def_.codeloc.block_addr == caller_block_addr and def_.codeloc.stmt_idx == DEFAULT_STATEMENT)
                or any(isinstance(tag, ReturnValueTag) for tag in def_.tags)
            )
        }
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
                    fact.return_value_used = False

        # Also check the FP return register (e.g. xmm0 on AMD64), but only
        # when the integer return register is NOT used.  This handles functions
        # like double_identity at O1 where rax is never written but xmm0
        # carries the result.  When the integer return IS used, the function
        # returns an integer and any xmm0 definition is coincidental.
        fp_return_val = cc.FP_RETURN_VAL
        if not fact.return_value_used and fp_return_val is not None and isinstance(fp_return_val, SimRegArg):
            try:
                fp_reg_offset, _ = self.project.arch.registers[fp_return_val.reg_name]
            except KeyError:
                fp_reg_offset = None
            if fp_reg_offset is not None:
                fp_return_def = next(
                    (d for d in all_defs if isinstance(d.atom, Register) and d.atom.reg_offset == fp_reg_offset),
                    None,
                )
                if fp_return_def is not None:
                    uses = all_uses.get_uses(fp_return_def)
                    if uses:
                        fact.return_value_used = True
                        # Record FP return size (4=float, 8=double).
                        atom_size = getattr(fp_return_def.atom, "size", None)
                        fact.return_fp_size = atom_size if atom_size in (4, 8) else 8

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

        # registers that a preceding callee may define for its caller: its return value
        ret_reg_offsets = (
            {self.project.arch.registers[cc.RETURN_VAL.reg_name][0]} if isinstance(cc.RETURN_VAL, SimRegArg) else set()
        )

        defs_by_reg_offset: dict[int, list[Definition]] = defaultdict(list)
        all_reg_defs: set[Definition] = get_all_definitions(state.registers)
        all_stack_defs: set[Definition] = get_all_definitions(state.stack)
        for d in all_reg_defs:
            if (
                isinstance(d.atom, Register)
                and not isinstance(d.codeloc, ExternalCodeLocation)
                and not (d.codeloc.block_addr == caller_block.addr and d.codeloc.stmt_idx == DEFAULT_STATEMENT)
                # registers clobbered by a preceding call are not arguments
                and not (d.codeloc.stmt_idx is None and d.atom.reg_offset not in ret_reg_offsets)
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
            try:
                arg_loc = cc.next_arg(arg_session, default_type_cls().with_arch(self.project.arch))
            except (TypeError, ValueError):
                if not isinstance(cc, SimCCSyscall):
                    raise
                # SimCCX86LinuxSyscall and SimCCARMLinuxSyscall declare a fixed set of
                # argument registers and refuse once those are spent instead of spilling,
                # so for them out of locations means out of arguments.
                break
            expected_args.append(arg_loc)
            if isinstance(arg_loc, SimRegArg):
                reg_offset = self.project.arch.registers[arg_loc.reg_name][0]
                # is it initialized?
                if reg_offset in defined_reg_offsets:
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

    def _adjust_prototype(
        self,
        proto: SimTypeFunction,
        facts: list[CallSiteFact],
        update_arguments: int = UpdateArgumentsOption.DoNotUpdate,
    ) -> SimTypeFunction:
        # is the return value used anywhere?
        if facts:
            if all(fact.return_value_used is False for fact in facts):
                # callers ignoring a result is not proof there is none; printf's is ignored all day. It settles the
                # question only when the function's own evidence for a return value is a leftover: rax written by
                # a load or a move whose value is then stored or tested, and merely still there at the ret. The
                # call-site fact only ever looked at the integer return register, so a floating-point return is
                # out of its reach entirely.
                # The exception: with no function body to ask (call-site-only analysis) or no type at all yet, the
                # call sites are the only evidence there is
                if (
                    self._function is None
                    or proto.returnty is None
                    or (
                        self._is_retval_incidental()
                        and not isinstance(proto.returnty, (SimTypeFloat, SimTypeDouble, SimTypeLongDouble))
                    )
                ):
                    proto.returnty = SimTypeBottom(label="void")
            else:
                if proto.returnty is None or isinstance(proto.returnty, SimTypeBottom):
                    # If any callsite saw the FP return register used, infer an FP return type.
                    fp_sizes = [f.return_fp_size for f in facts if f.return_fp_size is not None]
                    if fp_sizes:
                        fp_size = max(fp_sizes)
                        if fp_size == 4:
                            proto.returnty = SimTypeFloat().with_arch(self.project.arch)
                        else:
                            proto.returnty = SimTypeDouble().with_arch(self.project.arch)
                    else:
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

        def_cc = default_cc_for_project(self.project)
        for variable in variables:
            if isinstance(variable, SimStackVariable):
                # a stack variable. convert it to a stack argument.
                # TODO: deal with the variable base
                if self.project.arch.call_pushes_ret and variable.offset <= 0:
                    # skip the return address on the stack
                    # TODO: make sure it was the return address
                    continue
                if variable.offset - ret_addr_offset >= 0:
                    is_fp = isinstance(self.project.arch, archinfo.ArchS390X) and self._is_fp_stack_load(
                        var_manager, variable
                    )
                    arg = SimStackArg(variable.offset - ret_addr_offset, variable.size, is_fp=is_fp)
                    args.add(arg)
            elif isinstance(variable, SimRegisterVariable):
                # a register variable, convert it to a register argument
                if not is_sane_register_variable(self.project.arch, variable.reg, variable.size, def_cc=def_cc):
                    continue
                arg = reg_arg_from_span(self.project.arch, variable.reg, variable.size)
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
                    restored_reg_vars.add(reg_arg_from_span(self.project.arch, var_.reg, var_.size))

            else:
                reg_offsets: set[int] = {r.reg for r in reg_vars_with_single_access}
                # return-value registers are never restored
                ret_reg_offsets = {self.project.arch.ret_offset}
                if (
                    def_cc is not None
                    and isinstance(def_cc.FP_RETURN_VAL, SimRegArg)
                    and def_cc.FP_RETURN_VAL.reg_name in self.project.arch.registers
                ):
                    ret_reg_offsets.add(self.project.arch.registers[def_cc.FP_RETURN_VAL.reg_name][0])
                for var_ in var_manager.get_variables(sort="reg"):
                    if var_.reg in (reg_offsets - ret_reg_offsets):
                        # check if there is only a write to it
                        accesses = var_manager.get_variable_accesses(var_)
                        if len(accesses) == 1 and accesses[0].access_type == VariableAccessSort.WRITE:
                            found = False
                            for end_block_addr, end_block_size in end_blocks:
                                if end_block_addr <= accesses[0].location.ins_addr < end_block_addr + end_block_size:
                                    found = True
                                    break

                            if found:
                                restored_reg_vars.add(reg_arg_from_span(self.project.arch, var_.reg, var_.size))
                        if (
                            len(accesses) == 1
                            and accesses[0].access_type == VariableAccessSort.READ
                            and accesses[0].location.block_addr == self._function.addr
                            and (
                                (block := self.project.factory.block(self._function.addr)).vex.jumpkind != "Ijk_Call"
                                or accesses[0].location.ins_addr
                                != block_branch_ins_addr(
                                    block.instruction_addrs, block.addr, block.size, self.project.arch
                                )
                            )
                        ):
                            # check if there is only a store to the stack which is never used
                            dests = var_manager.find_variables_by_insn(
                                accesses[0].location.ins_addr, VariableType.MEMORY
                            )
                            if dests is not None and len(dests) == 1 and isinstance(dests[0][0], SimStackVariable):
                                accesses2 = var_manager.get_variable_accesses(dests[0][0])
                                if len(accesses2) == 1:
                                    restored_reg_vars.add(reg_arg_from_span(self.project.arch, var_.reg, var_.size))
                                    break

        return args.difference(restored_reg_vars)

    def _is_fp_stack_load(self, var_manager: VariableManagerInternal, variable: SimStackVariable) -> bool:
        """
        Whether an instruction that reads ``variable`` loads a floating-point value (e.g., ``adb %f0, 0xa0(%r15)``).
        """
        for acc in var_manager.get_variable_accesses(variable):
            if acc.access_type != VariableAccessSort.READ or acc.location.block_addr is None:
                continue
            try:
                vex = self.project.factory.block(acc.location.block_addr).vex
            except SimTranslationError:
                continue
            in_insn = False
            for stmt in vex.statements:
                if isinstance(stmt, IMark):
                    in_insn = stmt.addr == acc.location.ins_addr
                elif (
                    in_insn
                    and isinstance(stmt, WrTmp)
                    and isinstance(stmt.data, Load)
                    and stmt.data.ty in {"Ity_F32", "Ity_F64"}
                ):
                    return True
        return False

    def _fp_reg_ranges(self) -> list[tuple[int, int]]:
        """Return (offset, offset+size) ranges for all FP arg/return registers
        defined by the calling convention.  Cached after first call."""
        if not hasattr(self, "_fp_reg_ranges_cache"):
            ranges = []
            cc = default_cc_for_project(self.project)
            if cc is not None:
                for reg_name in list(cc.FP_ARG_REGS or []) + (
                    [cc.FP_RETURN_VAL.reg_name]
                    if cc.FP_RETURN_VAL is not None
                    and isinstance(cc.FP_RETURN_VAL, SimRegArg)
                    and cc.FP_RETURN_VAL.reg_name in self.project.arch.registers
                    else []
                ):
                    if reg_name in self.project.arch.registers:
                        off, sz = self.project.arch.registers[reg_name]
                        ranges.append((off, off + sz))
            self._fp_reg_ranges_cache = ranges
        return self._fp_reg_ranges_cache

    def _is_fp_reg_offset(self, reg_offset: int | None) -> bool:
        """Check if a register offset falls within any FP register range."""
        if reg_offset is None:
            return False
        return any(lo <= reg_offset < hi for lo, hi in self._fp_reg_ranges())

    def _normalize_fp_reg_name(self, reg_offset: int) -> str | None:
        """Normalize a sub-register offset to the canonical FP register name."""
        for lo, hi in self._fp_reg_ranges():
            if lo <= reg_offset < hi:
                return self.project.arch.translate_register_name(lo, size=hi - lo)
        return None

    def _consolidate_input_args(
        self, input_args: set[SimRegArg | SimStackArg], for_matching: bool = True
    ) -> set[SimRegArg | SimStackArg]:
        """
        Normalize FP sub-registers (``xmm0lq`` -> ``xmm0``, ``s0`` -> ``d0``) so they match FP_ARG_REGS, and on
        AMD64/X86 expand GPR sub-registers (``edi`` -> ``rdi``).

        On S390X with ``for_matching``, also expand GPR sub-registers (``r2_32`` -> ``r2``) and move stack args that
        sit in the low half of a big-endian 8-byte slot (``[0xa4]``) to the slot (``[0xa0]``), which is what
        ``SimCC._match`` knows.
        """

        if isinstance(self.project.arch, archinfo.ArchS390X):
            return self._consolidate_input_args_s390x(input_args, for_matching)

        if self.project.arch.name in {"AMD64", "X86", "AARCH64"}:
            new_input_args = set()
            for a in input_args:
                if not isinstance(a, SimRegArg):
                    new_input_args.add(a)
                    continue
                reg_offset, reg_size = self.project.arch.registers[a.reg_name]
                if self._is_fp_reg_offset(reg_offset):
                    fp_reg_name = self._normalize_fp_reg_name(reg_offset)
                    if fp_reg_name is not None:
                        arg = SimRegArg(fp_reg_name, min(a.size, 8))
                        if arg not in new_input_args:
                            new_input_args.add(arg)
                        continue
                elif a.size < self.project.arch.bytes and self.project.arch.name != "AARCH64":
                    full_reg_offset, full_reg_size = get_reg_offset_base_and_size(
                        reg_offset, self.project.arch, size=reg_size
                    )
                    full_reg_name = self.project.arch.translate_register_name(full_reg_offset, size=full_reg_size)
                    arg = SimRegArg(full_reg_name, full_reg_size)
                    if arg not in new_input_args:
                        new_input_args.add(arg)
                    continue
                new_input_args.add(a)
            return new_input_args

        return set(input_args)

    def _consolidate_input_args_s390x(
        self, input_args: set[SimRegArg | SimStackArg], for_matching: bool
    ) -> set[SimRegArg | SimStackArg]:
        arch = self.project.arch
        slot = arch.bytes
        stack_base = SimCCS390X.STACKARG_SP_BUFF
        new_input_args: set[SimRegArg | SimStackArg] = set()
        for a in input_args:
            if isinstance(a, SimRegArg):
                reg_offset, reg_size = arch.registers[a.reg_name]
                if self._is_fp_reg_offset(reg_offset):
                    fp_reg_name = self._normalize_fp_reg_name(reg_offset)
                    if fp_reg_name is not None:
                        new_input_args.add(SimRegArg(fp_reg_name, min(a.size, 8)))
                        continue
                elif for_matching and a.size < slot:
                    full_offset, full_size = get_reg_offset_base_and_size(reg_offset, arch, size=reg_size)
                    full_name = arch.translate_register_name(full_offset, size=full_size)
                    new_input_args.add(SimRegArg(full_name, full_size))
                    continue
            elif for_matching and a.size < slot and a.stack_offset >= stack_base:
                slot_offset = a.stack_offset - (a.stack_offset - stack_base) % slot
                if a.stack_offset + a.size == slot_offset + slot:
                    new_input_args.add(SimStackArg(slot_offset, slot, is_fp=a.is_fp))
                    continue
            new_input_args.add(a)
        return new_input_args

    def _apply_i386_cdecl_fp_arg_adjustments(
        self, args: list[SimRegArg | SimStackArg]
    ) -> list[SimRegArg | SimStackArg]:
        """Resolve i386 cdecl FP stack arguments.

        i386 cdecl passes doubles as two adjacent 4-byte slots and floats as a
        single 4-byte slot. The default classifier doesn't distinguish these
        from arbitrary int args, so we apply two post-passes specific to X86:

        1. Merge adjacent 4-byte slots into 8-byte doubles when we can prove
           (via F64 loads or callee prototypes) that those slots form a double.
        2. Tag remaining solitary 4-byte slots as floats when the function
           manipulates the x87 register file and the slot was forwarded
           individually to a callee (preventing merge in step 1).
        """
        # Step 1: merge 4-byte pairs that form doubles.
        if not any(isinstance(a, SimStackArg) and a.size == 8 for a in args):
            double_bp_pairs = self._find_double_arg_pairs() or self._find_double_pairs_from_callee_protos(args)
            if double_bp_pairs:
                args = self._merge_stack_args_by_pairs(args, double_bp_pairs)

        # Step 2: tag solitary 4-byte slots as floats when the function uses x87.
        all_callsites = {**self._callsites, **self._pushed_arg_callsites}
        if self._function_has_fpreg_puti() and all_callsites:
            individually_passed = self._get_individually_passed_offsets(all_callsites)
            ret_addr_size = self.project.arch.bytes
            arg_offsets = {a.stack_offset for a in args if isinstance(a, SimStackArg)}
            for i, a in enumerate(args):
                if (
                    isinstance(a, SimStackArg)
                    and a.size == 4
                    and not a.is_fp
                    and (a.stack_offset + ret_addr_size) in individually_passed
                    and (a.stack_offset + 4) not in arg_offsets
                    and (a.stack_offset - 4) not in arg_offsets
                ):
                    args[i] = SimStackArg(a.stack_offset, a.size, is_fp=True)
        return args

    def _function_has_fpreg_puti(self) -> bool:
        """Check if any block in the function writes to the x87 FP register file."""
        fpreg_offset = self.project.arch.registers.get("fpreg", (None,))[0]
        if fpreg_offset is None:
            return False
        assert self._function is not None
        for block_node in self._function.graph.nodes():
            try:
                irsb = self.project.factory.block(block_node.addr, size=block_node.size).vex
            except Exception:
                continue
            for stmt in irsb.statements:
                if isinstance(stmt, PutI) and stmt.descr.base == fpreg_offset:
                    return True
        return False

    def _find_double_arg_pairs(self) -> set[tuple[int, int]]:
        """Trace F64 loads from local stack back to arg area copies.

        On i386 O0, the compiler copies double halves from the arg area to local
        stack, then does ``fldl [local]``.  By matching F64 loads to the 4-byte
        stores that populated those locals, we find the exact ebp-relative offset
        pairs that form actual double parameters.

        Returns a set of ``(bp_lo, bp_hi)`` tuples.
        """
        import pyvex

        # Pass 1: collect all local_offset -> arg_bp_offset mappings across all blocks
        local_to_arg: dict[int, int] = {}
        f64_local_offsets: list[int] = []
        assert self._function is not None
        for block_node in self._function.graph.nodes():
            try:
                vex = self.project.factory.block(block_node.addr, size=block_node.size).vex
            except Exception:
                continue
            tmps: dict[int, object] = {}
            for s in vex.statements:
                if isinstance(s, pyvex.IRStmt.WrTmp):
                    tmps[s.tmp] = s.data
                elif isinstance(s, pyvex.IRStmt.Store):
                    local_off = self._resolve_bp_offset(s.addr, tmps)
                    if local_off is not None and local_off < 0:
                        arg_off = self._resolve_load_bp_offset(s.data, tmps)
                        if arg_off is not None and arg_off > 0:
                            local_to_arg[local_off] = arg_off

            # Check if this block has FP conversion ops (F64toI32S etc.)
            has_fp_conv = any(
                isinstance(s, pyvex.IRStmt.WrTmp) and isinstance(s.data, pyvex.IRExpr.Binop) and "F64to" in s.data.op
                for s in vex.statements
            )
            # Collect 8-byte FP load offsets.  Ity_F64 (fldl) always qualifies.
            # Ity_I64 loads also qualify when the block has FP conversions
            # (e.g. fisttp loads the double as I64 then converts via F64toI32S),
            # unless the loaded value is itself converted from an integer (fild).
            f64_types = {"Ity_F64"}
            if has_fp_conv:
                f64_types.add("Ity_I64")
            int_to_fp_tmps = {
                s.data.args[1].tmp
                for s in vex.statements
                if isinstance(s, pyvex.IRStmt.WrTmp)
                and isinstance(s.data, pyvex.IRExpr.Binop)
                and s.data.op in ("Iop_I64StoF64", "Iop_I64UtoF64")
                and isinstance(s.data.args[1], pyvex.IRExpr.RdTmp)
            }
            for s in vex.statements:
                if (
                    isinstance(s, pyvex.IRStmt.WrTmp)
                    and isinstance(s.data, pyvex.IRExpr.Load)
                    and vex.tyenv.types[s.tmp] in f64_types
                    and s.tmp not in int_to_fp_tmps
                ):
                    local_off = self._resolve_bp_offset(s.data.addr, tmps)
                    if local_off is not None and local_off < 0:
                        f64_local_offsets.append(local_off)

        # Pass 2: match F64 loads to arg pairs
        pairs: set[tuple[int, int]] = set()
        for local_off in f64_local_offsets:
            lo = local_to_arg.get(local_off)
            hi = local_to_arg.get(local_off + 4)
            if lo is not None and hi is not None:
                pairs.add((lo, hi))
        return pairs

    def _find_double_pairs_from_callee_protos(self, args: list[SimRegArg | SimStackArg]) -> set[tuple[int, int]]:
        """Infer double arg pairs from callee prototypes.

        For pass-through functions that forward args to callees without F64
        loads, check if a callee expects a double.  If so, the adjacent
        4-byte arg pairs that the caller has at matching positions likely
        form doubles.

        This works because on i386 cdecl, double parameters occupy two
        adjacent 4-byte stack slots in both the caller's and callee's frame.
        """
        from angr.sim_type import SimTypeDouble, SimTypeLongDouble

        pairs: set[tuple[int, int]] = set()
        ret_addr_size = self.project.arch.bytes  # 4 on i386

        # Collect our own 4-byte stack arg offsets (bp-relative)
        our_stack_args = sorted(
            (a.stack_offset + ret_addr_size, a) for a in args if isinstance(a, SimStackArg) and a.size == 4
        )
        if len(our_stack_args) < 2:
            return pairs

        assert self._function is not None
        for cs_addr in self._function.get_call_sites():
            target = self._function.get_call_target(cs_addr)
            if target is None:
                continue
            callee = self.kb.functions.get(target)
            callee_proto = callee.get_prototype(self._flavor) if callee is not None else None
            if callee_proto is None:
                continue
            # Check if callee has any double parameters
            has_double = any(isinstance(a, (SimTypeDouble, SimTypeLongDouble)) for a in callee_proto.args)
            if not has_double:
                continue

            # The callee expects double(s).  Merge adjacent 4-byte arg pairs
            # in our own arg list.  This is safe because the function forwards
            # its args to a double-taking callee, confirming the pairs.
            i = 0
            while i < len(our_stack_args) - 1:
                bp_lo = our_stack_args[i][0]
                bp_hi = our_stack_args[i + 1][0]
                if bp_hi == bp_lo + 4:
                    pairs.add((bp_lo, bp_hi))
                    i += 2
                else:
                    i += 1
            break  # one callee with double is enough

        return pairs

    @staticmethod
    def _resolve_bp_offset(expr, tmps) -> int | None:
        """Resolve a VEX expression to an ebp-relative offset, or None."""
        import pyvex

        if isinstance(expr, pyvex.IRExpr.RdTmp) and expr.tmp in tmps:
            expr = tmps[expr.tmp]
        if isinstance(expr, pyvex.IRExpr.Binop) and "Add" in expr.op:
            for arg in expr.args:
                if isinstance(arg, pyvex.IRExpr.Const):
                    off = arg.con.value
                    if off > 0x7FFFFFFF:
                        off -= 0x100000000
                    return off
        return None

    @staticmethod
    def _resolve_load_bp_offset(expr, tmps) -> int | None:
        """If *expr* is LDle(ebp + offset), return the offset."""
        import pyvex

        if isinstance(expr, pyvex.IRExpr.RdTmp) and expr.tmp in tmps:
            expr = tmps[expr.tmp]
        if isinstance(expr, pyvex.IRExpr.Load):
            return CallingConventionAnalysis._resolve_bp_offset(expr.addr, tmps)
        return None

    @staticmethod
    def _merge_stack_args_by_pairs(
        args: list[SimRegArg | SimStackArg],
        double_bp_pairs: set[tuple[int, int]],
    ) -> list[SimRegArg | SimStackArg]:
        """Merge stack arg pairs identified by _find_double_arg_pairs.

        *double_bp_pairs* contains (bp_lo, bp_hi) tuples.  Convert to
        SimStackArg offsets (bp_off - ret_addr_size) and merge matching pairs.
        """
        ret_addr_size = 4  # i386
        # Build a map: stack_offset -> its pair's stack_offset
        merge_lo: dict[int, int] = {}
        for bp_lo, bp_hi in double_bp_pairs:
            so_lo = bp_lo - ret_addr_size
            so_hi = bp_hi - ret_addr_size
            merge_lo[so_lo] = so_hi

        merged_offsets: set[int] = set()
        result: list[SimRegArg | SimStackArg] = []
        for a in args:
            if isinstance(a, SimStackArg) and a.stack_offset in merge_lo:
                hi_offset = merge_lo[a.stack_offset]
                result.append(SimStackArg(a.stack_offset, 8, is_fp=True))
                merged_offsets.add(hi_offset)
            elif isinstance(a, SimStackArg) and a.stack_offset in merged_offsets:
                continue  # skip the high half
            else:
                result.append(a)
        return result

    @staticmethod
    def _get_individually_passed_offsets(callsites: dict) -> set[int]:
        """Return ebp-relative stack offsets passed individually (not paired) to callees."""
        individually_passed: set[int] = set()
        for _callee, cargs in callsites.values():
            bp_offsets = {carg[1] for carg in cargs if carg is not None and carg[0] == KIND_STACKVAL}
            for off in bp_offsets:
                if (off + 4) not in bp_offsets and (off - 4) not in bp_offsets:
                    individually_passed.add(off)
        return individually_passed

    @staticmethod
    def _merge_adjacent_stack_args_to_doubles(
        args: list[SimRegArg | SimStackArg],
        callsites: dict | None = None,
    ) -> list[SimRegArg | SimStackArg]:
        """Merge adjacent 4-byte stack arg pairs into 8-byte FP args.

        On i386 cdecl, O0-compiled code reads double parameters as two
        separate 4-byte loads.  When we know the function is FP (returns
        float/double), merge consecutive 4-byte stack arg pairs into 8-byte
        FP args.  Float (4-byte) args and long double (12-byte) args are
        left alone.

        Skip merging a pair when either half is passed individually to a
        callee (e.g. two separate float args passed to square_float).
        """
        individually_passed = (
            CallingConventionAnalysis._get_individually_passed_offsets(callsites) if callsites else set()
        )

        stack_args = sorted(
            [(i, a) for i, a in enumerate(args) if isinstance(a, SimStackArg) and a.size == 4 and not a.is_fp],
            key=lambda x: x[1].stack_offset,
        )
        merged_indices: set[int] = set()
        replacements: dict[int, SimStackArg] = {}
        # ret_addr_offset: on i386, SimStackArg.stack_offset is relative to
        # the return address; bp-relative = stack_offset + arch.bytes
        ret_addr_size = 4  # i386
        i = 0
        while i < len(stack_args) - 1:
            idx_lo, arg_lo = stack_args[i]
            idx_hi, arg_hi = stack_args[i + 1]
            if arg_hi.stack_offset == arg_lo.stack_offset + 4:
                # Check if either half is passed individually to a callee
                bp_lo = arg_lo.stack_offset + ret_addr_size
                bp_hi = arg_hi.stack_offset + ret_addr_size
                if bp_lo in individually_passed or bp_hi in individually_passed:
                    i += 1
                    continue
                # Adjacent pair -- merge into an 8-byte FP arg
                replacements[idx_lo] = SimStackArg(arg_lo.stack_offset, 8, is_fp=True)
                merged_indices.add(idx_hi)
                i += 2
            else:
                i += 1
        if not merged_indices:
            return args
        result = []
        for i, a in enumerate(args):
            if i in merged_indices:
                continue
            if i in replacements:
                result.append(replacements[i])
            else:
                result.append(a)
        return result

    def _library_prototype_by_name(self) -> SimTypeFunction | None:
        """
        Find a library prototype whose name matches the function name. Libraries of the function's own binary are
        preferred; otherwise all non-syscall libraries are searched in name order (local copies of libc functions).
        """
        assert self._function is not None
        name = self._function.name
        binary_name = self._function.binary_name
        own = SIM_LIBRARIES.get(binary_name) if binary_name is not None else None
        if own is not None:
            libs = list(own)
        else:
            libs = []
            seen: set[int] = set()
            for lib_name in sorted(SIM_LIBRARIES):
                for lib in SIM_LIBRARIES[lib_name]:
                    if id(lib) not in seen and not isinstance(lib, SimSyscallLibrary):
                        seen.add(id(lib))
                        libs.append(lib)
        for lib in libs:
            if lib.has_prototype(name):
                proto = lib.get_prototype(name, arch=self.project.arch)
                if proto is not None:
                    return proto
        return None

    def _reorder_args_by_library_prototype(
        self, args: list[SimRegArg | SimStackArg], cc: SimCC
    ) -> list[SimRegArg | SimStackArg]:
        """
        When the int and FP argument registers form separate sequences, the register assignment does not encode how
        int and FP arguments interleave. If the function name matches a library prototype whose argument locations
        are exactly the recovered ones, take the argument order from that prototype.
        """
        if not cc.FP_ARG_REGS:
            return args
        has_fp = any(isinstance(a, SimRegArg) and a.reg_name in cc.FP_ARG_REGS for a in args)
        has_int = any(isinstance(a, SimRegArg) and a.reg_name not in cc.FP_ARG_REGS for a in args)
        if not (has_fp and has_int):
            return args
        proto = self._library_prototype_by_name()
        if proto is None or proto.variadic or len(proto.args) != len(args):
            return args
        try:
            lib_locs = cc.arg_locs(proto)
        except (TypeError, ValueError, NotImplementedError):
            return args

        arch = self.project.arch

        def _loc_key(loc: SimFunctionArgument) -> tuple[str, int] | None:
            if isinstance(loc, SimRegArg):
                off, size = arch.registers[loc.reg_name]
                return "reg", get_reg_offset_base(off + loc.reg_offset, arch, size)
            if isinstance(loc, SimStackArg):
                return "stack", loc.stack_offset
            return None

        arg_by_key: dict[tuple[str, int], SimRegArg | SimStackArg] = {}
        for a in args:
            k = _loc_key(a)
            if k is None or k in arg_by_key:
                return args
            arg_by_key[k] = a
        reordered = []
        for loc in lib_locs:
            k = _loc_key(loc)
            if k is None or k not in arg_by_key:
                return args
            reordered.append(arg_by_key.pop(k))
        return reordered if not arg_by_key else args

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

        arch = self.project.arch
        reg_args = []

        # reads of overlapping sub-registers (e.g., ch and cx) describe one argument
        regarg_by_span: dict[tuple[int, int], SimRegArg] = {}
        for arg in args:
            if isinstance(arg, SimRegArg):
                regarg_by_span[(arch.registers[arg.reg_name][0] + arg.reg_offset, arg.size)] = arg
        merged_reg_args: list[SimRegArg] = []
        for span in merge_overlapping_register_spans(arch, regarg_by_span):
            arg = regarg_by_span.get(span)
            if arg is None:
                arg = reg_arg_from_span(arch, span[0], span[1])
            merged_reg_args.append(arg)

        # split args into two lists
        int_args = []
        fp_args = []
        for arg in merged_reg_args:
            if cc.FP_ARG_REGS and arg.reg_name in cc.FP_ARG_REGS:
                fp_args.append(arg)
            else:
                int_args.append(arg)

        # stack args at the same offset describe one argument; keep the widest access
        stackarg_by_offset: dict[int, SimStackArg] = {}
        for arg in args:
            if isinstance(arg, SimStackArg):
                existing = stackarg_by_offset.get(arg.stack_offset)
                if existing is None or arg.size > existing.size:
                    stackarg_by_offset[arg.stack_offset] = arg
        initial_stack_args = [stackarg_by_offset[offset] for offset in sorted(stackarg_by_offset)]
        # ensure stack args are consecutive if necessary
        if cc.STACKARG_SP_DIFF is not None and initial_stack_args:
            arg_by_offset = {a.stack_offset: a for a in initial_stack_args}
            init_stackarg_offset = cc.STACKARG_SP_DIFF + cc.STACKARG_SP_BUFF
            int_arg_size = cc.arg_slot_size
            covered = set()
            for a in initial_stack_args:
                # a narrow arg may sit at the end of its slot (big-endian)
                slot_start = a.stack_offset - (a.stack_offset - init_stackarg_offset) % int_arg_size
                for off in range(slot_start, a.stack_offset + a.size, int_arg_size):
                    covered.add(off)
            for stackarg_offset in range(init_stackarg_offset, max(arg_by_offset), int_arg_size):
                if stackarg_offset not in arg_by_offset and stackarg_offset not in covered:
                    arg_by_offset[stackarg_offset] = SimStackArg(stackarg_offset, int_arg_size)
            stack_args = [arg_by_offset[offset] for offset in sorted(arg_by_offset)]
        else:
            stack_args = initial_stack_args

        stack_int_args = [a for a in stack_args if not a.is_fp]

        if cc.SHARED_ARG_SLOTS:
            # slot i is ARG_REGS[i] or FP_ARG_REGS[i]; an unread slot before a later argument is padded
            slots = list(zip(cc.ARG_REGS, cc.FP_ARG_REGS))
            slot_args: list[SimRegArg | None] = []
            for int_reg_name, fp_reg_name in slots:
                arg = next(
                    (
                        a
                        for a in int_args + fp_args
                        if _is_same_reg(a.reg_name, int_reg_name) or _is_same_reg(a.reg_name, fp_reg_name)
                    ),
                    None,
                )
                slot_args.append(arg)
                if arg in int_args:
                    int_args.remove(arg)
                elif arg in fp_args:
                    fp_args.remove(arg)
            used = (
                len(slots) if stack_args else max((i + 1 for i, a in enumerate(slot_args) if a is not None), default=0)
            )
            reg_args = [
                a if a is not None else SimRegArg(slots[i][0], cc.arg_slot_size) for i, a in enumerate(slot_args[:used])
            ]
            return reg_args + int_args + fp_args + stack_args

        # match int args first
        for reg_name in cc.ARG_REGS:
            try:
                arg = next(iter(a for a in int_args if isinstance(a, SimRegArg) and _is_same_reg(a.reg_name, reg_name)))
            except StopIteration:
                # have we reached the end of the args list?
                if [a for a in int_args if isinstance(a, SimRegArg)] or len(stack_int_args) > 0:
                    # haven't reached the end yet or there are stack args
                    arg = SimRegArg(reg_name, cc.arg_slot_size)
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
                    # have we reached the end of the fp register args list?
                    # FP stack args (e.g. long double on AMD64) are memory-class and do not occupy XMM slots
                    if [a for a in fp_args if isinstance(a, SimRegArg)]:
                        arg = SimRegArg(reg_name, cc.arg_slot_size)
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
        if isinstance(arg, SimStackArg) and arg.is_fp:
            if arg.size <= 4:
                return SimTypeFloat()
            if arg.size <= 8:
                return SimTypeDouble()
            # 80-bit long double (stored as 12 or 16 bytes depending on ABI)
            return SimTypeLongDouble()

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
                elif func.get_prototype(self._flavor) is not None:
                    passed_ty = func.get_prototype(self._flavor).args[use]
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
                if isinstance(ptr_ty, SimTypeBottom) and self._pointer_arg_deref_sizes.get((key[0], key[1], 0)) == 10:
                    # only an x87 extended-precision value is 10 bytes wide
                    ptr_ty = SimTypeNum(80, signed=False)
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

        if arg.size == 12 and arg.is_fp:
            return SimTypeLongDouble()
        if arg.size == 8:
            if arg.is_fp:
                return SimTypeDouble()
            return SimTypeLongLong()
        if arg.size == 4:
            if arg.is_fp:
                return SimTypeFloat()
            return SimTypeInt()
        if arg.size == 2:
            return SimTypeShort()
        if arg.size == 1:
            return SimTypeChar()
        # Unsupported for now
        return SimTypeBottom()

    def _x87_scan(self) -> dict[int, int | None]:
        if self._x87_ret_ftops is None:
            assert self._function is not None
            ret_ftops, depth = X87StackModel(self.project, self.kb, max_callee_blocks=32, assume_balanced=True).scan(
                self._function
            )
            self._x87_args = X87StackModel.classify_x87_args(ret_ftops, depth)
            if ret_ftops is None or (depth and self._x87_args is None):
                # unknown, or values taken on the x87 stack with an inconsistent stack effect
                self._x87_ret_ftops = {}
            else:
                # relative to the stack top after the callee popped its x87 arguments
                n = self._x87_args[0] if self._x87_args is not None else 0
                self._x87_ret_ftops = {
                    addr: None if ftop is None else (ftop - n) % 8 for addr, ftop in ret_ftops.items()
                }
        return self._x87_ret_ftops

    def _x87_ret_ftop(self, ret_block_addr: int) -> int | None:
        """
        The x87 stack pointer at a return site of the function after its x87 arguments are popped (0 at its entry
        when it takes none; 7 when it leaves one value on the stack), or None when unknown.
        """
        return self._x87_scan().get(ret_block_addr)

    def _apply_x87_args(self, cc: SimCC, prototype: SimTypeFunction) -> SimTypeFunction:
        """Prepend the arguments the function takes on the x87 stack."""
        if self.project.arch.name != "X86":
            return prototype
        self._x87_scan()
        if self._x87_args is None:
            return prototype
        n = self._x87_args[0]
        cc.x87_args = n
        new_proto = copy.copy(prototype)
        new_proto.args = tuple(SimTypeDouble().with_arch(self.project.arch) for _ in range(n)) + tuple(prototype.args)
        if prototype.arg_names:
            new_proto.arg_names = ("",) * n + tuple(prototype.arg_names)
        if self._x87_args[1] and (prototype.returnty is None or isinstance(prototype.returnty, SimTypeBottom)):
            # the result is left in st(0), e.g. by a tail call, where the return-site scan does not see it
            new_proto.returnty = SimTypeDouble().with_arch(self.project.arch)
        return new_proto

    def _is_retval_incidental(self) -> bool:
        """See :attr:`FactCollector.retval_incidental`. Collected with the other facts in fact-collecting mode;
        computed on demand when the return value size came from variable recovery instead."""
        if self._retval_incidental is None:
            self._retval_incidental = (
                self._function is not None
                and self.project.analyses[FactCollector]
                .prep(kb=self.kb)(self._function, flavor=self._flavor)
                .retval_incidental
            )
        return self._retval_incidental

    def _guess_retval_type(self, cc: SimCC, ret_val_size: int | None) -> SimType:
        assert self._function is not None

        if cc.FP_RETURN_VAL and self._function.ret_sites:
            # examine the last block of the function and see which registers are assigned to
            fpreg_offset = self.project.arch.registers.get("fpreg", (None,))[0]
            # Compute the byte range for the FP return register so we can match sub-register
            # writes (e.g. Put(xmm0_lo64, f64_tmp) where reg_name resolves to "xmm0lq", not "xmm0").
            fp_ret_range: tuple[int, int] | None = None
            if isinstance(cc.FP_RETURN_VAL, SimRegArg) and cc.FP_RETURN_VAL.reg_name in self.project.arch.registers:
                _fp_ret_off, _fp_ret_sz = self.project.arch.registers[cc.FP_RETURN_VAL.reg_name]
                fp_ret_range = (_fp_ret_off, _fp_ret_off + _fp_ret_sz)
            for ret_block in self._function.ret_sites:
                fpretval_updated, retval_updated, fpreg_puti = False, False, False
                fp_reg_size = 0
                try:
                    irsb = self.project.factory.block(ret_block.addr, size=ret_block.size).vex
                except SimTranslationError:
                    # failed to lift the block
                    continue
                x87_pushed = False
                # Collect tmp definitions so we can trace what feeds the return reg
                tmp_defs: dict[int, object] = {}
                for stmt in irsb.statements:
                    if isinstance(stmt, WrTmp):
                        tmp_defs[stmt.tmp] = stmt.data
                # index of the last write to the integer return register in this block, and the width of that value
                # if the last FP return register write derives from it
                retval_put_idx: int | None = None
                staged_size: int | None = None
                for stmt_idx, stmt in enumerate(irsb.statements):
                    if isinstance(stmt, Put) and isinstance(stmt.data, (RdTmp, VexConst)):
                        if isinstance(stmt.data, RdTmp):
                            reg_size = irsb.tyenv.sizeof(stmt.data.tmp) // self.project.arch.byte_width  # type: ignore
                        else:
                            reg_size = stmt.data.result_size(irsb.tyenv) // self.project.arch.byte_width
                        reg_name = self.project.arch.translate_register_name(stmt.offset, size=reg_size)
                        # Match the FP return register by name OR by offset range (handles sub-register
                        # writes such as Put(xmm0+0, f64_tmp) where reg_name is "xmm0lq" not "xmm0").
                        fp_ret_match = isinstance(cc.FP_RETURN_VAL, SimRegArg) and (
                            reg_name == cc.FP_RETURN_VAL.reg_name
                            or (fp_ret_range is not None and fp_ret_range[0] <= stmt.offset < fp_ret_range[1])
                        )
                        if fp_ret_match and self._is_f128_high_half(stmt.data, tmp_defs):
                            # the high half of a long double in an FP register pair (s390x): long double is
                            # returned through a hidden pointer, so this is not an FP return value
                            pass
                        elif fp_ret_match:
                            fpretval_updated = True
                            fp_reg_size = reg_size
                            # For V128 writes (e.g. PUT(xmm0) = Mul32F0x4_result), the size is
                            # 16 bytes regardless of the scalar element type.  Trace back through
                            # tmp definitions to determine whether the scalar operation was float
                            # (F0x4 / F32) or double (F0x2 / F64) so we can return the right type.
                            if fp_reg_size == 16 and isinstance(stmt.data, RdTmp):
                                traced = self._trace_vex_fp_elem_size(tmp_defs, stmt.data.tmp)
                                if traced is not None:
                                    fp_reg_size = traced
                            # `or rax, rdx; movq xmm0, rax`: the bit pattern was assembled in the integer return
                            # register and moved into the FP one, so rax was only staging the return value
                            staged_size = (
                                self._int_retval_feeds_fp_write(irsb, stmt.data, retval_put_idx)
                                if retval_updated and retval_put_idx is not None
                                else None
                            )
                        elif isinstance(cc.RETURN_VAL, SimRegArg) and reg_name == cc.RETURN_VAL.reg_name:
                            retval_put_idx = stmt_idx
                            staged_size = None
                            if isinstance(stmt.data, VexConst):
                                # Constant write (e.g. return 0) is always a real return value
                                retval_updated = True
                            else:
                                # Check if the value written to the return register comes from
                                # a stack/memory load (likely stack canary) vs a computation.
                                # On O0, stack canary checks write eax from a memory load in
                                # the return block, which looks like a return value to us.
                                data_src = tmp_defs.get(stmt.data.tmp, stmt.data)
                                if isinstance(data_src, Load):
                                    # Memory load -> likely stack canary, not a real return
                                    pass
                                else:
                                    retval_updated = True
                    elif isinstance(stmt, PutI) and fpreg_offset is not None:
                        # x87 PutI to the FP register array indicates an FP return value
                        if stmt.descr.base == fpreg_offset:
                            fpreg_puti = True
                            ret_ftop = self._x87_ret_ftop(ret_block.addr)
                            if ret_ftop is None or ret_ftop == 7:
                                x87_pushed = ret_ftop == 7
                                fpretval_updated = True
                                fp_reg_size = {"Ity_F64": 8, "Ity_F32": 4}.get(stmt.descr.elemTy, 8)

                if staged_size is not None:
                    retval_updated = False
                    if fp_reg_size == 16:
                        fp_reg_size = staged_size

                # If the return block itself has no FP write, check predecessors.
                # This handles cases like fp_recursive where the FP return value is
                # written in a predecessor block and the return block only does
                # stack cleanup + ret.  We check both x87 PutI and vector register Put.
                if not fpretval_updated:
                    # First pass: direct predecessors (most common case + callee call detection)
                    for pred in self._function.graph.predecessors(ret_block):
                        try:
                            pred_irsb = self.project.factory.block(pred.addr, size=pred.size).vex
                        except SimTranslationError:
                            continue
                        pred_tmp_defs: dict[int, object] = {}
                        for stmt in pred_irsb.statements:
                            if isinstance(stmt, WrTmp):
                                pred_tmp_defs[stmt.tmp] = stmt.data
                        for stmt in pred_irsb.statements:
                            # x87: PutI to the FP register file
                            if fpreg_offset is not None and isinstance(stmt, PutI) and stmt.descr.base == fpreg_offset:
                                fpreg_puti = True
                                ret_ftop = self._x87_ret_ftop(ret_block.addr)
                                if ret_ftop is None or ret_ftop == 7:
                                    x87_pushed = ret_ftop == 7
                                    fpretval_updated = True
                                    fp_reg_size = {"Ity_F64": 8, "Ity_F32": 4}.get(stmt.descr.elemTy, 8)
                                break
                            # Vector Put to the FP return register (e.g. xmm0) or a sub-register
                            if (
                                fp_ret_range is not None
                                and isinstance(stmt, Put)
                                and isinstance(stmt.data, RdTmp)
                                and fp_ret_range[0] <= stmt.offset < fp_ret_range[1]
                                and not self._is_f128_high_half(stmt.data, pred_tmp_defs)
                            ):
                                byte_width = self.project.arch.byte_width
                                reg_size = pred_irsb.tyenv.sizeof(stmt.data.tmp) // byte_width  # type: ignore
                                fpretval_updated = True
                                fp_reg_size = reg_size
                                if fp_reg_size == 16:
                                    traced = self._trace_vex_fp_elem_size(pred_tmp_defs, stmt.data.tmp)
                                    if traced is not None:
                                        fp_reg_size = traced
                                break
                        # Also check: if the predecessor ends with a call to an
                        # FP-returning function (e.g. chained_fp_calls -> call
                        # double_identity -> ret), the callee's FP return value
                        # becomes our return value.
                        if not fpretval_updated and pred_irsb.jumpkind == "Ijk_Call":
                            callee_addr = pred_irsb.next.con.value if hasattr(pred_irsb.next, "con") else None
                            if callee_addr is not None:
                                callee_func = self.project.kb.functions.function(addr=callee_addr)
                                if (
                                    callee_func is not None
                                    and callee_func.get_prototype(self._flavor) is not None
                                    and isinstance(
                                        callee_func.get_prototype(self._flavor).returnty, (SimTypeFloat, SimTypeDouble)
                                    )
                                ):
                                    ret_ftop = (
                                        self._x87_ret_ftop(ret_block.addr)
                                        if X87StackModel.prototype_returns_x87(callee_func)
                                        else None
                                    )
                                    # an x87 return value that is popped before our return is not passed through
                                    if ret_ftop is None or ret_ftop == 7:
                                        x87_pushed = ret_ftop == 7
                                        fpretval_updated = True
                                        fp_reg_size = 8
                        if fpretval_updated:
                            break

                # Second pass: for functions with vector FP registers and complex CFGs, the FP return value may be
                # written in a block that is not a direct predecessor of the ret block (e.g. inside a loop body).
                # Gated on the CC capability flag: only conventions with dedicated FP registers permit a whole-function
                # scan (on ARM VFP is used for general computation, which would yield false positives).
                # A function that deliberately sets the integer return register on its way to ret (a parser that
                # does FP math internally and returns status flags) does not return in xmm0: the scan only runs when
                # no non-incidental integer return value is known.
                default_cc_cls = default_cc_for_project(self.project)
                whole_fn_fp_scan = default_cc_cls is not None and default_cc_cls.FP_RET_WHOLE_FUNCTION_SCAN
                if (
                    not fpretval_updated
                    and fp_ret_range is not None
                    and whole_fn_fp_scan
                    and (ret_val_size is None or self._is_retval_incidental())
                ):
                    elem_size = self._vex_function_fp_elem_size(fp_ret_range)
                    if elem_size is not None:
                        fpretval_updated = True
                        fp_reg_size = elem_size

                if fpretval_updated and (not retval_updated or x87_pushed):
                    if fp_reg_size == 4:
                        return SimTypeFloat()
                    # x87 always uses F64 internally.  An explicit F64->F32
                    # truncation in the VEX IR (e.g. fstp dword; fld dword)
                    # is the only reliable signal that the return is float.
                    if self._function_has_f64_to_f32():
                        return SimTypeFloat()
                    # Long double detection: if the x87 FP register file was
                    # written (PutI to fpreg) but the CC's FP return register
                    # (xmm0 on AMD64) was NOT explicitly written, the function
                    # returns via ST0 -> long double.  On i386 (where FP_RETURN_VAL
                    # is st0, not a real register), fall back to the loadF80le
                    # heuristic.
                    if (
                        fpreg_puti
                        and isinstance(cc.FP_RETURN_VAL, SimRegArg)
                        and cc.FP_RETURN_VAL.reg_name in self.project.arch.registers
                    ):
                        fp_ret_offset = self.project.arch.registers[cc.FP_RETURN_VAL.reg_name][0]
                        fp_ret_written = any(isinstance(s, Put) and s.offset == fp_ret_offset for s in irsb.statements)
                        if not fp_ret_written:
                            # x87 FP stack written but FP return register (e.g.
                            # xmm0 on AMD64) not written -> returns via ST0
                            return SimTypeLongDouble()
                    elif self._function_returns_long_double():
                        # i386 fallback: FP_RETURN_VAL is st0 (not a real
                        # register in archinfo), so use loadF80le heuristic
                        return SimTypeLongDouble()
                    # If ALL FP arguments are 4 bytes (float) and none are
                    # 8 bytes (double), infer float return.  On SSE, xorps-based
                    # negation has no FP-typed VEX ops, so the only precision
                    # signal is the arg size.
                    if self._input_args:
                        fp_arg_sizes = [
                            a.size
                            for a in self._input_args
                            if isinstance(a, SimRegArg)
                            and self._is_fp_reg_offset(self.project.arch.registers.get(a.reg_name, (None,))[0])
                        ]
                        if fp_arg_sizes and all(s == 4 for s in fp_arg_sizes):
                            return SimTypeFloat()
                    return SimTypeDouble()

        if ret_val_size is not None:
            if ret_val_size == 1:
                return SimTypeChar()
            if ret_val_size == 2:
                return SimTypeShort()
            if 3 <= ret_val_size <= 4:
                return SimTypeInt()
            if 5 <= ret_val_size <= 8:
                return SimTypeLongLong()
            # Go returns two-word values (strings, slices, interfaces, (T, error) pairs) in RAX:RBX
            if (self.project.is_rust_binary or self.project.is_go_binary) and 9 <= ret_val_size <= 16:
                return SimTypeInt128()

        # If the CC has a real FP return register (not x87 stack) and the function
        # has FP register args but neither the integer nor FP return register is
        # written, the function likely returns its FP input unchanged (passthrough).
        if (
            self._input_args
            and isinstance(cc.FP_RETURN_VAL, SimRegArg)
            and cc.FP_RETURN_VAL.reg_name in self.project.arch.registers
        ):
            fp_ret_offset = self.project.arch.registers[cc.FP_RETURN_VAL.reg_name][0]
            for arg in self._input_args:
                if isinstance(arg, SimRegArg) and arg.reg_name in self.project.arch.registers:
                    arg_offset = self.project.arch.registers[arg.reg_name][0]
                    if arg_offset == fp_ret_offset:
                        # xmm0 is both an input arg and the FP return register
                        return SimTypeDouble()

        return SimTypeBottom(label="void")

    def _int_retval_feeds_fp_write(self, irsb, data, retval_put_idx: int) -> int | None:
        """Whether the value written to the FP return register derives from the integer return register as written
        by the Put at ``retval_put_idx`` (its tmp or constant, or a later read of the register). Returns the byte
        width of the value moved (the narrowest scalar on the way, 4 for `movd xmm0, eax`), else None."""
        arch = self.project.arch
        assert arch.ret_offset is not None
        ret_lo, ret_hi = arch.ret_offset, arch.ret_offset + arch.bytes
        retval_src = irsb.statements[retval_put_idx].data
        tmp_defs: dict[int, tuple[int, IRExpr]] = {
            s.tmp: (idx, s.data) for idx, s in enumerate(irsb.statements) if isinstance(s, WrTmp)
        }
        seen: set[int] = set()
        # (expression, narrowest integer width seen on the path to it)
        worklist: list[tuple[IRExpr, int]] = [(data, arch.bytes)]
        while worklist:
            expr, width = worklist.pop()
            size = expr.result_size(irsb.tyenv) // arch.byte_width
            if size <= arch.bytes:
                width = min(width, size)
            if isinstance(expr, VexConst):
                # zero is too common on both sides (`xor eax, eax` next to `pxor xmm0, xmm0`) to mean anything
                if isinstance(retval_src, VexConst) and expr.con.value == retval_src.con.value and expr.con.value != 0:
                    return width
            elif isinstance(expr, RdTmp):
                if isinstance(retval_src, RdTmp) and expr.tmp == retval_src.tmp:
                    return width
                if expr.tmp in seen or expr.tmp not in tmp_defs:
                    continue
                seen.add(expr.tmp)
                def_idx, def_expr = tmp_defs[expr.tmp]
                # a register read is the written value only when it follows the write
                if not (isinstance(def_expr, Get) and def_idx < retval_put_idx):
                    worklist.append((def_expr, width))
            elif isinstance(expr, Get):
                if ret_lo <= expr.offset < ret_hi:
                    return width
            elif isinstance(expr, (Unop, Binop, Triop, Qop)):
                worklist.extend((arg, width) for arg in expr.args)
        return None

    @staticmethod
    def _is_f128_high_half(data, tmp_defs: dict) -> bool:
        """Whether a VEX expression (through one tmp) is F128HItoF64, the high half of a binary128 value."""
        if isinstance(data, RdTmp):
            data = tmp_defs.get(data.tmp, data)
        return isinstance(data, Unop) and data.op == "Iop_F128HItoF64"

    @staticmethod
    def _trace_vex_fp_elem_size(tmp_defs: dict, start_tmp: int) -> int | None:
        """Return 4 (float) or 8 (double) by tracing the VEX op that produced *start_tmp*.

        VEX scalar-in-vector float ops have "F0x4" in the op name; double ops have "F0x2".
        We also recognise plain "F32" / "F64" suffixes (e.g. IToF32, IToF64) for conversion ops.
        """
        import pyvex

        seen: set[int] = set()
        queue = [start_tmp]
        while queue:
            t = queue.pop(0)
            if t in seen:
                continue
            seen.add(t)
            expr = tmp_defs.get(t)
            if expr is None:
                continue
            if isinstance(expr, (pyvex.IRExpr.Unop, pyvex.IRExpr.Binop, pyvex.IRExpr.Triop)):
                op = expr.op
                if "F0x4" in op or ("F32" in op and "F64" not in op):
                    return 4
                if "F0x2" in op or "F64" in op:
                    return 8
            # Recurse into arguments
            if hasattr(expr, "args"):
                for arg in expr.args:
                    if isinstance(arg, pyvex.IRExpr.RdTmp):
                        queue.append(arg.tmp)
        return None

    def _vex_function_fp_elem_size(self, fp_ret_range: tuple[int, int]) -> int | None:
        """Scan all function blocks for VEX vector FP operations that write to the FP
        return register (*fp_ret_range* is the byte range ``[lo, hi)`` of that register).

        Returns 4 for float (F0x4 ops), 8 for double (F0x2 ops), or None if not detected.
        Double (F0x2) takes priority over float (F0x4) when both are present -- a function
        that promotes its result to double should be typed as double.
        """

        has_float_op = False
        has_double_op = False

        assert self._function is not None
        for block_node in self._function.graph.nodes():
            try:
                irsb = self.project.factory.block(block_node.addr, size=block_node.size).vex
            except Exception:
                continue
            tmp_defs: dict[int, object] = {}
            for stmt in irsb.statements:
                if isinstance(stmt, WrTmp):
                    tmp_defs[stmt.tmp] = stmt.data
            for stmt in irsb.statements:
                if (
                    isinstance(stmt, Put)
                    and isinstance(stmt.data, RdTmp)
                    and fp_ret_range[0] <= stmt.offset < fp_ret_range[1]
                ):
                    reg_size = irsb.tyenv.sizeof(stmt.data.tmp) // self.project.arch.byte_width  # type: ignore
                    if reg_size in (4, 8):
                        # Direct sub-register size tells us the element type
                        if reg_size == 4:
                            has_float_op = True
                        else:
                            has_double_op = True
                    elif reg_size == 16:
                        # V128 Put: trace the source op to determine element type
                        traced = self._trace_vex_fp_elem_size(tmp_defs, stmt.data.tmp)
                        if traced == 4:
                            has_float_op = True
                        elif traced == 8:
                            has_double_op = True

        if has_double_op:
            return 8
        if has_float_op:
            return 4
        return None

    def _function_has_f64_to_f32(self) -> bool:
        """Check whether the function contains an explicit F64->F32 conversion.

        This is the only reliable binary-level signal that a function returns
        ``float`` rather than ``double`` on x87, since VEX emulates x87 with
        F64 and the element type in PutI descriptors is always ``Ity_F64``.
        """
        import pyvex

        assert self._function is not None
        for block_node in self._function.graph.nodes():
            try:
                irsb = self.project.factory.block(block_node.addr, size=block_node.size).vex
            except Exception:
                continue
            for stmt in irsb.statements:
                if (
                    isinstance(stmt, pyvex.IRStmt.WrTmp)
                    and isinstance(stmt.data, (pyvex.IRExpr.Unop, pyvex.IRExpr.Binop))
                    and "F64toF32" in stmt.data.op
                ):
                    return True
        return False

    def _function_returns_long_double(self) -> bool:
        """Check whether the function returns long double (x87 extended precision).

        A function returns long double when it uses ``loadF80le`` (indicating
        long-double parameters) and does NOT round through 64-bit memory before
        returning.  The round-trip pattern (``fstp qword; fld qword``) appears
        in VEX as an ``STle`` of an F64 value followed by ``LDle:F64`` from
        the same address -- this truncates 80-bit precision to 64-bit, signaling
        a ``double`` return.
        """
        import pyvex

        has_loadF80le = False
        has_f64_roundtrip = False

        assert self._function is not None
        for block_node in self._function.graph.nodes():
            try:
                irsb = self.project.factory.block(block_node.addr, size=block_node.size).vex
            except Exception:
                continue
            for stmt in irsb.statements:
                if isinstance(stmt, pyvex.IRStmt.Dirty) and "loadF80le" in stmt.cee.name:
                    has_loadF80le = True
                # Detect fstpl/fstps (STle of x87 F64/F32) followed by fldl/flds
                # (LDle:F64/F32) anywhere in the function -- the fstp qword; fld qword
                # pattern truncates 80-bit precision to 64-bit, indicating a double
                # return.  We check for any x87 FP store plus any F64 load rather
                # than matching addresses exactly, because addresses are typically
                # computed expressions (e.g. ebp-0x20) whose VEX tmps differ between
                # the store and the reload.  The store data is checked by type (the
                # x87 value is wrapped in an ITE, so the direct data is an RdTmp
                # whose type is F64, not a bare GetI).
                if isinstance(stmt, pyvex.IRStmt.Store):
                    store_data_type = None
                    if isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                        with contextlib.suppress(Exception):
                            store_data_type = irsb.tyenv.lookup(stmt.data.tmp)
                    elif isinstance(stmt.data, pyvex.IRExpr.GetI):
                        store_data_type = "Ity_F64"
                    if store_data_type in ("Ity_F64", "Ity_F32"):
                        for stmt2 in irsb.statements:
                            if (
                                isinstance(stmt2, pyvex.IRStmt.WrTmp)
                                and isinstance(stmt2.data, pyvex.IRExpr.Load)
                                and irsb.tyenv.lookup(stmt2.tmp) in ("Ity_F64", "Ity_F32")
                            ):
                                has_f64_roundtrip = True

        return has_loadF80le and not has_f64_roundtrip

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

    def has_va_xmm_save_area_amd64(self, func: Function) -> bool:
        """
        Detect the va_start prologue idiom that spills xmm0-xmm7 into the register save area
        (``test al, al; je ...; movaps [base+disp+16*i], xmm_i`` for i in 0..7).
        """

        xmm_regs = [
            capstone.x86.X86_REG_XMM0,
            capstone.x86.X86_REG_XMM1,
            capstone.x86.X86_REG_XMM2,
            capstone.x86.X86_REG_XMM3,
            capstone.x86.X86_REG_XMM4,
            capstone.x86.X86_REG_XMM5,
            capstone.x86.X86_REG_XMM6,
            capstone.x86.X86_REG_XMM7,
        ]
        for blk in func.blocks:
            run: list[tuple[int, int]] = []  # (base, disp)
            for insn in blk.capstone.insns:
                if not (
                    insn.mnemonic == "movaps"
                    and len(insn.operands) == 2
                    and insn.operands[0].type == capstone.x86.X86_OP_MEM
                    and insn.operands[0].mem.base in (capstone.x86.X86_REG_RSP, capstone.x86.X86_REG_RBP)
                    and insn.operands[0].mem.index == 0
                    and insn.operands[1].type == capstone.x86.X86_OP_REG
                    and insn.operands[1].reg in xmm_regs
                ):
                    run = []
                    continue
                idx = xmm_regs.index(insn.operands[1].reg)
                base, disp = insn.operands[0].mem.base, insn.operands[0].mem.disp
                if idx == len(run) and (not run or (run[-1][0] == base and run[-1][1] + 16 == disp)):
                    run.append((base, disp))
                else:
                    run = [(base, disp)] if idx == 0 else []
                if len(run) == len(xmm_regs):
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
        head_block = self.project.factory.block(head.addr, size=head.size)
        if b"\x4c\x89" not in head_block.bytes:
            # the spills must end with mov [rsp/rbp+disp], r9 (4c 89 /r); skip disassembling blocks without one
            return False, None
        stores: list[tuple[int, int, int, int]] = []
        for i, insn in enumerate(head_block.capstone.insns):
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
            stores.append((i, idx, base, disp))

        if not stores or stores[-1][1] != len(allowed_spilled_regs) - 1:
            return False, None

        # the register save area run: contiguous +8 stores of consecutive arg registers ending at r9
        run_start = len(stores) - 1
        while run_start > 0:
            pi, pidx, pbase, pdisp = stores[run_start - 1]
            ci, cidx, cbase, cdisp = stores[run_start]
            if (pi, pidx, pbase, pdisp) != (ci - 1, cidx - 1, cbase, cdisp - 8):
                break
            run_start -= 1
        named_spills = stores[:run_start]
        run = stores[run_start:]

        base = run[0][2]
        disp_min = run[0][3]
        disp_max = run[-1][3]
        num_fixed = run[0][1]
        zero_disp = run[0][3] - 8 * num_fixed

        # earlier stores (gcc -O0) may only spill the named args, once each, outside the save area
        spilled_named: set[int] = set()
        for _, idx, sbase, sdisp in named_spills:
            if idx >= num_fixed or idx in spilled_named:
                return False, None
            if sbase == base and zero_disp <= sdisp < disp_max + 8:
                return False, None
            spilled_named.add(idx)
        if named_spills and len(run) < 2 and not self.has_va_xmm_save_area_amd64(func):
            # a lone r9 store after named spills also matches a plain six-arg -O0 prologue
            return False, None

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
