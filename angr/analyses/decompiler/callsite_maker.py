from __future__ import annotations

import copy
import logging
from typing import TYPE_CHECKING, Any, cast

import archinfo

from angr.ailment import Const, Expr, Stmt
from angr.ailment.manager import Manager
from angr.analyses.analysis import Analysis, register_analysis
from angr.analyses.s_reaching_definitions import SRDAView
from angr.calling_conventions import (
    SimCC,
    SimComboArg,
    SimFunctionArgument,
    SimReferenceArgument,
    SimRegArg,
    SimStackArg,
    SimStructArg,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
from angr.procedures.stubs.format_parser import FormatParser, FormatSpecifier
from angr.sim_type import (
    SimType,
    SimTypeBottom,
    SimTypeChar,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeInt,
    SimTypePointer,
)
from angr.utils.types import dereference_simtype_by_lib

from .stackarg_offset_manager import StackArgOffsetManager
from .variable_map import variable_map_of

if TYPE_CHECKING:
    from angr.analyses.s_reaching_definitions import SRDAModel
    from angr.knowledge_plugins.functions import Function
    from angr.knowledge_plugins.key_definitions.definition import Definition


l = logging.getLogger(name=__name__)


class CallSiteMaker(Analysis):
    """
    Add calling convention, declaration, and args to a call site.
    """

    def __init__(
        self, block, *, ail_manager: Manager, reaching_definitions: SRDAModel | None = None, stack_pointer_tracker=None
    ):
        self.block = block

        self._reaching_definitions = reaching_definitions
        self._stack_pointer_tracker = stack_pointer_tracker
        self._ail_manager: Manager = ail_manager
        self._call_stmt_idx = -1

        self.result_block = None
        # block addr, call ins addr, stack offset, arg size (in bytes)
        self.stackarg_offset_manager: StackArgOffsetManager = StackArgOffsetManager(self.project.arch.bits)
        self.removed_vvar_ids: set[int] = set()

        self._analyze()

    def _analyze(self):
        if not self.block.statements:
            return

        call_stmt_idx = len(self.block.statements) - 1
        while call_stmt_idx >= 0 and self.block.statements[call_stmt_idx].tags.get(
            "post_call_register_state_effect", False
        ):
            call_stmt_idx -= 1
        if call_stmt_idx < 0:
            self.result_block = self.block
            return
        self._call_stmt_idx = call_stmt_idx
        last_stmt = self.block.statements[call_stmt_idx]
        trailing_stmts = self.block.statements[call_stmt_idx + 1 :]

        if isinstance(last_stmt, Stmt.SideEffectStatement):
            call_expr = last_stmt.expr
        elif isinstance(last_stmt, Stmt.Assignment) and isinstance(last_stmt.src, Expr.Call):
            call_expr = last_stmt.src
        elif (
            isinstance(last_stmt, Stmt.Assignment)
            and isinstance(last_stmt.src, Expr.Convert)
            and isinstance(last_stmt.src.operand, Expr.Call)
        ):
            call_expr = last_stmt.src.operand
        elif (
            isinstance(last_stmt, Stmt.Assignment)
            and isinstance(last_stmt.src, Expr.Insert)
            and isinstance(last_stmt.src.value, Expr.Call)
        ):
            call_expr = last_stmt.src.value
        elif (
            isinstance(last_stmt, Stmt.Assignment)
            and isinstance(last_stmt.src, Expr.Extract)
            and isinstance(last_stmt.src.base, Expr.Call)
        ):
            call_expr = last_stmt.src.base
        else:
            self.result_block = self.block
            return

        custom_call = isinstance(call_expr.target, str)

        if call_expr.tags.get("indirect_far_call_dispatch", False) or call_expr.tags.get(
            "indirect_near_call_dispatch", False
        ):
            # Clinic has already replaced an exactly authorized dynamic CALLF
            # or CALL with a logical runtime ABI. Machine-level callsite facts
            # belong to the original target and must not guess a prototype,
            # return expression, or argument layout for the dispatcher.
            self.result_block = self.block
            return

        cc = None
        prototype: SimTypeFunction | None = None
        func = None
        stack_arg_locs: list[SimStackArg] = []
        stackarg_sp_diff = 0

        target = self._get_call_target(call_expr)
        if target is not None and target in self.kb.functions:
            # function-specific logic when the calling target is known
            func = self.kb.functions[target]

        # priority:
        # 0. manually-specified call-site prototype
        # 1. function-specific prototype
        # 2. automatically recovered call-site prototype

        # manually-specified call-site prototype
        has_callsite_prototype = self.kb.callsite_prototypes.has_prototype(self.block.addr)
        if custom_call and not has_callsite_prototype:
            # There is no machine-level ABI to apply to an opaque intrinsic. Preserve the original AIL exactly.
            self.result_block = self.block
            return
        if has_callsite_prototype:
            manually_specified = self.kb.callsite_prototypes.is_prototype_manual(self.block.addr)
            if manually_specified:
                cc = self.kb.callsite_prototypes.get_cc(self.block.addr)
                prototype = self.kb.callsite_prototypes.get_prototype(self.block.addr)

        # function-specific prototype
        if (cc is None or prototype is None) and func is not None:
            if func.prototype is None:
                func.find_declaration()
            cc = func.calling_convention
            prototype = func.prototype

        # automatically recovered call-site prototype
        if (cc is None or prototype is None) and has_callsite_prototype:
            cc = self.kb.callsite_prototypes.get_cc(self.block.addr)
            prototype = self.kb.callsite_prototypes.get_prototype(self.block.addr)

        # ensure the prototype has been resolved
        if prototype is not None and func is not None:
            # make sure the function prototype is resolved.
            # TODO: Cache resolved function prototypes globally
            prototype_libname = func.prototype_libname
            if prototype_libname is not None:
                prototype = cast(SimTypeFunction, dereference_simtype_by_lib(prototype, prototype_libname))

        # String-named intrinsics carry logical metadata arguments that are not passed through the machine calling
        # convention. Preserve them verbatim while still applying any per-callsite return-value fact below.
        args = list(call_expr.args) if custom_call and call_expr.args is not None else []
        arg_vvars = []
        arg_locs = None
        if cc is None:
            l.warning("Call site %#x (callee %s) has an unknown calling convention.", self.block.addr, repr(func))
        else:
            stackarg_sp_diff = cc.STACKARG_SP_DIFF
            if prototype is not None:
                # Make arguments
                arg_locs = cc.arg_locs(prototype)
                if prototype.variadic:
                    # determine the number of variadic arguments
                    assert func is not None
                    variadic_args = self._determine_variadic_arguments(func, cc, call_expr)
                    if variadic_args:
                        callsite_ty = copy.copy(prototype)
                        callsite_ty.args = tuple(callsite_ty.args) + tuple(variadic_args)
                        arg_locs = cc.arg_locs(callsite_ty)

        if arg_locs is not None and cc is not None and not custom_call:
            expanded_arg_locs = self._expand_arglocs(arg_locs)
            arguments_already_logical = call_expr.args is not None and len(call_expr.args) == len(arg_locs)
            if arguments_already_logical:
                # CallSiteMaker can run more than once in the decompilation pipeline. A prior run has already folded
                # every SimComboArg when the call carries exactly one expression per logical prototype argument.
                args.extend(call_expr.args)
                stack_arg_locs.extend(arg_loc for arg_loc in expanded_arg_locs if isinstance(arg_loc, SimStackArg))
            for arg_idx, arg_loc in enumerate(expanded_arg_locs):
                if arguments_already_logical:
                    break
                if call_expr.args is not None and arg_idx < len(call_expr.args):
                    args.append(call_expr.args[arg_idx])
                    continue
                if isinstance(arg_loc, SimReferenceArgument):
                    if not isinstance(arg_loc.ptr_loc, (SimRegArg, SimStackArg)):
                        raise NotImplementedError("Why would a calling convention produce this?")
                    if isinstance(arg_loc.main_loc, SimStructArg):
                        dereference_size = arg_loc.main_loc.struct.size // self.project.arch.byte_width
                    else:
                        dereference_size = arg_loc.main_loc.size
                    arg_loc = arg_loc.ptr_loc
                else:
                    dereference_size = None

                if isinstance(arg_loc, SimRegArg):
                    size = arg_loc.size
                    offset = arg_loc.check_offset(cc.arch)
                    value_and_def = self._resolve_register_argument(arg_loc)
                    if value_and_def is not None:
                        vvar_def = value_and_def[1]
                        arg_vvars.append(vvar_def)
                        vvar_use = Expr.VirtualVariable(
                            self._ail_manager.next_atom(),
                            vvar_def.varid,
                            vvar_def.bits,
                            vvar_def.category,
                            oident=vvar_def.oident,
                            **vvar_def.tags,
                        )
                        vvar_def_reg_offset = None
                        if vvar_def.was_reg:
                            vvar_def_reg_offset = vvar_def.reg_offset
                        elif (
                            vvar_def.was_parameter
                            and vvar_def.parameter_category == Expr.VirtualVariableCategory.REGISTER
                        ):
                            vvar_def_reg_offset = vvar_def.parameter_reg_offset

                        if vvar_def_reg_offset is not None and offset > vvar_def_reg_offset:
                            # we need to shift the value
                            vvar_use = Expr.BinaryOp(
                                self._ail_manager.next_atom(),
                                "Shr",
                                [
                                    vvar_use,
                                    Expr.Const(
                                        self._ail_manager.next_atom(),
                                        (offset - vvar_def_reg_offset) * 8,
                                        8,
                                    ),
                                ],
                                **vvar_use.tags,
                            )
                        if vvar_def.size > arg_loc.size:
                            # we need to narrow the value
                            vvar_use = Expr.Convert(
                                self._ail_manager.next_atom(),
                                vvar_use.bits,
                                arg_loc.size * self.project.arch.byte_width,
                                False,
                                vvar_use,
                                **vvar_use.tags,
                            )
                        arg_expr = vvar_use
                    else:
                        reg = Expr.Register(
                            self._atom_idx(),
                            offset,
                            size * 8,
                            reg_name=arg_loc.reg_name,
                            ins_addr=last_stmt.tags["ins_addr"],
                        )
                        arg_expr = reg
                elif isinstance(arg_loc, SimStackArg):
                    stack_arg_locs.append(arg_loc)
                    _, the_arg = self._resolve_stack_argument(
                        call_expr,
                        arg_loc,
                        stackarg_sp_diff,
                    )
                    arg_expr = the_arg if the_arg is not None else None
                elif isinstance(arg_loc, SimStructArg):
                    arg_expr = None
                    l.warning("SimStructArg is not yet supported")
                elif isinstance(arg_loc, SimComboArg):
                    arg_expr = None
                    l.warning("SimComboArg is not yet supported")
                else:
                    assert False, "Unreachable"

                if arg_expr is not None and dereference_size is not None:
                    arg_expr = Expr.Load(self._atom_idx(), arg_expr, dereference_size, endness=archinfo.Endness.BE)
                if arg_expr is not None:
                    args.append(arg_expr)

            # ``SimComboArg`` is one source-level argument spread across multiple ABI locations, ordered least-
            # significant piece first. The resolver above must visit the physical locations individually, but passing
            # those pieces to C as separate arguments changes both the prototype and the call ABI. Reassemble a combo
            # only when every physical location was recovered; otherwise leave the pieces visible so downstream
            # completeness checks can reject the malformed call instead of inventing missing bits.
            if (
                not arguments_already_logical
                and len(args) == len(expanded_arg_locs)
                and any(isinstance(arg_loc, SimComboArg) and not arg_loc.is_fp for arg_loc in arg_locs)
            ):
                logical_args: list[Expr.Expression] = []
                physical_idx = 0
                for arg_loc in arg_locs:
                    physical_locs = self._expand_arglocs([arg_loc])
                    physical_args = args[physical_idx : physical_idx + len(physical_locs)]
                    physical_idx += len(physical_locs)
                    if isinstance(arg_loc, SimComboArg) and not arg_loc.is_fp:
                        logical_args.append(self._combine_integer_argument(arg_loc, physical_args))
                    else:
                        logical_args.extend(physical_args)
                args = logical_args

        # Remove the old call statement
        new_stmts = self.block.statements[:call_stmt_idx]

        # remove the statement that stores the return address
        if self.project.arch.call_pushes_ret:
            # check if the last statement is storing the return address onto the top of the stack
            for stmt_idx_r, the_stmt in enumerate(reversed(new_stmts)):
                stmt_idx = len(new_stmts) - 1 - stmt_idx_r
                if isinstance(the_stmt, Stmt.SideEffectStatement):
                    break
                if isinstance(the_stmt, Stmt.Assignment):
                    if not (isinstance(the_stmt.dst, Expr.VirtualVariable) and the_stmt.dst.was_stack):
                        continue
                    src = the_stmt.src
                    varid = the_stmt.dst.varid
                elif isinstance(the_stmt, Stmt.Store):
                    src = the_stmt.data
                    varid = None
                else:
                    continue
                if isinstance(src, Expr.Const) and src.value == self.block.addr + self.block.original_size:
                    # yes it is!
                    if varid is not None:
                        self.removed_vvar_ids.add(varid)
                    new_stmts = new_stmts[:stmt_idx] + new_stmts[stmt_idx + 1 :]
                    break
        else:
            # if there is an lr register...
            lr_offset = None
            if archinfo.arch_arm.is_arm_arch(self.project.arch) or self.project.arch.name in {"PPC32", "PPC64"}:
                lr_offset = self.project.arch.registers["lr"][0]
            elif self.project.arch.name in {"MIPS32", "MIPS64"}:
                lr_offset = self.project.arch.registers["ra"][0]
            # remove the assignment to the lr register
            if lr_offset is not None:
                for stmt_idx_r, the_stmt in enumerate(reversed(new_stmts)):
                    stmt_idx = len(new_stmts) - 1 - stmt_idx_r
                    if isinstance(the_stmt, Stmt.SideEffectStatement):
                        break
                    if not isinstance(the_stmt, Stmt.Assignment):
                        continue
                    if isinstance(the_stmt.dst, Expr.Register) and the_stmt.dst.reg_offset == lr_offset:
                        varid = None
                    elif (
                        isinstance(the_stmt.dst, Expr.VirtualVariable)
                        and the_stmt.dst.was_reg
                        and the_stmt.dst.reg_offset == lr_offset
                    ):
                        varid = the_stmt.dst.varid
                    else:
                        continue
                    # found it
                    new_stmts = new_stmts[:stmt_idx] + new_stmts[stmt_idx + 1 :]
                    if varid is not None:
                        self.removed_vvar_ids.add(varid)
                    break

        # calculate stack offsets for arguments that are put on the stack. these offsets will be consumed by
        # simplification steps in the future, which may decide to remove statements that store arguments on the stack.
        if stack_arg_locs:
            assert self._stack_pointer_tracker is not None
            sp_offset = self._stack_pointer_tracker.offset_before(
                call_expr.tags["ins_addr"], self.project.arch.sp_offset
            )
            if sp_offset is None:
                l.warning(
                    "Failed to calculate the stack pointer offset at pc %#x. You may find redundant Store statements.",
                    call_expr.tags["ins_addr"],
                )
            else:
                if sp_offset >= (1 << (self.project.arch.bits - 1)):
                    # make it a signed integer
                    sp_offset -= 1 << self.project.arch.bits
                for arg in stack_arg_locs:
                    self.stackarg_offset_manager.add_call_stack_arg_offset(
                        self.block.addr,
                        self.block.idx,
                        call_expr.tags["ins_addr"],
                        sp_offset + arg.stack_offset - stackarg_sp_diff,
                        arg.size,
                    )

        if isinstance(last_stmt, Stmt.SideEffectStatement):
            ret_expr = last_stmt.ret_expr
            fp_ret_expr = last_stmt.fp_ret_expr
        else:
            ret_expr = None
            fp_ret_expr = None
        # if ret_expr and fp_ret_expr are None, it means in previous steps (such as during AIL simplification) we have
        # deemed the return value of this call statement as useless and is removed.

        inferred_callsite_prototype = (
            self.kb.callsite_prototypes.get_prototype(self.block.addr) if has_callsite_prototype else None
        )
        callsite_proves_return_unused = (
            inferred_callsite_prototype is not None
            and isinstance(inferred_callsite_prototype.returnty, SimTypeBottom)
            and inferred_callsite_prototype.returnty.label == "void"
        )
        if (
            prototype is not None
            and isinstance(prototype.returnty, SimTypeBottom)
            and prototype.returnty.label == "void"
            and (
                callsite_proves_return_unused
                or (
                    func is not None
                    and func.prototype_source
                    in {
                        PrototypeSource.SIMPROC,
                        PrototypeSource.SIGNATURES,
                        PrototypeSource.USER,
                    }
                )
            )
        ):
            # A low-level call writes the architecture's return-value registers even when the source declaration is
            # void. Keeping those synthetic definitions turns a valid call such as ``srand(seed);`` into the invalid
            # C expression ``tmp = srand(seed);``. Either the declaration is authoritative or a bounded call-site
            # analysis proved that the caller discards the machine result, so no source-level value is lost here.
            ret_expr = None
            fp_ret_expr = None

        if (
            ret_expr is not None
            and fp_ret_expr is not None
            and prototype is not None
            and prototype.returnty is not None
        ):
            # we need to determine the return type of this call (ret_expr vs fp_ret_expr)
            is_float = isinstance(prototype.returnty, SimTypeFloat)
            if is_float:
                ret_expr = None
            else:
                fp_ret_expr = None

        if (
            ret_expr is not None
            and prototype is not None
            and prototype.returnty is not None
            and not isinstance(prototype.returnty, SimTypeBottom)
            and not isinstance(ret_expr, Expr.VirtualVariable)
        ):
            # try to narrow the non-float return expression if needed
            ret_type_bits = prototype.returnty.with_arch(self.project.arch).size
            if ret_type_bits is not None and ret_expr.bits > ret_type_bits:
                ret_expr = ret_expr.copy()
                ret_expr.bits = ret_type_bits
            # TODO: Support narrowing virtual variables

        tags = call_expr.tags.copy()
        tags.pop("arg_vvars", None)
        transfer_kind = tags.pop("transfer_kind", getattr(call_expr, "transfer_kind", "unknown"))
        if func is not None:
            tags["is_prototype_guessed"] = func.is_prototype_guessed
        new_call = Expr.Call(
            call_expr.idx,
            call_expr.target,
            args=args,
            arg_vvars=arg_vvars,
            transfer_kind=transfer_kind,
            **tags,
        )
        vm = variable_map_of(self._ail_manager)
        vm.set_calling_convention(new_call, cc)
        vm.set_prototype(new_call, prototype)
        if isinstance(last_stmt, Stmt.Assignment):
            if not new_call.bits:
                new_call.bits = last_stmt.src.bits
            new_stmt = Stmt.Assignment(last_stmt.idx, last_stmt.dst, new_call, **last_stmt.tags)
        else:
            if not new_call.bits:
                if ret_expr is not None:
                    new_call.bits = ret_expr.bits
                elif fp_ret_expr is not None:
                    new_call.bits = fp_ret_expr.bits
            new_stmt = Stmt.SideEffectStatement(
                call_expr.idx,
                new_call,
                ret_expr=ret_expr,
                fp_ret_expr=fp_ret_expr,
                **tags,
            )

        new_stmts.append(new_stmt)
        new_stmts.extend(trailing_stmts)

        new_block = self.block.copy(statements=new_stmts)

        self.result_block = new_block

    def _find_variable_from_definition(self, def_: Definition):
        """

        :param Definition def_: The reaching definition of a variable.
        :return:                The variable that is defined.
        """

        if def_.codeloc.block_addr != self.block.addr:
            l.warning("TODO: The definition comes from a different block %#x.", def_.codeloc.block_addr)
            return None

        stmt = self.block.statements[def_.codeloc.stmt_idx]
        if isinstance(stmt, Stmt.Assignment):
            return stmt.dst
        if isinstance(stmt, Stmt.Store):
            return stmt.addr
        l.warning(
            "TODO: Unsupported statement type %s for definitions.",
            getattr(stmt, "kind_name", None) or type(stmt).__name__,
        )
        return None

    def _resolve_register_argument(self, arg_loc) -> tuple[Expr.Expression | None, Expr.VirtualVariable] | None:
        offset = arg_loc.check_offset(self.project.arch)

        if self._reaching_definitions is not None:
            # Find its definition
            view = SRDAView(self._reaching_definitions)
            vvar = view.get_reg_vvar_by_stmt(
                offset,
                arg_loc.size,
                self.block.addr,
                self.block.idx,
                self._call_stmt_idx,
                OP_BEFORE,
            )

            if vvar is not None:
                vvar_value = view.get_vvar_value(vvar)
                if not isinstance(vvar_value, Expr.Phi):
                    return vvar_value, vvar
                return None, vvar

        return None

    def _resolve_stack_argument(
        self,
        call_stmt: Expr.Call,
        arg_loc: SimStackArg,
        stackarg_sp_diff: int,
    ) -> tuple[Any, Any]:
        assert self._stack_pointer_tracker is not None

        size = arg_loc.size
        offset = arg_loc.stack_offset
        if self.project.arch.call_pushes_ret:
            # ``SimStackArg`` offsets are relative to the callee's stack pointer, after the call instruction has
            # materialized its return frame. Resolve them against the caller's pre-call stack pointer by removing the
            # selected calling convention's complete return-frame width. This is usually one architecture word, but
            # segmented far calls can push a wider return address (for example, CS:IP on 16-bit x86).
            offset -= stackarg_sp_diff

        call_addr = call_stmt.tags.get("ins_addr", None)
        assert call_addr is not None
        sp_base = self._stack_pointer_tracker.offset_before(call_addr, self.project.arch.sp_offset)
        if sp_base is not None:
            sp_offset = sp_base + offset
            if sp_offset >= (1 << (self.project.arch.bits - 1)):
                # make it a signed integer
                sp_offset -= 1 << self.project.arch.bits

            if self._reaching_definitions is not None:
                # find its definition
                view = SRDAView(self._reaching_definitions)
                vvar = view.get_stack_vvar_by_stmt(
                    sp_offset, size, self.block.addr, self.block.idx, len(self.block.statements) - 1, OP_BEFORE
                )
                if vvar is not None:
                    # FIXME: vvar may be larger than that we ask; we may need to chop the correct value of vvar
                    value = view.get_vvar_value(vvar)
                    if value is not None and not isinstance(value, Expr.Phi):
                        v: Expr.Expression = value
                    else:
                        v: Expr.Expression = Expr.VirtualVariable(
                            self._atom_idx(),
                            vvar.varid,
                            vvar.bits,
                            vvar.category,
                            oident=vvar.oident,
                            ins_addr=call_addr,
                        )
                    if v.bits // self.project.arch.byte_width > size:
                        v = Expr.Convert(
                            self._atom_idx(),
                            v.bits,
                            size * self.project.arch.byte_width,
                            False,
                            v,
                            ins_addr=call_addr,
                        )
                    return None, v

            return None, Expr.Load(
                self._atom_idx(),
                Expr.StackBaseOffset(self._atom_idx(), self.project.arch.bits, sp_offset),
                size,
                self.project.arch.memory_endness,
                func_arg=True,
            )

        return None, Expr.Load(
            self._atom_idx(),
            Expr.StackBaseOffset(self._atom_idx(), self.project.arch.bits, offset),
            size,
            self.project.arch.memory_endness,
            func_arg=True,
        )

    @staticmethod
    def _get_call_target(stmt):
        """

        :param Stmt.Call stmt:
        :return:
        """

        if isinstance(stmt.target, Expr.Const):
            return stmt.target.value

        return None

    def _load_string(self, addr: int) -> bytes:
        s = b""
        while True:
            try:
                chunk = self.project.loader.memory.load(addr, 8)
                addr += 8
            except KeyError:
                return s

            if b"\x00" in chunk:
                # found a null byte
                s += chunk[: chunk.index(b"\x00")]
                return s
            s += chunk
            if len(s) > 2048:
                break

        return s

    def _determine_variadic_arguments(self, func: Function, cc: SimCC, call_expr: Expr.Call) -> list[SimType]:
        if "printf" in func.name or "scanf" in func.name:
            return self._determine_variadic_arguments_for_format_strings(func, cc, call_expr)
        return []

    def _determine_variadic_arguments_for_format_strings(self, func, cc: SimCC, call_expr: Expr.Call) -> list[SimType]:
        proto = func.prototype
        if proto is None:
            # TODO: Support cases where prototypes are not available
            return []

        #
        # get the format string
        #

        potential_fmt_args: list[int] = []
        for idx, arg in enumerate(proto.args):
            if isinstance(arg, SimTypePointer) and isinstance(arg.pts_to, SimTypeChar):
                # find a char*
                # we assume this is the format string
                potential_fmt_args.append(idx)

        if not potential_fmt_args:
            return []

        fmt_str = None
        min_arg_count = max(potential_fmt_args) + 1
        arg_locs = cc.arg_locs(SimCC.guess_prototype([0] * min_arg_count, proto))

        for fmt_arg_idx in potential_fmt_args:
            value = None

            arg_loc = arg_locs[fmt_arg_idx]

            if isinstance(arg_loc, SimRegArg):
                value_and_def = self._resolve_register_argument(arg_loc)
                if value_and_def is not None:
                    value = value_and_def[0]

            elif isinstance(arg_loc, SimStackArg):
                value, _ = self._resolve_stack_argument(
                    call_expr,
                    arg_loc,
                    cc.STACKARG_SP_DIFF,
                )
            else:
                # Unexpected type of argument
                l.warning("Unexpected type of argument type %s.", arg_loc.__class__)
                continue

            if not isinstance(value, Const) and call_expr.args is not None and len(call_expr.args) > fmt_arg_idx:
                value = call_expr.args[fmt_arg_idx]
            if isinstance(value, Const) and isinstance(value.value, int):
                value = value.value
            if isinstance(value, int):
                fmt_str = self._load_string(value)
                if fmt_str:
                    break

        if not fmt_str:
            return []

        #
        # parse the format string
        #

        parser = FormatParser(project=self.project)
        if "printf" in func.name:
            return self._determine_printf_argument_types(parser, fmt_str)

        fmt_str_list = [bytes([b]) for b in fmt_str]
        components = parser.extract_components(fmt_str_list)

        specifiers = [component for component in components if isinstance(component, FormatSpecifier)]
        if not specifiers:
            return []
        return [spec.ty for spec in specifiers]

    @staticmethod
    def _determine_printf_argument_types(parser: FormatParser, fmt_str: bytes) -> list[SimType]:
        """Recover the promoted argument sequence consumed by a printf-style format string."""

        argument_types: list[SimType] = []
        flags = b"#0- +'I"
        length_modifiers = (b"hh", b"ll", b"h", b"l", b"j", b"z", b"t", b"L")
        idx = 0

        while (percent_idx := fmt_str.find(b"%", idx)) != -1:
            idx = percent_idx + 1
            if idx >= len(fmt_str):
                break
            if fmt_str[idx] == ord("%"):
                idx += 1
                continue

            # POSIX positional conversions begin with ``n$``. They do not consume an
            # extra argument; the following width/precision/conversion still do.
            positional_end = idx
            while positional_end < len(fmt_str) and chr(fmt_str[positional_end]).isdigit():
                positional_end += 1
            if positional_end < len(fmt_str) and fmt_str[positional_end] == ord("$"):
                idx = positional_end + 1

            while idx < len(fmt_str) and fmt_str[idx] in flags:
                idx += 1

            if idx < len(fmt_str) and fmt_str[idx] == ord("*"):
                argument_types.append(SimTypeInt().with_arch(parser.arch))
                idx += 1
                positional_end = idx
                while positional_end < len(fmt_str) and chr(fmt_str[positional_end]).isdigit():
                    positional_end += 1
                if positional_end < len(fmt_str) and fmt_str[positional_end] == ord("$"):
                    idx = positional_end + 1
            else:
                while idx < len(fmt_str) and chr(fmt_str[idx]).isdigit():
                    idx += 1

            if idx < len(fmt_str) and fmt_str[idx] == ord("."):
                idx += 1
                if idx < len(fmt_str) and fmt_str[idx] == ord("*"):
                    argument_types.append(SimTypeInt().with_arch(parser.arch))
                    idx += 1
                    positional_end = idx
                    while positional_end < len(fmt_str) and chr(fmt_str[positional_end]).isdigit():
                        positional_end += 1
                    if positional_end < len(fmt_str) and fmt_str[positional_end] == ord("$"):
                        idx = positional_end + 1
                else:
                    while idx < len(fmt_str) and chr(fmt_str[idx]).isdigit():
                        idx += 1

            length_modifier = b""
            for candidate in length_modifiers:
                if fmt_str.startswith(candidate, idx):
                    length_modifier = candidate
                    idx += len(candidate)
                    break

            if idx >= len(fmt_str):
                break
            conversion = fmt_str[idx : idx + 1]
            idx += 1

            # ``%m`` is a GNU extension that prints strerror(errno) and consumes no
            # argument. Unknown conversions are left alone instead of guessing an
            # ABI location.
            argument_type = parser._all_spec.get(length_modifier + conversion)  # pylint:disable=protected-access
            if argument_type is not None:
                argument_types.append(argument_type.with_arch(parser.arch))

        return argument_types

    def _combine_integer_argument(self, arg_loc: SimComboArg, physical_args: list[Expr.Expression]) -> Expr.Expression:
        """Reassemble the least-significant-first pieces of an integer ``SimComboArg``."""

        assert physical_args and len(physical_args) == len(arg_loc.locations)
        pieces = []
        for location, physical_arg in zip(arg_loc.locations, physical_args):
            piece_bits = location.size * self.project.arch.byte_width
            piece = physical_arg
            if piece.bits != piece_bits:
                piece = Expr.Convert(
                    self._ail_manager.next_atom(),
                    piece.bits,
                    piece_bits,
                    False,
                    piece,
                    **piece.tags,
                )
            pieces.append(piece)

        combined = pieces[0]
        for more_significant_piece in pieces[1:]:
            combined = Expr.BinaryOp(
                self._ail_manager.next_atom(),
                "Concat",
                [more_significant_piece, combined],
                **combined.tags,
            )
        assert combined.bits == arg_loc.size * self.project.arch.byte_width
        return combined

    def _expand_arglocs(
        self, arg_locs: list[SimFunctionArgument]
    ) -> list[SimStackArg | SimRegArg | SimReferenceArgument]:
        expanded_arg_locs: list[SimStackArg | SimRegArg | SimReferenceArgument] = []

        for arg_loc in arg_locs:
            if isinstance(arg_loc, SimComboArg):
                # a ComboArg spans across multiple locations (mostly stack but *in theory* can also be spanning
                # across registers). most importantly, a ComboArg represents one variable, not multiple, but we
                # have no way to know that until later down the pipeline.
                expanded_arg_locs += arg_loc.locations
            elif isinstance(arg_loc, SimStructArg):
                for field_name in arg_loc.struct.fields:
                    if field_name not in arg_loc.locs:
                        continue
                    expanded_arg_locs += self._expand_arglocs([arg_loc.locs[field_name]])
            elif isinstance(arg_loc, (SimRegArg, SimStackArg, SimReferenceArgument)):
                expanded_arg_locs.append(arg_loc)
            else:
                raise NotImplementedError("Not implemented yet.")

        return expanded_arg_locs

    def _atom_idx(self) -> int:
        return self._ail_manager.next_atom()


register_analysis(CallSiteMaker, "AILCallSiteMaker")
