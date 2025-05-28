from __future__ import annotations
from typing import cast, Any, TYPE_CHECKING
import copy
import logging

import archinfo
from angr.ailment import Stmt, Expr, Const
from angr.ailment.manager import Manager

from angr.procedures.stubs.format_parser import FormatParser, FormatSpecifier
from angr.sim_type import (
    SimTypeBottom,
    SimTypePointer,
    SimTypeChar,
    SimTypeInt,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeLongLong,
)
from angr.calling_conventions import SimReferenceArgument, SimRegArg, SimStackArg, SimCC, SimStructArg, SimComboArg
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
from angr.analyses import Analysis, register_analysis
from angr.analyses.s_reaching_definitions import SRDAView
from angr.utils.types import dereference_simtype_by_lib

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function
    from angr.knowledge_plugins.key_definitions.definition import Definition


l = logging.getLogger(name=__name__)


class CallSiteMaker(Analysis):
    """
    Add calling convention, declaration, and args to a call site.
    """

    def __init__(
        self, block, reaching_definitions=None, stack_pointer_tracker=None, ail_manager: Manager | None = None
    ):
        self.block = block

        self._reaching_definitions = reaching_definitions
        self._stack_pointer_tracker = stack_pointer_tracker
        self._ail_manager: Manager | None = ail_manager

        self.result_block = None
        self.stack_arg_offsets: set[tuple[int, int]] | None = None  # call ins addr, stack_offset
        self.removed_vvar_ids: set[int] = set()

        self._analyze()

    def _analyze(self):
        if not self.block.statements:
            return

        last_stmt = self.block.statements[-1]

        if type(last_stmt) is Stmt.Call:
            call_stmt = last_stmt
        elif isinstance(last_stmt, Stmt.Assignment) and type(last_stmt.src) is Stmt.Call:
            call_stmt = last_stmt.src
        else:
            self.result_block = self.block
            return

        if isinstance(call_stmt.target, str):
            # custom function calls
            self.result_block = self.block
            return

        cc = None
        prototype: SimTypeFunction | None = None
        func = None
        stack_arg_locs: list[SimStackArg] = []
        stackarg_sp_diff = 0

        # priority:
        # 0. manually-specified call-site prototype
        # 1. function-specific prototype
        # 2. automatically recovered call-site prototype

        # manually-specified call-site prototype
        has_callsite_prototype = self.kb.callsite_prototypes.has_prototype(self.block.addr)
        if has_callsite_prototype:
            manually_specified = self.kb.callsite_prototypes.get_prototype_type(self.block.addr)
            if manually_specified:
                cc = self.kb.callsite_prototypes.get_cc(self.block.addr)
                prototype = self.kb.callsite_prototypes.get_prototype(self.block.addr)

        # function-specific prototype
        if cc is None or prototype is None:
            target = self._get_call_target(call_stmt)
            if target is not None and target in self.kb.functions:
                # function-specific logic when the calling target is known
                func = self.kb.functions[target]
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

        args = []
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
                    variadic_args = self._determine_variadic_arguments(func, cc, call_stmt)
                    if variadic_args:
                        callsite_ty = copy.copy(prototype)
                        callsite_args = list(callsite_ty.args)
                        base_type = SimTypeInt if self.project.arch.bits == 32 else SimTypeLongLong
                        for _ in range(variadic_args):
                            callsite_args.append(base_type().with_arch(self.project.arch))
                        callsite_ty.args = tuple(callsite_args)
                        arg_locs = cc.arg_locs(callsite_ty)

        if arg_locs is not None and cc is not None:
            expanded_arg_locs: list[SimStackArg | SimRegArg | SimReferenceArgument] = []
            for arg_loc in arg_locs:
                if isinstance(arg_loc, SimComboArg):
                    # a ComboArg spans across multiple locations (mostly stack but *in theory* can also be spanning
                    # across registers). most importantly, a ComboArg represents one variable, not multiple, but we
                    # have no way to know that until later down the pipeline.
                    expanded_arg_locs += arg_loc.locations
                elif isinstance(arg_loc, SimStructArg):
                    expanded_arg_locs += [  # type: ignore
                        arg_loc.locs[field_name] for field_name in arg_loc.struct.fields if field_name in arg_loc.locs
                    ]
                elif isinstance(arg_loc, (SimRegArg, SimStackArg, SimReferenceArgument)):
                    expanded_arg_locs.append(arg_loc)
                else:
                    raise NotImplementedError("Not implemented yet.")

            for arg_loc in expanded_arg_locs:
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
                            None,
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
                                self._ail_manager.next_atom() if self._ail_manager is not None else None,
                                "Shr",
                                [
                                    vvar_use,
                                    Expr.Const(
                                        self._ail_manager.next_atom() if self._ail_manager is not None else None,
                                        None,
                                        (offset - vvar_def_reg_offset) * 8,
                                        8,
                                    ),
                                ],
                                **vvar_use.tags,
                            )
                        if vvar_def.size > arg_loc.size:
                            # we need to narrow the value
                            vvar_use = Expr.Convert(
                                self._ail_manager.next_atom() if self._ail_manager is not None else None,
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
                            None,
                            offset,
                            size * 8,
                            reg_name=arg_loc.reg_name,
                            ins_addr=last_stmt.ins_addr,
                        )
                        arg_expr = reg
                elif isinstance(arg_loc, SimStackArg):
                    stack_arg_locs.append(arg_loc)
                    _, the_arg = self._resolve_stack_argument(call_stmt, arg_loc)
                    arg_expr = the_arg if the_arg is not None else None
                else:
                    assert False, "Unreachable"

                if arg_expr is not None and dereference_size is not None:
                    arg_expr = Expr.Load(self._atom_idx(), arg_expr, dereference_size, endness=archinfo.Endness.BE)
                args.append(arg_expr)

        # Remove the old call statement
        new_stmts = self.block.statements[:-1]

        # remove the statement that stores the return address
        if self.project.arch.call_pushes_ret:
            # check if the last statement is storing the return address onto the top of the stack
            if len(new_stmts) >= 1:
                the_stmt = new_stmts[-1]
                if (
                    isinstance(the_stmt, Stmt.Assignment)
                    and isinstance(the_stmt.dst, Expr.VirtualVariable)
                    and the_stmt.dst.was_stack
                    and isinstance(the_stmt.src, Expr.Const)
                    and the_stmt.src.value == self.block.addr + self.block.original_size
                ):
                    # yes it is!
                    self.removed_vvar_ids.add(the_stmt.dst.varid)
                    new_stmts = new_stmts[:-1]
        else:
            # if there is an lr register...
            lr_offset = None
            if archinfo.arch_arm.is_arm_arch(self.project.arch) or self.project.arch.name in {"PPC32", "PPC64"}:
                lr_offset = self.project.arch.registers["lr"][0]
            elif self.project.arch.name in {"MIPS32", "MIPS64"}:
                lr_offset = self.project.arch.registers["ra"][0]
            # remove the assignment to the lr register
            if lr_offset is not None and len(new_stmts) >= 1:
                the_stmt = new_stmts[-1]
                if (
                    isinstance(the_stmt, Stmt.Assignment)
                    and isinstance(the_stmt.dst, Expr.Register)
                    and the_stmt.dst.reg_offset == lr_offset
                ):
                    # found it
                    new_stmts = new_stmts[:-1]

        # calculate stack offsets for arguments that are put on the stack. these offsets will be consumed by
        # simplification steps in the future, which may decide to remove statements that store arguments on the stack.
        if stack_arg_locs:
            assert self._stack_pointer_tracker is not None
            sp_offset = self._stack_pointer_tracker.offset_before(call_stmt.ins_addr, self.project.arch.sp_offset)
            if sp_offset is None:
                l.warning(
                    "Failed to calculate the stack pointer offset at pc %#x. You may find redundant Store "
                    "statements.",
                    call_stmt.ins_addr,
                )
                self.stack_arg_offsets = None
            else:
                self.stack_arg_offsets = {
                    (call_stmt.ins_addr, sp_offset + arg.stack_offset - stackarg_sp_diff) for arg in stack_arg_locs
                }

        ret_expr = call_stmt.ret_expr
        fp_ret_expr = call_stmt.fp_ret_expr
        # if ret_expr and fp_ret_expr are None, it means in previous steps (such as during AIL simplification) we have
        # deemed the return value of this call statement as useless and is removed.

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

        new_stmt = Stmt.Call(
            call_stmt.idx,
            call_stmt.target,
            calling_convention=cc,
            prototype=prototype,
            args=args,
            ret_expr=ret_expr,
            fp_ret_expr=fp_ret_expr,
            arg_vvars=arg_vvars,
            **call_stmt.tags,
        )
        if isinstance(last_stmt, Stmt.Assignment):
            if new_stmt.bits is None:
                new_stmt.bits = last_stmt.src.bits
            new_stmt = Stmt.Assignment(last_stmt.idx, last_stmt.dst, new_stmt, **last_stmt.tags)

        new_stmts.append(new_stmt)

        new_block = self.block.copy()
        new_block.statements = new_stmts

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
        if type(stmt) is Stmt.Assignment:
            return stmt.dst
        if type(stmt) is Stmt.Store:
            return stmt.addr
        l.warning("TODO: Unsupported statement type %s for definitions.", type(stmt))
        return None

    def _resolve_register_argument(self, arg_loc) -> tuple[Expr.Expression | None, Expr.VirtualVariable] | None:
        offset = arg_loc.check_offset(self.project.arch)

        if self._reaching_definitions is not None:
            # Find its definition
            view = SRDAView(self._reaching_definitions.model)
            vvar = view.get_reg_vvar_by_stmt(
                offset, self.block.addr, self.block.idx, len(self.block.statements) - 1, OP_BEFORE
            )

            if vvar is not None:
                vvar_value = view.get_vvar_value(vvar)
                if not isinstance(vvar_value, Expr.Phi):
                    return vvar_value, vvar
                return None, vvar

        return None

    def _resolve_stack_argument(
        self, call_stmt: Stmt.Call, arg_loc
    ) -> tuple[Any, Any]:  # pylint:disable=unused-argument
        assert self._stack_pointer_tracker is not None

        size = arg_loc.size
        offset = arg_loc.stack_offset
        if self.project.arch.call_pushes_ret:
            # adjust the offset
            offset -= self.project.arch.bytes

        sp_base = self._stack_pointer_tracker.offset_before(call_stmt.ins_addr, self.project.arch.sp_offset)
        if sp_base is not None:
            sp_offset = sp_base + offset
            if sp_offset >= (1 << (self.project.arch.bits - 1)):
                # make it a signed integer
                mask = (1 << self.project.arch.bits) - 1
                sp_offset = -(((~sp_offset) & mask) + 1)

            if self._reaching_definitions is not None:
                # find its definition
                view = SRDAView(self._reaching_definitions.model)
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
                            ins_addr=call_stmt.ins_addr,
                        )
                    if v.size > size:
                        v = Expr.Convert(
                            self._atom_idx(),
                            v.bits,
                            size * self.project.arch.byte_width,
                            False,
                            v,
                            ins_addr=call_stmt.ins_addr,
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

        if type(stmt.target) is Expr.Const:
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

    def _determine_variadic_arguments(self, func: Function, cc: SimCC, call_stmt) -> int | None:
        if "printf" in func.name or "scanf" in func.name:
            return self._determine_variadic_arguments_for_format_strings(func, cc, call_stmt)
        return None

    def _determine_variadic_arguments_for_format_strings(self, func, cc: SimCC, call_stmt) -> int | None:
        proto = func.prototype
        if proto is None:
            # TODO: Support cases where prototypes are not available
            return None

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
            return None

        fmt_str = None
        min_arg_count = max(potential_fmt_args) + 1
        arg_locs = cc.arg_locs(SimCC.guess_prototype([0] * min_arg_count, proto))

        for fmt_arg_idx in potential_fmt_args:
            arg_loc = arg_locs[fmt_arg_idx]

            value = None
            if isinstance(arg_loc, SimRegArg):
                value_and_def = self._resolve_register_argument(arg_loc)
                if value_and_def is not None:
                    value = value_and_def[0]

            elif isinstance(arg_loc, SimStackArg):
                value, _ = self._resolve_stack_argument(call_stmt, arg_loc)
            else:
                # Unexpected type of argument
                l.warning("Unexpected type of argument type %s.", arg_loc.__class__)
                return None

            if isinstance(value, Const) and isinstance(value.value, int):
                value = value.value
            if isinstance(value, int):
                fmt_str = self._load_string(value)
                if fmt_str:
                    break

        if not fmt_str:
            return None

        #
        # parse the format string
        #

        parser = FormatParser(project=self.project)
        fmt_str_list = [bytes([b]) for b in fmt_str]
        components = parser.extract_components(fmt_str_list)

        specifiers = [component for component in components if isinstance(component, FormatSpecifier)]
        if not specifiers:
            return None
        return len(specifiers)

    def _atom_idx(self) -> int | None:
        return self._ail_manager.next_atom() if self._ail_manager is not None else None


register_analysis(CallSiteMaker, "AILCallSiteMaker")
