from typing import Optional, List, Tuple, Any, Set, TYPE_CHECKING
import copy
import logging

import archinfo
from ailment import Stmt, Expr

from angr.procedures.stubs.format_parser import FormatParser, FormatSpecifier
from angr.errors import SimMemoryMissingError
from angr.sim_type import SimTypeBottom, SimTypePointer, SimTypeChar, SimTypeInt
from angr.calling_conventions import SimRegArg, SimStackArg, SimCC
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
from angr.analyses import Analysis, register_analysis

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function
    from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
    from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
    from angr.knowledge_plugins.key_definitions.definition import Definition


l = logging.getLogger(name=__name__)


class CallSiteMaker(Analysis):
    """
    Add calling convention, declaration, and args to a call site.
    """

    def __init__(self, block, reaching_definitions=None, stack_pointer_tracker=None, ail_manager=None):
        self.block = block

        self._reaching_definitions = reaching_definitions
        self._stack_pointer_tracker = stack_pointer_tracker
        self._ail_manager = ail_manager

        self.result_block = None
        self.stack_arg_offsets: Optional[Set[Tuple[int, int]]] = None  # ins_addr, stack_offset

        self._analyze()

    def _analyze(self):
        if not self.block.statements:
            return

        last_stmt = self.block.statements[-1]

        if type(last_stmt) is not Stmt.Call:
            self.result_block = self.block
            return

        cc = None
        prototype = None
        func = None
        stack_arg_locs: List[SimStackArg] = []
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
            target = self._get_call_target(last_stmt)
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

        args = []
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
                    variadic_args = self._determine_variadic_arguments(func, cc, last_stmt)
                    if variadic_args:
                        callsite_ty = copy.copy(prototype)
                        callsite_ty.args = list(callsite_ty.args)
                        for _ in range(variadic_args):
                            callsite_ty.args.append(SimTypeInt().with_arch(self.project.arch))
                        arg_locs = cc.arg_locs(callsite_ty)

        if arg_locs is not None:
            for arg_loc in arg_locs:
                if type(arg_loc) is SimRegArg:
                    size = arg_loc.size
                    offset = arg_loc.check_offset(cc.arch)
                    args.append(Expr.Register(self._atom_idx(), None, offset, size * 8, reg_name=arg_loc.reg_name))
                elif type(arg_loc) is SimStackArg:
                    stack_arg_locs.append(arg_loc)
                    _, the_arg = self._resolve_stack_argument(last_stmt, arg_loc)

                    if the_arg is not None:
                        args.append(the_arg)
                    else:
                        args.append(None)

                else:
                    raise NotImplementedError("Not implemented yet.")

        # Remove the old call statement
        new_stmts = self.block.statements[:-1]

        # remove the statement that stores the return address
        if self.project.arch.call_pushes_ret:
            # check if the last statement is storing the return address onto the top of the stack
            if len(new_stmts) >= 1:
                the_stmt = new_stmts[-1]
                if isinstance(the_stmt, Stmt.Store) and isinstance(the_stmt.data, Expr.Const):
                    if (
                        isinstance(the_stmt.addr, Expr.StackBaseOffset)
                        and the_stmt.data.value == self.block.addr + self.block.original_size
                    ):
                        # yes it is!
                        new_stmts = new_stmts[:-1]
        else:
            # if there is an lr register...
            lr_offset = None
            if archinfo.arch_arm.is_arm_arch(self.project.arch) or self.project.arch.name in {"PPC32", "PPC64"}:
                lr_offset = self.project.arch.registers["lr"][0]
            elif self.project.arch.name in {"MIPS32", "MIPS64"}:
                lr_offset = self.project.arch.registers["ra"][0]
            if lr_offset is not None:
                # remove the assignment to the lr register
                if len(new_stmts) >= 1:
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
            sp_offset = self._stack_pointer_tracker.offset_before(last_stmt.ins_addr, self.project.arch.sp_offset)
            if sp_offset is None:
                l.warning(
                    "Failed to calculate the stack pointer offset at pc %#x. You may find redundant Store "
                    "statements.",
                    last_stmt.ins_addr,
                )
                self.stack_arg_offsets = None
            else:
                self.stack_arg_offsets = {
                    (last_stmt.ins_addr, sp_offset + arg.stack_offset - stackarg_sp_diff) for arg in stack_arg_locs
                }

        ret_expr = last_stmt.ret_expr
        # if ret_expr is None, it means in previous steps (such as during AIL simplification) we have deemed the return
        # value of this call statement as useless and is removed.

        if (
            ret_expr is not None
            and prototype is not None
            and prototype.returnty is not None
            and not isinstance(prototype.returnty, SimTypeBottom)
        ):
            # try to narrow the return expression if needed
            ret_type_bits = prototype.returnty.with_arch(self.project.arch).size
            if ret_expr.bits > ret_type_bits:
                ret_expr = ret_expr.copy()
                ret_expr.bits = ret_type_bits

        new_stmts.append(
            Stmt.Call(
                last_stmt.idx,
                last_stmt.target,
                calling_convention=cc,
                prototype=prototype,
                args=args,
                ret_expr=ret_expr,
                **last_stmt.tags,
            )
        )

        new_block = self.block.copy()
        new_block.statements = new_stmts

        self.result_block = new_block

    def _find_variable_from_definition(self, def_: "Definition"):
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
        elif type(stmt) is Stmt.Store:
            return stmt.addr
        else:
            l.warning("TODO: Unsupported statement type %s for definitions.", type(stmt))
            return None

    def _resolve_register_argument(self, call_stmt, arg_loc) -> Tuple:
        size = arg_loc.size
        offset = arg_loc.check_offset(self.project.arch)

        if self._reaching_definitions is not None:
            # Find its definition
            ins_addr = call_stmt.tags["ins_addr"]
            try:
                rd: "LiveDefinitions" = self._reaching_definitions.get_reaching_definitions_by_insn(ins_addr, OP_BEFORE)
            except KeyError:
                return None, None

            try:
                vs: "MultiValues" = rd.register_definitions.load(offset, size=size)
            except SimMemoryMissingError:
                return None, None
            values_and_defs_ = set()
            for values in vs.values():
                for value in values:
                    if value.concrete:
                        concrete_value = value._model_concrete.value
                    else:
                        concrete_value = None
                    for def_ in rd.extract_defs(value):
                        values_and_defs_.add((concrete_value, def_))

            if not values_and_defs_:
                l.warning("Did not find any reaching definition for register %s at instruction %x.", arg_loc, ins_addr)
            elif len(values_and_defs_) > 1:
                l.warning("TODO: More than one reaching definition are found at instruction %x.", ins_addr)
            else:
                # Find the definition
                # FIXME: Multiple definitions - we need phi nodes
                value, def_ = next(iter(values_and_defs_))
                variable = self._find_variable_from_definition(def_)
                return value, variable

        return None, None

    def _resolve_stack_argument(self, call_stmt, arg_loc) -> Tuple[Any, Any]:  # pylint:disable=unused-argument
        size = arg_loc.size
        offset = arg_loc.stack_offset
        if self.project.arch.call_pushes_ret:
            # adjust the offset
            offset -= self.project.arch.bytes

        # TODO: Support extracting values

        return None, Expr.Load(
            self._atom_idx(),
            Expr.Register(self._atom_idx(), None, self.project.arch.sp_offset, self.project.arch.bits)
            + Expr.Const(self._atom_idx(), None, offset, self.project.arch.bits),
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

    def _determine_variadic_arguments(self, func: Optional["Function"], cc: SimCC, call_stmt) -> Optional[int]:
        if func is not None and "printf" in func.name or "scanf" in func.name:
            return self._determine_variadic_arguments_for_format_strings(func, cc, call_stmt)
        return None

    def _determine_variadic_arguments_for_format_strings(self, func, cc: SimCC, call_stmt) -> Optional[int]:
        proto = func.prototype
        if proto is None:
            # TODO: Support cases where prototypes are not available
            return None

        #
        # get the format string
        #

        potential_fmt_args: List[int] = []
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

            if isinstance(arg_loc, SimRegArg):
                value, _ = self._resolve_register_argument(call_stmt, arg_loc)
            elif isinstance(arg_loc, SimStackArg):
                value, _ = self._resolve_stack_argument(call_stmt, arg_loc)
            else:
                # Unexpected type of argument
                l.warning("Unexpected type of argument type %s.", arg_loc.__class__)
                return None

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

    def _atom_idx(self) -> Optional[int]:
        return self._ail_manager.next_atom() if self._ail_manager is not None else None


register_analysis(CallSiteMaker, "AILCallSiteMaker")
