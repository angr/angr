import logging
from collections import defaultdict
from typing import Tuple

from angr.ailment import Block, UnaryOp
from angr.ailment.expression import Const, VirtualVariable, StringLiteral, Struct, Array
from angr.ailment.statement import Call, FunctionLikeMacro, Store, Assignment
from angr.rust.optimization_passes.utils import extract_str_from_addr
from angr.rust.utils.ail import unwrap_stack_vvar_reference, extract_vvar_and_offset
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.mixins import CFAMixin, DFAMixin, SRDAMixin
from angr.rust.optimization_passes.utils import CallReplacer
from angr.rust.sim_type import RustSimType, RustSimTypeSize
from angr.rust.utils.library import demangle

PRINT_FUNCTIONS = (
    "std::io::stdio::_print",
    "std::io::stdio::_eprint",
    "alloc::fmt::format::format_inner",
    "alloc::fmt::format",
    "core::option::Option<T>::map_or_else",
    "core::panicking::panic_fmt",
    "std::io::Write::write_fmt",
    "core::fmt::write",
    "core::fmt::Write::write_fmt",
    "core::fmt::Formatter::write_fmt",
)

NEW_ARGUMENTS_FUNCTION = (
    "core::fmt::rt::<impl core::fmt::Arguments>::new_v1",
    "core::fmt::rt::<impl core::fmt::Arguments>::new_const",
)

NEW_ARGUMENT_FUNCTION = ("core::fmt::rt::Argument::new_display",)

l = logging.getLogger(__name__)


class FormatMacroSimplifier(OptimizationPass, CFAMixin, DFAMixin, SRDAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Recover print-like macros"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        DFAMixin.__init__(self, self._graph)
        SRDAMixin.__init__(self, func, self._graph, self.project)

        self._stmts_to_remove = defaultdict(list)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _select_macro(self, func_name, fmt_str) -> Tuple[str, str, RustSimType | None] | Tuple[None, None, None]:
        match func_name.split("::")[-1]:
            case "_print":
                if fmt_str.endswith("\n"):
                    return "println", fmt_str[:-1], None
                return "print", fmt_str, None
            case "_eprint":
                if fmt_str.endswith("\n"):
                    return "eprintln", fmt_str[:-1], None
                return "eprint", fmt_str, None
            case "format_inner" | "format" | "map_or_else":
                return "format", fmt_str, self.project.kb.known_structs["alloc::string::String"]
            case "panic_fmt":
                return "panic", fmt_str, None
            case "write_fmt" | "write":
                if fmt_str.endswith("\n"):
                    return "writeln", fmt_str[:-1], RustSimTypeSize(signed=False)
                return "write", fmt_str, RustSimTypeSize(signed=False)
        l.error(f"Can't find a macro for {func_name}")
        assert False

    def _is_debug_formatter(self, arg: Struct):
        formatter = arg.get_field("formatter")
        if isinstance(formatter, Const) and formatter.value in self.project.kb.functions:
            name = demangle(self.project.kb.functions[formatter.value].name)
            if "core::fmt::Display" in name:
                return False
            return True
        return False

    def _extract_args_len_and_pieces_len(self, func_addr):
        func = self.project.kb.functions.get(func_addr, None)
        clinic = self.project.kb.clinic_factory.get(func)
        arguments_ty = self.project.kb.known_structs["core::fmt::Arguments"]
        args_len, pieces_len = None, None
        if arguments_ty:
            args_len_offset = arguments_ty.get_field_offset("args.len")
            pieces_len_offset = arguments_ty.get_field_offset("pieces.len")
            for block in clinic.graph.nodes:
                for stmt in block.statements:
                    if isinstance(stmt, Store):
                        vvar, offset = extract_vvar_and_offset(stmt.addr)
                        if isinstance(vvar, VirtualVariable) and vvar.was_parameter and vvar.varid == 0:
                            if offset == args_len_offset:
                                value = stmt.data
                                if isinstance(value, Const):
                                    args_len = value.value
                            elif offset == pieces_len_offset:
                                value = stmt.data
                                if isinstance(value, Const):
                                    pieces_len = value.value
        return args_len, pieces_len

    def _extract_fmt_function(self, func_addr):
        func = self.project.kb.functions.get(func_addr, None)
        clinic = self.project.kb.clinic_factory.get(func)
        if clinic:
            for block in clinic.graph:
                for stmt in block.statements:
                    data = None
                    if isinstance(stmt, Store):
                        data = stmt.data
                    elif isinstance(stmt, Assignment):
                        data = stmt.src
                    if isinstance(data, Const) and data.value in self.project.kb.functions:
                        name = demangle(self.project.kb.functions[data.value].name)
                        if "display" in name or "Display" in name:
                            return "display"
                        elif "debug" in name or "Debug" in name:
                            return "debug"
        return None

    def _extract_fmt_str(self, func_addr):
        func = self.project.kb.functions.get(func_addr, None)
        clinic = self.project.kb.clinic_factory.get(func)
        arguments_ty = self.project.kb.known_structs["core::fmt::Arguments"]
        if arguments_ty:
            pieces_addr_offset = arguments_ty.get_field_offset("pieces.ptr")
            for block in clinic.graph.nodes:
                for stmt in block.statements:
                    if isinstance(stmt, Store):
                        vvar, offset = extract_vvar_and_offset(stmt.addr)
                        if (
                            isinstance(vvar, VirtualVariable)
                            and vvar.was_parameter
                            and vvar.varid == 0
                            and offset == pieces_addr_offset
                            and isinstance(stmt.data, Const)
                        ):
                            return extract_str_from_addr(self.project, stmt.data.value)
        return None

    def replace_call_inlined(self, block: Block, arg_vvar: VirtualVariable):
        """
        First attempt: check if the argument is a fmt::Arguments struct
        """
        stack_defs = self.collect_callsite_stack_defs(block)
        arg_def = stack_defs.get(arg_vvar.stack_offset, None)
        if arg_def and isinstance(arg_def.data, Struct) and arg_def.data.name == "core::fmt::Arguments":
            pieces = arg_def.data.get_field("pieces")
            args = arg_def.data.get_field("args")
            if (
                isinstance(pieces, Array)
                and isinstance(args, Array)
                and 0 <= pieces.length - args.length <= 1
                and all(
                    isinstance(arg, VirtualVariable)
                    and arg.was_stack
                    and arg.stack_offset in stack_defs
                    and isinstance(stack_defs[arg.stack_offset].data, Struct)
                    and stack_defs[arg.stack_offset].data.name in ["core::fmt::rt::Argument", "core::fmt::ArgumentV1"]
                    for arg in args.elements
                )
                and all(isinstance(piece, Const) for piece in pieces.elements)
            ):
                pieces = [extract_str_from_addr(self.project, piece.value) for piece in pieces.elements]
                macro_args = [stack_defs[arg.stack_offset].data for arg in args.elements]
                if len(pieces) == len(macro_args):
                    pieces.append("")
                placeholders = ["{:?}" if self._is_debug_formatter(macro_arg) else "{}" for macro_arg in macro_args]
                placeholders.append("")
                macro_args = [macro_arg.get_field("ty") or macro_arg.get_field("value") for macro_arg in macro_args]
                for arg in args.elements:
                    stack_def = stack_defs[arg.stack_offset]
                    self._stmts_to_remove[stack_def.block].append(stack_def.stmt)
                self._stmts_to_remove[arg_def.block].append(arg_def.stmt)
                return pieces, placeholders, macro_args
        return None

    def replace_call_uninlined(self, arg_vvar: VirtualVariable):
        """
        Second attempt: check if the argument is constructed via new_v1
        """
        new_arguments_call = self.get_terminal_vvar_value(arg_vvar)
        # Find the block containing the new_arguments_call
        new_arguments_call_block = None
        new_arguments_call_stmt = None
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and stmt.src is new_arguments_call:
                    new_arguments_call_block = block
                    new_arguments_call_stmt = stmt
                    break
        if (
            new_arguments_call_block is not None
            and isinstance(new_arguments_call, Call)
            # and self.match_call(new_arguments_call, NEW_ARGUMENTS_FUNCTION, monopolize=False, use_trait_name=False)
        ):
            if len(new_arguments_call.args) == 2:
                pieces_value = new_arguments_call.args[0]
                args_value = unwrap_stack_vvar_reference(new_arguments_call.args[1])
                args_len, pieces_len = self._extract_args_len_and_pieces_len(new_arguments_call.target.value)
                if (
                    isinstance(pieces_value, Const)
                    and isinstance(args_value, VirtualVariable)
                    and args_value.was_stack
                    and args_len is not None
                    and pieces_len is not None
                    and 0 <= pieces_len - args_len <= 1
                ):
                    pieces = [
                        extract_str_from_addr(self.project, pieces_value.value + i * self.project.arch.bytes * 2)
                        for i in range(pieces_len)
                    ]
                    if pieces_len == args_len:
                        pieces.append("")
                    placeholders = []
                    macro_args = []
                    calls_to_remove = []
                    for i in range(args_len):
                        arg_vvar = self.get_stack_vvar_by_insn(
                            args_value.stack_offset + i * self.project.arch.bytes * 2,
                            new_arguments_call.ins_addr,
                            new_arguments_call_block.idx,
                        )
                        new_argument_call = self.get_terminal_vvar_value(arg_vvar)
                        if (
                            isinstance(new_argument_call, Call)
                            and len(new_argument_call.args) == 1
                            and isinstance(new_argument_call.args[0], UnaryOp)
                            and new_argument_call.args[0].op == "Reference"
                        ):
                            calls_to_remove.append(new_argument_call)
                            macro_args.append(new_argument_call.args[0].operand)
                            fmt_function = self._extract_fmt_function(new_argument_call.target.value)
                            if fmt_function == "display" or fmt_function is None:
                                placeholders.append("{}")
                            else:
                                placeholders.append("{:?}")
                    placeholders.append("")
                    # Remove the statements defining the arguments and the new_arguments_call
                    self._stmts_to_remove[new_arguments_call_block].append(new_arguments_call_stmt)
                    for block in self._graph.nodes:
                        for call in calls_to_remove:
                            for stmt in block.statements:
                                if isinstance(stmt, Assignment) and stmt.src is call:
                                    self._stmts_to_remove[block].append(stmt)
                    return pieces, placeholders, macro_args
            else:
                fmt_str = self._extract_fmt_str(new_arguments_call.target.value)
                if fmt_str is not None:
                    self._stmts_to_remove[new_arguments_call_block].append(new_arguments_call_stmt)
                    pieces = [fmt_str]
                    placeholders = [""]
                    macro_args = []
                    return pieces, placeholders, macro_args
        return None

    def replace_call(self, call: Call, block: Block, stmt, is_expr):
        if (
            (name := self.match_call(call, PRINT_FUNCTIONS, monopolize=False, use_trait_name=False))
            and call.args
            and (arg_vvar := unwrap_stack_vvar_reference(call.args[-1]))
        ):
            result = self.replace_call_inlined(block, arg_vvar) or self.replace_call_uninlined(arg_vvar)
            if result:
                pieces, placeholders, macro_args = result
                fmt_str = ""
                for piece, placeholder in zip(pieces, placeholders):
                    fmt_str += piece + placeholder
                macro_name, fmt_str, returnty = self._select_macro(name, fmt_str)
                if returnty is not None:
                    returnty = returnty.with_arch(self.project.arch)
                macro_args.insert(0, StringLiteral(None, fmt_str, self.project.arch.bits * 2))
                macro = FunctionLikeMacro(
                    None,
                    macro_name,
                    macro_args,
                    bits=call.bits if is_expr else None,
                    returnty=returnty,
                    **call.tags,
                )
                return macro
        return None

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            CallReplacer(self.replace_call).walk(block)
        for block, stmts in self._stmts_to_remove.items():
            for stmt in stmts:
                if stmt in block.statements:
                    block.statements.remove(stmt)
