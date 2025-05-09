import logging
from collections import defaultdict
from typing import Tuple

from ailment import Block
from ailment.expression import Const, VirtualVariable, StringLiteral, Struct, Array
from ailment.statement import Call, FunctionLikeMacro

from angr.rust.optimization_passes.utils import extract_str_from_addr
from angr.rust.utils.ail import unwrap_stack_vvar_reference
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.mixins import CFAMixin, DFAMixin
from angr.rust.optimization_passes.utils import CallReplacer
from angr.rust.sim_type import RustSimType, RustSimTypeString
from angr.rust.utils.library import demangle

PRINT_FUNCTIONS = (
    "std::io::stdio::_print",
    "std::io::stdio::_eprint",
    "alloc::fmt::format::format_inner",
    "alloc::fmt::format",
    "core::option::Option<T>::map_or_else",
    "core::panicking::panic_fmt",
)

l = logging.getLogger(__name__)


class PrintMacroSimplifier(OptimizationPass, CFAMixin, DFAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Recover print-like macros"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        DFAMixin.__init__(self, self._graph)

        self._stmts_to_remove = defaultdict(list)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    @staticmethod
    def _select_macro(func_name, fmt_str) -> Tuple[str, str, RustSimType | None] | Tuple[None, None, None]:
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
                return "format", fmt_str, RustSimTypeString()
            case "panic_fmt":
                return "panic", fmt_str, None
        l.error(f"Can't find a macro for {func_name}")
        return None, None, None

    def _is_debug_formatter(self, arg: Struct):
        formatter = arg.get_field("formatter")
        if isinstance(formatter, Const) and formatter.value in self.project.kb.functions:
            name = demangle(self.project.kb.functions[formatter.value].name)
            if "core::fmt::Display" in name:
                return False
            return True
        return False

    def replace_call(self, call: Call, block: Block, stmt, is_expr):
        if (
            (name := self.match_call(call, PRINT_FUNCTIONS, monopolize=False, use_trait_name=False))
            and call.args
            and (arg_vvar := unwrap_stack_vvar_reference(call.args[-1]))
        ):
            stack_defs = self.collect_callsite_stack_defs(block)
            arg_def = stack_defs.get(arg_vvar.stack_offset, None)
            if arg_def and isinstance(arg_def.data, Struct) and arg_def.data.name == "Arguments":
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
                        and stack_defs[arg.stack_offset].data.name == "Argument"
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
                    fmt_str = ""
                    for piece, placeholder in zip(pieces, placeholders):
                        fmt_str += piece + placeholder
                    macro_name, fmt_str, returnty = self._select_macro(name, fmt_str)
                    if returnty is not None:
                        returnty = returnty.with_arch(self.project.arch)
                    if macro_name and fmt_str:
                        macro_args = [macro_arg.get_field("value") for macro_arg in macro_args]
                        macro_args.insert(0, StringLiteral(None, fmt_str, self.project.arch.bits * 2))
                        macro = FunctionLikeMacro(
                            None,
                            macro_name,
                            macro_args,
                            bits=call.bits if is_expr else None,
                            returnty=returnty,
                            **call.tags,
                        )
                        for arg in args.elements:
                            stack_def = stack_defs[arg.stack_offset]
                            self._stmts_to_remove[stack_def.block].append(stack_def.stmt)
                        self._stmts_to_remove[arg_def.block].append(arg_def.stmt)
                        return macro
        return None

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            CallReplacer(self.replace_call).walk(block)
        for block, stmts in self._stmts_to_remove.items():
            for stmt in stmts:
                if stmt in block.statements:
                    block.statements.remove(stmt)
