from __future__ import annotations

import argparse
import logging
import re
import sys
from typing import TYPE_CHECKING
from collections.abc import Generator

from rich.syntax import Syntax
from rich.console import Console

import angr
from angr.analyses.decompiler import DECOMPILATION_PRESETS
from angr.analyses.decompiler.structuring import STRUCTURER_CLASSES, DEFAULT_STRUCTURER
from angr.analyses.decompiler.utils import decompile_functions
from angr.utils.formatting import ansi_color_enabled

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


log = logging.getLogger(__name__)


NUMERIC_ARG_RE = re.compile(r"^(0x)?[a-fA-F0-9]+$")
KNOWN_COMMANDS = frozenset({"decompile", "dec", "disassemble", "dis"})
# Options that take a value argument (used for backwards-compat argv reordering)
_OPTIONS_WITH_VALUE = frozenset({"--base-addr", "--structurer", "--preset", "--theme"})


def parse_function_args(proj: angr.Project, func_args: list[str] | None) -> Generator[Function]:
    """
    Generate a sequence of functions in the project kb by their identifier in func_args.

    :param proj:      Project to query.
    :param func_args: Sequence of function identifiers to query. None for all functions.
    """
    if func_args is None:
        yield from sorted(proj.kb.functions.values(), key=lambda f: f.addr)
        return

    for func_arg in func_args:
        if func_arg in proj.kb.functions:
            yield proj.kb.functions[func_arg]
            continue

        if NUMERIC_ARG_RE.match(func_arg):
            func_addr = int(func_arg, 0)
            if func_addr in proj.kb.functions:
                yield proj.kb.functions[func_addr]
                continue

        log.error('Function "%s" not found', func_arg)


def disassemble(args):
    """
    Disassemble functions.
    """
    loader_main_opts_kwargs = {}
    if args.base_addr is not None:
        loader_main_opts_kwargs["base_addr"] = args.base_addr

    proj = angr.Project(args.binary, auto_load_libs=False, main_opts=loader_main_opts_kwargs)
    proj.analyses.CFG(normalize=True, data_references=True)

    for func in parse_function_args(proj, args.functions):
        try:
            if func.is_plt or func.is_syscall or func.is_alignment or func.is_simprocedure:
                continue
            func.pp(show_bytes=True, min_edge_depth=10)
        except Exception as e:  # pylint:disable=broad-exception-caught
            if not args.catch_exceptions:
                raise
            log.exception(e)


def decompile(args):
    """
    Decompile functions.
    """
    decompilation = decompile_functions(
        args.binary,
        functions=args.functions,
        structurer=args.structurer,
        catch_errors=args.catch_exceptions,
        show_casts=not args.no_casts,
        base_address=args.base_addr,
        preset=args.preset,
        cca=args.cca,
        cca_callsites=args.cca_callsites,
        progressbar=args.progress,
    )

    # Determine if we should use syntax highlighting
    should_highlight = ansi_color_enabled and not args.no_colors

    if should_highlight:
        try:
            console = Console()
            syntax = Syntax(decompilation, "c", theme=args.theme, line_numbers=False)
            console.print(syntax)
        # pylint: disable=broad-exception-caught
        except Exception as e:
            log.warning("Syntax highlighting failed: %s", e)
            # Fall back to plain text if syntax highlighting fails
            print(decompilation)
    else:
        print(decompilation)


def _add_binary_args(parser: argparse.ArgumentParser) -> None:
    """Add the binary positional argument and related options shared by all subcommands."""
    parser.add_argument("binary", help="The path to the binary to analyze.")
    parser.add_argument(
        "--catch-exceptions",
        help="""
        Catch exceptions during analysis. The scope of error handling may depend on the command used for analysis.
        If multiple functions are specified for analysis, each function will be handled individually.""",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--base-addr",
        help="""
        The base address of the binary. This is useful when the binary is loaded at a different address than the one
        specified in the ELF header.""",
        type=lambda x: int(x, 0),
        default=None,
    )


def _maybe_reorder_args(argv: list[str]) -> list[str]:
    """
    Detect old-style argument order (angr <binary> <command>) and reorder
    to new style (angr <command> <binary>) with a deprecation warning.
    """
    positionals = []
    skip_next = False
    for i, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if arg in _OPTIONS_WITH_VALUE:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        positionals.append((i, arg))
        if len(positionals) >= 2:
            break

    if len(positionals) < 2:
        return argv

    first_idx, first_val = positionals[0]
    second_idx, second_val = positionals[1]

    # If first positional is already a known command, no reorder needed
    if first_val in KNOWN_COMMANDS:
        return argv

    # If second positional is a known command, it's the old argument order
    if second_val in KNOWN_COMMANDS:
        print(
            "WARNING: Deprecated argument order detected: angr <binary> <command>.\n"
            "Please use the new order: angr <command> <binary>\n"
            "The old argument order will be removed in a future version.",
            file=sys.stderr,
        )
        new_argv = list(argv)
        new_argv[first_idx] = second_val
        new_argv[second_idx] = first_val
        return new_argv

    return argv


def main():
    parser = argparse.ArgumentParser(description="The angr CLI allows you to decompile and analyze binaries.")
    parser.add_argument("--version", action="version", version=angr.__version__)
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Increase verbosity level (can be used multiple times)."
    )
    subparsers = parser.add_subparsers(metavar="command", required=True)

    decompile_cmd_parser = subparsers.add_parser("decompile", aliases=["dec"], help=decompile.__doc__)
    decompile_cmd_parser.set_defaults(func=decompile)
    _add_binary_args(decompile_cmd_parser)
    decompile_cmd_parser.add_argument(
        "--structurer",
        help="The structuring algorithm to use for decompilation.",
        choices=STRUCTURER_CLASSES.keys(),
        default=DEFAULT_STRUCTURER.NAME,
    )
    decompile_cmd_parser.add_argument(
        "--no-casts",
        help="Do not show type casts in the decompiled output.",
        action="store_true",
        default=False,
    )
    decompile_cmd_parser.add_argument(
        "--preset",
        help="The configuration preset to use for decompilation.",
        choices=DECOMPILATION_PRESETS,
        default="default",
    )
    decompile_cmd_parser.add_argument(
        "--cca",
        help="Enable full-binary function prototype recovery. Improves decompilation quality but may be slow on "
        "binaries with many functions.",
        action="store_true",
        default=False,
    )
    decompile_cmd_parser.add_argument(
        "--cca-callsites",
        help="When --cca (full-binary function prototype recovery) is enabled, also analyze call sites for better "
        "function prototype inference.",
        action="store_true",
        default=True,
    )
    decompile_cmd_parser.add_argument(
        "-p",
        "--progress",
        help="Show a progress bar during decompilation.",
        action="store_true",
    )
    decompile_cmd_parser.add_argument(
        "--functions",
        help="""
        The functions to decompile. Functions can either be expressed as names found in the
        symbols of the binary or as addresses like: 0x401000.""",
        nargs="+",
    )
    decompile_cmd_parser.add_argument(
        "--no-colors",
        help="Disable syntax highlighting in the decompiled output.",
        action="store_true",
        default=False,
    )
    decompile_cmd_parser.add_argument(
        "--theme",
        help="The syntax highlighting theme to use (only if rich is installed and colors are enabled).",
        default="ansi_dark",
    )

    disassemble_cmd_parser = subparsers.add_parser("disassemble", aliases=["dis"], help=disassemble.__doc__)
    disassemble_cmd_parser.set_defaults(func=disassemble)
    _add_binary_args(disassemble_cmd_parser)
    disassemble_cmd_parser.add_argument(
        "--functions",
        help="""
        The functions to disassemble. Functions can either be expressed as names found in the
        symbols of the binary or as addresses like: 0x401000.""",
        nargs="+",
    )

    args = parser.parse_args(_maybe_reorder_args(sys.argv[1:]))

    log_level = max(logging.ERROR - (10 * args.verbose), logging.DEBUG)
    logging.getLogger("angr").setLevel(log_level)

    args.func(args)


if __name__ == "__main__":
    main()
