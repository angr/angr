from __future__ import annotations

import argparse
import logging
import re
from typing import TYPE_CHECKING
from collections.abc import Generator

import angr
from angr.analyses.decompiler import DECOMPILATION_PRESETS
from angr.analyses.decompiler.structuring import STRUCTURER_CLASSES, DEFAULT_STRUCTURER
from angr.analyses.decompiler.utils import decompile_functions


if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


log = logging.getLogger(__name__)


NUMERIC_ARG_RE = re.compile(r"^(0x)?[a-fA-F0-9]+$")


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
    )
    print(decompilation)


def main():
    parser = argparse.ArgumentParser(description="The angr CLI allows you to decompile and analyze binaries.")
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
    subparsers = parser.add_subparsers(metavar="command", required=True)

    decompile_cmd_parser = subparsers.add_parser("decompile", aliases=["dec"], help=decompile.__doc__)
    decompile_cmd_parser.set_defaults(func=decompile)
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
        "--functions",
        help="""
        The functions to decompile. Functions can either be expressed as names found in the
        symbols of the binary or as addresses like: 0x401000.""",
        nargs="+",
    )

    disassemble_cmd_parser = subparsers.add_parser("disassemble", aliases=["dis"], help=disassemble.__doc__)
    disassemble_cmd_parser.set_defaults(func=disassemble)
    disassemble_cmd_parser.add_argument(
        "--functions",
        help="""
        The functions to disassemble. Functions can either be expressed as names found in the
        symbols of the binary or as addresses like: 0x401000.""",
        nargs="+",
    )

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
