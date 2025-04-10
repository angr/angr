from __future__ import annotations

import argparse

from angr.analyses.decompiler import DECOMPILATION_PRESETS
from angr.analyses.decompiler.structuring import STRUCTURER_CLASSES, DEFAULT_STRUCTURER
from angr.analyses.decompiler.utils import decompile_functions


def decompile(args):
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

    decompile_cmd_parser = subparsers.add_parser("decompile", help="Decompile functions.")
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

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
