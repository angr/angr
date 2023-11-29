import argparse

from angr.analyses.decompiler.structuring import STRUCTURER_CLASSES
from angr.analyses.decompiler.utils import decompile_functions


class COMMANDS:
    """
    The commands that the angr CLI supports.
    """

    DECOMPILE = "decompile"
    ALL_COMMANDS = [DECOMPILE]


def main():
    parser = argparse.ArgumentParser(description="The angr CLI allows you to decompile and analyze binaries.")
    parser.add_argument(
        "command",
        help="""
        The analysis type to run on the binary. All analysis is output to stdout.""",
        choices=COMMANDS.ALL_COMMANDS,
    )
    parser.add_argument("binary", help="The path to the binary to analyze.")
    parser.add_argument(
        "--functions",
        help="""
        The functions to analyze under the current command. Functions can either be expressed as names found in the
        symbols of the binary or as addresses like: 0x401000.""",
        nargs="+",
    )
    parser.add_argument(
        "--catch-exceptions",
        help="""
        Catch exceptions during analysis. The scope of error handling may depend on the command used for analysis.
        If multiple functions are specified for analysis, each function will be handled individually.""",
        action="store_true",
        default=False,
    )
    # decompilation-specific arguments
    parser.add_argument(
        "--structurer",
        help="The structuring algorithm to use for decompilation.",
        choices=STRUCTURER_CLASSES.keys(),
        default="phoenix",
    )

    args = parser.parse_args()
    if args.command == COMMANDS.DECOMPILE:
        decompilation = decompile_functions(
            args.binary, functions=args.functions, structurer=args.structurer, catch_errors=args.catch_exceptions
        )
        print(decompilation)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
