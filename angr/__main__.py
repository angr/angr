import argparse

from angr.analyses.decompiler.structuring import STRUCTURER_CLASSES
from angr.analyses.decompiler.utils import decompile_functions

COMMANDS = [
    "decompile",
]


def main():
    parser = argparse.ArgumentParser(description="The angr CLI allows you to decompile and analyze binaries.")
    parser.add_argument("command", help="The command to run", choices=COMMANDS)
    parser.add_argument("binary", help="The path to the binary to analyze")
    parser.add_argument("--functions", help="The functions to analyze", nargs="+")
    parser.add_argument(
        "--structurer", help="The structurer to use", choices=STRUCTURER_CLASSES.keys(), default="phoenix"
    )

    args = parser.parse_args()
    if args.command == "decompile":
        decompilation = decompile_functions(args.binary, functions=args.functions, structurer=args.structurer)
        print(decompilation)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
