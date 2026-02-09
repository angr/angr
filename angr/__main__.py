from __future__ import annotations

import argparse
import hashlib
import logging
import os
import pathlib
import re
import sys
from typing import TYPE_CHECKING
from collections.abc import Generator

from rich.syntax import Syntax
from rich.console import Console

import angr
from angr.analyses.decompiler import DECOMPILATION_PRESETS
from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION
from angr.analyses.decompiler.structuring import STRUCTURER_CLASSES, DEFAULT_STRUCTURER

try:
    from angr.angrdb import AngrDB
except ImportError:
    AngrDB = None
from angr.utils.formatting import ansi_color_enabled

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


log = logging.getLogger(__name__)


_CACHE_DIR = pathlib.Path(os.environ.get("ANGR_CACHE_DIR", os.path.join("~", ".cache", "angr"))).expanduser()

NUMERIC_ARG_RE = re.compile(r"^(0x)?[a-fA-F0-9]+$")
KNOWN_COMMANDS = frozenset({"decompile", "dec", "disassemble", "dis"})
# Options that take a value argument (used for backwards-compat argv reordering)
_OPTIONS_WITH_VALUE = frozenset({"--base-addr", "--structurer", "--preset", "--theme"})


def _cache_path_for(binary: str, base_addr: int | None = None) -> pathlib.Path:
    """Return the deterministic AngrDB cache path for *binary*."""
    binary_resolved = str(pathlib.Path(binary).resolve())
    key = binary_resolved
    if base_addr is not None:
        key += f":base_addr={base_addr:#x}"
    digest = hashlib.sha256(key.encode()).hexdigest()[:16]
    name = pathlib.Path(binary_resolved).name
    return _CACHE_DIR / f"{name}-{digest}.angrdb"


def _cache_is_fresh(cache_path: pathlib.Path, binary: str) -> bool:
    """Return True if *cache_path* exists and is newer than *binary*."""
    try:
        return cache_path.stat().st_mtime >= pathlib.Path(binary).resolve().stat().st_mtime
    except OSError:
        return False


def _load_project_from_cache(cache_path: pathlib.Path) -> angr.Project | None:
    """Try to load a project (with CFG) from the AngrDB cache."""
    if AngrDB is None:
        return None
    try:
        angrdb = AngrDB()
        proj = angrdb.load(str(cache_path))
        log.info("Loaded cached analysis from %s", cache_path)
        return proj
    except Exception:  # pylint:disable=broad-exception-caught
        log.debug("Failed to load cache %s, will recompute", cache_path, exc_info=True)
        return None


def _save_project_to_cache(proj: angr.Project, cache_path: pathlib.Path) -> None:
    """Save the project's knowledge base to the AngrDB cache."""
    if AngrDB is None:
        return
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        angrdb = AngrDB(project=proj)
        angrdb.dump(str(cache_path))
        log.info("Saved analysis cache to %s", cache_path)
    except Exception:  # pylint:disable=broad-exception-caught
        log.debug("Failed to save cache to %s", cache_path, exc_info=True)


def _load_or_analyze(
    binary: str, base_addr: int | None = None, no_cache: bool = False, progressbar: bool = False
) -> angr.Project:
    """
    Load a project with CFG results, using a cache when possible.

    If a valid cache exists for *binary*, load from it.  Otherwise create a
    fresh project, run CFGFast, and persist the results for next time.
    """
    cache_path = _cache_path_for(binary, base_addr)

    # Try loading from cache
    if not no_cache and _cache_is_fresh(cache_path, binary):
        proj = _load_project_from_cache(cache_path)
        if proj is not None:
            return proj

    # Fresh analysis
    loader_main_opts = {}
    if base_addr is not None:
        loader_main_opts["base_addr"] = base_addr
    proj = angr.Project(binary, auto_load_libs=False, main_opts=loader_main_opts)
    proj.analyses.CFG(normalize=True, data_references=True, show_progressbar=progressbar)

    # Persist to cache
    if not no_cache:
        _save_project_to_cache(proj, cache_path)

    return proj


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
    proj = _load_or_analyze(args.binary, base_addr=args.base_addr, no_cache=args.no_cache)

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
    structurer = args.structurer or DEFAULT_STRUCTURER.NAME

    proj = _load_or_analyze(args.binary, base_addr=args.base_addr, no_cache=args.no_cache, progressbar=args.progress)
    cfg = proj.kb.cfgs["CFGFast"]

    if args.cca:
        proj.analyses.CompleteCallingConventions(
            analyze_callsites=args.cca_callsites,
            show_progressbar=args.progress,  # type: ignore[call-arg]
        )

    # Resolve which functions to decompile
    functions = args.functions
    if functions is None:
        functions = sorted(proj.kb.functions)
    else:
        normalized: list[int | str] = []
        for func in functions:
            try:
                normalized.append(int(func, 0) if isinstance(func, str) else func)
            except ValueError:
                normalized.append(func)
        functions = normalized

    # Verify functions exist
    for func in list(functions):
        if func not in proj.kb.functions:
            if args.catch_exceptions:
                log.warning("Function %s does not exist in the CFG.", str(func))
                functions.remove(func)
            else:
                raise ValueError(f"Function {func} does not exist in the CFG.")

    # Decompile
    dec_options = [
        (PARAM_TO_OPTION["structurer_cls"], structurer),
        (PARAM_TO_OPTION["show_casts"], not args.no_casts),
    ]
    decompilation = ""
    for func in functions:
        f = proj.kb.functions[func]
        if f is None or f.is_plt or f.is_syscall or f.is_alignment or f.is_simprocedure:
            continue

        exception_string = ""
        if not args.catch_exceptions:
            dec = proj.analyses.Decompiler(
                f,
                cfg=cfg,
                options=dec_options,
                preset=args.preset,
                show_progressbar=args.progress,  # type: ignore[call-arg]
            )
        else:
            try:
                dec = proj.analyses.Decompiler(
                    f,
                    cfg=cfg,
                    options=dec_options,
                    preset=args.preset,
                    show_progressbar=args.progress,
                    fail_fast=True,  # type: ignore[call-arg]
                )
            except Exception as e:  # pylint:disable=broad-exception-caught
                exception_string = str(e).replace("\n", " ")
                dec = None

        if not exception_string and (dec is None or not dec.codegen or not dec.codegen.text):
            exception_string = "Decompilation had no code output (failed in decompilation)"

        if exception_string:
            log.critical("Failed to decompile %s because %s", repr(f), exception_string)
            decompilation += f"// [error: {func} | {exception_string}]\n"
        else:
            if dec is not None and dec.codegen is not None and dec.codegen.text is not None:
                decompilation += dec.codegen.text
            else:
                decompilation += "Invalid decompilation output"
            decompilation += "\n"

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
    parser.add_argument(
        "--no-cache",
        help="Disable automatic caching of analysis results between invocations.",
        action="store_true",
        default=False,
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
