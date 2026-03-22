from __future__ import annotations

import argparse
import contextlib
import logging
import re
from typing import TYPE_CHECKING
from collections.abc import Generator

from rich import progress as rich_progress
from rich.logging import RichHandler
from rich.syntax import Syntax
from rich.console import Console
from rich.table import Column

import angr
from angr.analyses.decompiler import DECOMPILATION_PRESETS
from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION
from angr.analyses.decompiler.structuring import STRUCTURER_CLASSES, DEFAULT_STRUCTURER
from angr.utils.formatting import ansi_color_enabled

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

pdb = __import__("pdb")
with contextlib.suppress(ImportError):
    pdb = __import__("ipdb")


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


def _make_status_console() -> tuple[Console, bool]:
    """Create a stderr console for status messages and determine if interactive status should be shown.

    Also installs a RichHandler on the angr logger so that log messages integrate
    properly with Rich's live progress displays instead of corrupting them.
    """
    console = Console(stderr=True)
    angr_logger = logging.getLogger("angr")
    angr_logger.handlers = [RichHandler(console=console, show_path=False, show_time=False)]
    angr_logger.propagate = False
    return console, console.is_terminal


def _make_progress(*extra_columns) -> tuple:
    """Build the standard column set for progress bars.

    The status text is placed *after* the bar so changing its length
    doesn't shift the bar and percentage around.
    """
    return (
        rich_progress.SpinnerColumn(),
        rich_progress.TextColumn("{task.description}"),
        rich_progress.BarColumn(),
        rich_progress.TaskProgressColumn(),
        rich_progress.TimeElapsedColumn(),
        *extra_columns,
    )


@contextlib.contextmanager
def _stderr_progress(console: Console, description: str, show: bool = True):
    """Show a progress bar on stderr for a long-running analysis.

    Yields a progress_callback compatible with angr's Analysis infrastructure.
    When not in a terminal, yields None (no progress display).
    """
    if not show:
        yield None
        return

    status_col = rich_progress.TextColumn("{task.fields[status]}")
    p = rich_progress.Progress(*_make_progress(status_col), console=console, redirect_stderr=True, transient=True)
    task_id = p.add_task(f"[bold]{description}", total=100, status="")

    def callback(percentage: float, text: str | None = None, **_kwargs) -> None:
        p.update(task_id, completed=percentage, status=text or "")

    with p:
        yield callback


class _NoOpTracker:
    """No-op tracker when progress display is disabled."""

    @contextlib.contextmanager
    def task(self, _name):  # pylint:disable=no-self-use
        yield None


_MAX_NAME_WIDTH = 20


@contextlib.contextmanager
def _multi_progress(console: Console, total: int, description: str, show: bool = True):
    """Progress tracker with an overall bar and per-item sub-task progress.

    The display is paused between tasks so stdout output doesn't corrupt the terminal.
    Yields a tracker whose ``task()`` context manager creates a sub-task progress bar
    and yields a ``progress_callback`` for the analysis.
    """
    if not show:
        yield _NoOpTracker()
        return

    prefix_len = 2 if total > 1 else 0  # "  " indent for sub-tasks
    desc_width = max(len(description), _MAX_NAME_WIDTH + prefix_len)
    status_col = rich_progress.TextColumn("{task.fields[status]}")
    p = rich_progress.Progress(
        rich_progress.SpinnerColumn(),
        rich_progress.TextColumn("{task.description}", table_column=Column(min_width=desc_width, max_width=desc_width)),
        rich_progress.BarColumn(),
        rich_progress.TaskProgressColumn(),
        rich_progress.TimeElapsedColumn(),
        status_col,
        console=console,
        redirect_stderr=True,
        transient=True,
    )
    overall = p.add_task(f"[bold]{description}", total=total, status="") if total > 1 else None

    class _Tracker:  # pylint:disable=missing-class-docstring
        @contextlib.contextmanager
        def task(self, name):  # pylint:disable=no-self-use
            prefix = "  " if overall is not None else ""
            display_name = (
                name
                if len(name) <= _MAX_NAME_WIDTH - len(prefix)
                else name[: _MAX_NAME_WIDTH - len(prefix) - 1] + "\u2026"
            )
            sub = p.add_task(f"{prefix}{display_name}", total=100, status="")
            p.start()

            def callback(percentage: float, text: str | None = None, **_kwargs) -> None:
                p.update(sub, completed=percentage, status=text or "")

            try:
                yield callback
            finally:
                p.remove_task(sub)
                if overall is not None:
                    p.advance(overall)
                p.stop()

    try:
        yield _Tracker()
    finally:
        p.stop()


def disassemble(args):
    """
    Disassemble functions.
    """
    err, show_status = _make_status_console()
    if not args.pbar:
        show_status = False

    loader_main_opts_kwargs = {}
    if args.blob:
        loader_main_opts_kwargs["backend"] = "blob"
    if args.base_addr is not None:
        loader_main_opts_kwargs["base_addr"] = args.base_addr
    if args.arch is not None:
        loader_main_opts_kwargs["arch"] = args.arch
    if args.entry_point is not None:
        loader_main_opts_kwargs["entry_point"] = args.entry_point

    proj = angr.Project(args.binary, auto_load_libs=False, main_opts=loader_main_opts_kwargs)

    with _stderr_progress(err, "Recovering control flow graph", show=show_status) as progress_cb:
        proj.analyses.CFG(  # pyright: ignore[reportCallIssue]
            normalize=True, data_references=True, progress_callback=progress_cb
        )

    # Collect disassemblable functions
    funcs = [
        f
        for f in parse_function_args(proj, args.functions)
        if not (f.is_plt or f.is_syscall or f.is_alignment or f.is_simprocedure)
    ]

    total = len(funcs)
    if total == 0:
        if show_status:
            err.print("[yellow]No disassemblable functions found[/yellow]")
        return

    success_count = 0
    error_count = 0

    with _multi_progress(err, total, "Disassembling", show=show_status) as tracker:
        for func in funcs:
            func_name = func.name or hex(func.addr)

            exception_string = ""
            text = ""
            with tracker.task(func_name):
                try:
                    disasm = proj.analyses.Disassembly(func)
                    text = disasm.render(show_bytes=True, min_edge_depth=10)
                except Exception as e:  # pylint:disable=broad-exception-caught
                    if args.pdb:
                        pdb.post_mortem(e.__traceback__)
                    elif not args.catch_exceptions:
                        raise
                    exception_string = str(e).replace("\n", " ")

            # Progress is paused here -- safe to print to stdout / stderr
            if exception_string:
                error_count += 1
                if show_status:
                    err.print(f"[red]Error disassembling {func_name}:[/red] {exception_string}")
                else:
                    log.error(exception_string)
            else:
                success_count += 1
                print(text)

    # Summary for interactive sessions
    if show_status and total > 1:
        if error_count:
            err.print(
                f"Disassembled {success_count}/{total} functions ({error_count} error{'s' if error_count != 1 else ''})"
            )
        else:
            err.print(f"Disassembled {success_count} functions")


def decompile(args):
    """
    Decompile functions.
    """
    structurer = args.structurer or DEFAULT_STRUCTURER.NAME
    should_highlight = ansi_color_enabled and not args.no_colors
    err, show_status = _make_status_console()
    if not args.pbar:
        show_status = False

    loader_main_opts_kwargs = {}
    if args.blob:
        loader_main_opts_kwargs["backend"] = "blob"
    if args.base_addr is not None:
        loader_main_opts_kwargs["base_addr"] = args.base_addr
    if args.arch is not None:
        loader_main_opts_kwargs["arch"] = args.arch
    if args.entry_point is not None:
        loader_main_opts_kwargs["entry_point"] = args.entry_point

    # Load binary
    proj = angr.Project(args.binary, auto_load_libs=False, main_opts=loader_main_opts_kwargs)

    # CFG recovery with progress on stderr
    with _stderr_progress(err, "Recovering control flow graph", show=show_status) as progress_cb:
        cfg = proj.analyses.CFG(  # pyright: ignore[reportCallIssue]
            normalize=True, data_references=True, progress_callback=progress_cb
        )

    # Complete calling conventions with progress on stderr
    if args.cca:
        with _stderr_progress(err, "Recovering calling conventions", show=show_status) as progress_cb:
            proj.analyses.CompleteCallingConventions(
                analyze_callsites=args.cca_callsites,
                progress_callback=progress_cb,  # pyright: ignore[reportCallIssue]
            )

    # Collect and normalize function identifiers
    if args.functions is None:
        func_ids = sorted(cfg.kb.functions)
    else:
        func_ids = []
        for func_arg in args.functions:
            try:
                func_id = int(func_arg, 0) if isinstance(func_arg, str) else func_arg
            except ValueError:
                func_id = func_arg
            if func_id not in cfg.functions:
                if args.catch_exceptions:
                    if show_status:
                        err.print(f"[yellow]Warning:[/yellow] Function {func_arg!r} not found")
                    else:
                        log.warning("Function %s does not exist in the CFG.", func_arg)
                    continue
                raise ValueError(f"Function {func_arg} does not exist in the CFG.")
            func_ids.append(func_id)

    # Filter to decompilable functions
    funcs = []
    for func_id in func_ids:
        f = cfg.functions[func_id]
        if f is not None and not (f.is_plt or f.is_syscall or f.is_alignment or f.is_simprocedure):
            funcs.append(f)

    total = len(funcs)
    if total == 0:
        if show_status:
            err.print("[yellow]No decompilable functions found[/yellow]")
        return

    # Prepare decompilation options
    dec_options = [
        (PARAM_TO_OPTION["structurer_cls"], structurer),
        (PARAM_TO_OPTION["show_casts"], not args.no_casts),
    ]
    if args.llm:
        dec_options.append(("llm_refine", True))

    out = Console(highlight=False)
    success_count = 0
    error_count = 0

    with _multi_progress(err, total, "Decompiling", show=show_status) as tracker:
        for func in funcs:
            func_name = func.name or hex(func.addr)

            # Decompile with progress bar showing per-stage status
            exception_string = ""
            dec = None
            with tracker.task(func_name) as progress_cb:
                try:
                    if args.catch_exceptions:
                        dec = proj.analyses.Decompiler(
                            func,
                            cfg=cfg,
                            options=dec_options,
                            preset=args.preset,
                            fail_fast=True,  # pyright: ignore[reportCallIssue]
                            progress_callback=progress_cb,  # pyright: ignore[reportCallIssue]
                        )
                    else:
                        dec = proj.analyses.Decompiler(
                            func,
                            cfg=cfg,
                            options=dec_options,
                            preset=args.preset,
                            progress_callback=progress_cb,  # pyright: ignore[reportCallIssue]
                        )
                except Exception as e:  # pylint:disable=broad-exception-caught
                    if args.pdb:
                        pdb.post_mortem(e.__traceback__)
                    elif not args.catch_exceptions:
                        raise
                    exception_string = str(e).replace("\n", " ")

            # Progress is paused here -- safe to print to stdout / stderr
            if not exception_string and (dec is None or not dec.codegen or not dec.codegen.text):
                exception_string = "Decompilation produced no output"

            if exception_string:
                error_count += 1
                if show_status:
                    err.print(f"[red]Error decompiling {func_name}:[/red] {exception_string}")
                else:
                    log.critical("Failed to decompile %s: %s", func_name, exception_string)
            else:
                success_count += 1
                assert dec is not None and dec.codegen is not None
                text = dec.codegen.text
                if should_highlight:
                    syntax = Syntax(text + "\n", "c", theme=args.theme, line_numbers=False)  # type: ignore[operator]
                    out.print(syntax)
                else:
                    print(text)

    # Trailing newline for plain text output
    if not should_highlight and success_count > 0:
        print()

    # Summary for interactive sessions
    if show_status and total > 1:
        if error_count:
            err.print(
                f"Decompiled {success_count}/{total} functions ({error_count} error{'s' if error_count != 1 else ''})"
            )
        else:
            err.print(f"Decompiled {success_count} functions")


def _add_common_args(subparser):
    """Add arguments common to all subcommands."""
    subparser.add_argument("binary", help="The path to the binary to analyze.")
    subparser.add_argument(
        "--catch-exceptions",
        help="""
        Catch exceptions during analysis. The scope of error handling may depend on the command used for analysis.
        If multiple functions are specified for analysis, each function will be handled individually.""",
        action="store_true",
        default=False,
    )
    subparser.add_argument(
        "--pdb",
        help="""
        Implies --catch-exceptions, and also launches a postmortem debug shell when we catch one.
        """,
        action="store_true",
        default=False,
    )
    subparser.add_argument(
        "--base-addr",
        help="""
        The base address of the binary. This is useful when the binary is loaded at a different address than the one
        specified in the ELF header.""",
        type=lambda x: int(x, 0),
        default=None,
    )
    subparser.add_argument(
        "--blob",
        help="Treat the input file as a raw binary blob instead of auto-detecting a file format.",
        action="store_true",
        default=False,
    )
    subparser.add_argument(
        "--arch",
        help="Architecture to use when loading a raw binary blob.",
        default=None,
    )
    subparser.add_argument(
        "--entry-point",
        help="Entry point to use when loading a raw binary blob.",
        type=lambda x: int(x, 0),
        default=None,
    )


def main():
    parser = argparse.ArgumentParser(description="The angr CLI allows you to decompile and analyze binaries.")
    parser.add_argument("--version", action="version", version=angr.__version__)
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Increase verbosity level (can be used multiple times)."
    )
    parser.add_argument(
        "-n",
        "--nopbar",
        action="store_false",
        dest="pbar",
        default=True,
        help="Disable progress bars; useful when debugging.",
    )
    subparsers = parser.add_subparsers(metavar="command", required=True)

    decompile_cmd_parser = subparsers.add_parser("decompile", aliases=["dec"], help=decompile.__doc__)
    decompile_cmd_parser.set_defaults(func=decompile)
    _add_common_args(decompile_cmd_parser)
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
        "--llm",
        help="Use an LLM to refine the decompilation output. The LLM must be configured separately using environment "
        "variables. You may only need to set ANGR_LLM_MODEL (see pydantic-ai model list) and ANGR_LLM_API_KEY. See "
        "the documentation for angr.LLMClient for details in LLM configuration.",
        action="store_true",
        default=False,
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
    _add_common_args(disassemble_cmd_parser)
    disassemble_cmd_parser.add_argument(
        "--functions",
        help="""
        The functions to disassemble. Functions can either be expressed as names found in the
        symbols of the binary or as addresses like: 0x401000.""",
        nargs="+",
    )

    args = parser.parse_args()

    if args.blob:
        if args.arch is None:
            parser.error("--blob requires --arch")
        if args.base_addr is None:
            parser.error("--blob requires --base-addr")
        if args.entry_point is None:
            parser.error("--blob requires --entry-point")

    log_level = max(logging.ERROR - (10 * args.verbose), logging.DEBUG)
    logging.getLogger("angr").setLevel(log_level)

    args.func(args)


if __name__ == "__main__":
    main()
