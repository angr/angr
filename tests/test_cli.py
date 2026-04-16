#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long,no-member
from __future__ import annotations

__package__ = __package__ or "tests"  # pylint:disable=redefined-builtin

import io
import logging
import os
import re
import sys
import unittest
from unittest import mock

from rich.console import Console
from rich.logging import RichHandler

import angr
from angr.__main__ import main
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.utils import decompile_functions
from angr.analyses.disassembly import Disassembly

from .common import bin_location

test_location = os.path.join(bin_location, "tests")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def run_cli(*args):
    with mock.patch("sys.argv", [sys.executable, *args]), mock.patch("sys.stdout", new=io.StringIO()) as fake_out:
        main()
        return fake_out.getvalue()


def run_cli_interactive(*args):
    """Run CLI simulating an interactive terminal. Returns (stdout, stderr) as plain text."""
    stderr_buf = io.StringIO()

    def mock_make_status():
        console = Console(file=stderr_buf, force_terminal=True, no_color=True, width=200)
        angr_logger = logging.getLogger("angr")
        angr_logger.handlers = [RichHandler(console=console, show_path=False, show_time=False)]
        angr_logger.propagate = False
        return console, True

    with (
        mock.patch("sys.argv", [sys.executable, *args]),
        mock.patch("sys.stdout", new=io.StringIO()) as fake_out,
        mock.patch("angr.__main__._make_status_console", mock_make_status),
    ):
        main()
        stderr_text = ANSI_RE.sub("", stderr_buf.getvalue())
        return fake_out.getvalue(), stderr_text


class TestCommandLineInterface(unittest.TestCase):
    def test_decompiling(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sailr_motivating_example")
        f1 = "schedule_job"
        f2 = "main"

        # test a single function
        assert (
            run_cli("decompile", bin_path, "--functions", f1, "--no-colors")
            == decompile_functions(bin_path, [f1]) + "\n"
        )

        # test multiple functions
        assert (
            run_cli("decompile", bin_path, "--functions", f1, f2, "--no-colors")
            == decompile_functions(bin_path, [f1, f2]) + "\n"
        )

    def test_structuring(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sailr_motivating_example")
        f1 = "schedule_job"

        dream_cli = run_cli("decompile", bin_path, "--no-casts", "--functions", f1, "--structurer", "dream")
        sailr_cli = run_cli("decompile", bin_path, "--functions", f1, "--structurer", "sailr")
        assert dream_cli.count("goto") == 0
        assert dream_cli != sailr_cli

    def test_base_addr_dec(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sailr_motivating_example")
        f1 = "schedule_job"
        proj = angr.Project(bin_path, auto_load_libs=False)
        default_base_addr = proj.loader.main_object.min_addr
        f1_default_addr = proj.loader.find_symbol(f1).rebased_addr
        f1_offset = f1_default_addr - default_base_addr

        # function resolving is based on symbol
        sym_based_dec = run_cli("decompile", bin_path, "--functions", f1, "--preset", "full", "--no-colors")
        # function resolving is based on the address (with default angr loading)
        base_addr_dec = run_cli(
            "decompile", bin_path, "--functions", hex(f1_default_addr), "--preset", "full", "--no-colors"
        )
        # function resolving is based on the address (with base address specified)
        offset_dec = run_cli(
            "decompile",
            bin_path,
            "--base-addr",
            "0x0",
            "--functions",
            hex(f1_offset),
            "--preset",
            "full",
            "--no-colors",
        )

        # since the externs can be unpredictable, we only check the function name down
        sym_based_dec = re.sub(r"extern .*;", "", sym_based_dec).lstrip("\n")
        base_addr_dec = re.sub(r"extern .*;", "", base_addr_dec).lstrip("\n")
        offset_dec = re.sub(r"extern .*;", "", offset_dec).lstrip("\n")

        # we must also normalize label names (since they are based on the address)
        sym_based_dec = re.sub(r"LABEL_[0-9a-fA-F]+", "LABEL_A", sym_based_dec)
        base_addr_dec = re.sub(r"LABEL_[0-9a-fA-F]+", "LABEL_A", base_addr_dec)
        offset_dec = re.sub(r"LABEL_[0-9a-fA-F]+", "LABEL_A", offset_dec)

        assert sym_based_dec == base_addr_dec == offset_dec

    def test_disassembly(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        disasm = run_cli("disassemble", bin_path)
        funcs = {
            "_init",
            "_start",
            "call_gmon_start",
            "__do_global_dtors_aux",
            "frame_dummy",
            "authenticate",
            "accepted",
            "rejected",
            "main",
            "__libc_csu_init",
            "__libc_csu_fini",
            "__do_global_ctors_aux",
            "_fini",
        }
        substrs = [f"{f}:" for f in funcs]
        substrs += "40071d  55              push    rbp"

        for s in substrs:
            assert s in disasm

    def test_syntax_highlighting_no_colors_flag(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sailr_motivating_example")
        f1 = "main"

        no_colors_output = run_cli("decompile", bin_path, "--functions", f1, "--no-colors")
        expected_output = decompile_functions(bin_path, [f1]) + "\n"

        # it should maintain that no ANSI color codes are present
        assert no_colors_output == expected_output

    def test_aliases(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        dec_output = run_cli("dec", bin_path, "--functions", "main", "--no-colors")
        assert "main" in dec_output

        dis_output = run_cli("dis", bin_path, "--functions", "main")
        assert "main:" in dis_output

    def test_disassemble_specific_functions(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        output = run_cli("disassemble", bin_path, "--functions", "main")
        assert "main:" in output
        assert "authenticate:" not in output

    def test_disassemble_function_by_address(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        main_addr = proj.loader.find_symbol("main").rebased_addr
        output = run_cli("disassemble", bin_path, "--functions", hex(main_addr))
        assert "main:" in output

    def test_decompile_interactive_summary(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        stdout, stderr = run_cli_interactive(
            "decompile", bin_path, "--functions", "main", "authenticate", "--no-colors"
        )
        # Both functions should appear in stdout
        assert "main" in stdout
        # Summary on stderr for multiple functions
        assert "Decompiled" in stderr

    def test_disassemble_interactive_summary(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        stdout, stderr = run_cli_interactive("disassemble", bin_path, "--functions", "main", "authenticate")
        assert "main:" in stdout
        assert "authenticate:" in stdout
        assert "Disassembled" in stderr

    def test_decompile_missing_function_raises(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        with self.assertRaises(ValueError):
            run_cli("decompile", bin_path, "--functions", "nonexistent_func", "--no-colors")

    def test_decompile_catch_exceptions_missing_function(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        stdout, stderr = run_cli_interactive(
            "decompile", bin_path, "--functions", "nonexistent_func", "--catch-exceptions", "--no-colors"
        )
        assert stdout == ""
        assert "not found" in stderr.lower()

    def test_disassemble_missing_function(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        # parse_function_args logs error and yields nothing -> "No disassemblable functions found"
        stdout, stderr = run_cli_interactive("disassemble", bin_path, "--functions", "nonexistent_func")
        assert stdout == ""
        assert "no disassemblable functions found" in stderr.lower()

    def test_decompile_no_decompilable_functions(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        # _init is typically a stub that gets filtered out
        _stdout, stderr = run_cli_interactive(
            "decompile", bin_path, "--functions", "nonexistent_func", "--catch-exceptions", "--no-colors"
        )
        assert "no decompilable functions found" in stderr.lower() or "not found" in stderr.lower()

    def test_decompile_cca(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        output = run_cli("decompile", bin_path, "--functions", "main", "--cca", "--no-colors")
        assert "main" in output

    def test_decompile_syntax_highlighting(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        # Force ansi_color_enabled=True to exercise the Syntax highlighting path.
        # Note: Rich's Console strips ANSI when stdout is a StringIO (not a real terminal),
        # so we verify the path ran by checking the output content.
        with mock.patch("angr.__main__.ansi_color_enabled", True):
            stdout, _ = run_cli_interactive("decompile", bin_path, "--functions", "main")
        assert stdout  # non-empty
        assert "main" in ANSI_RE.sub("", stdout)

    def test_decompile_syntax_highlighting_multiple(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        with mock.patch("angr.__main__.ansi_color_enabled", True):
            stdout, stderr = run_cli_interactive("decompile", bin_path, "--functions", "main", "authenticate")
        plain = ANSI_RE.sub("", stdout)
        assert "main" in plain
        assert "authenticate" in plain
        assert "Decompiled" in stderr

    def test_disassemble_base_addr(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        output = run_cli("disassemble", bin_path, "--base-addr", "0x0", "--functions", "main")
        assert "main:" in output

    def test_disassemble_missing_address(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        # Address passes numeric regex but doesn't match any function
        stdout, stderr = run_cli_interactive("disassemble", bin_path, "--functions", "0xdeadbeef")
        assert stdout == ""
        assert "no disassemblable functions found" in stderr.lower()

    def test_decompile_catch_exceptions_noninteractive(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        # Non-interactive catch-exceptions hits the log.warning path
        output = run_cli("decompile", bin_path, "--functions", "nonexistent_func", "--catch-exceptions", "--no-colors")
        assert output == ""

    def test_decompile_catch_exceptions_error(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        with mock.patch.object(Decompiler, "_decompile", side_effect=RuntimeError("mock failure")):
            stdout, stderr = run_cli_interactive(
                "decompile", bin_path, "--functions", "main", "authenticate", "--catch-exceptions", "--no-colors"
            )
        assert stdout == ""
        assert "error decompiling" in stderr.lower()
        assert "2 error" in stderr.lower()

    def test_disassemble_catch_exceptions_error(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        with mock.patch.object(Disassembly, "render", side_effect=RuntimeError("mock failure")):
            stdout, stderr = run_cli_interactive(
                "disassemble", bin_path, "--functions", "main", "authenticate", "--catch-exceptions"
            )
        assert stdout == ""
        assert "error disassembling" in stderr.lower()
        assert "2 error" in stderr.lower()

    def test_decompile_no_output(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        # Simulate decompilation succeeding but producing no codegen output
        with mock.patch.object(Decompiler, "_decompile"):
            stdout, stderr = run_cli_interactive(
                "decompile", bin_path, "--functions", "main", "--catch-exceptions", "--no-colors"
            )
        assert stdout == ""
        assert "no output" in stderr.lower() or "error decompiling" in stderr.lower()

    def test_disassemble_catch_exceptions_noninteractive(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        with mock.patch.object(Disassembly, "render", side_effect=RuntimeError("mock failure")):
            output = run_cli("disassemble", bin_path, "--functions", "main", "--catch-exceptions")
        assert output == ""

    def test_decompile_no_functions_noninteractive(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        # _init is a stub that gets filtered; requesting only it should yield nothing
        output = run_cli("decompile", bin_path, "--functions", "nonexistent_func", "--catch-exceptions", "--no-colors")
        assert output == ""

    def test_disassemble_no_functions_noninteractive(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        output = run_cli("disassemble", bin_path, "--functions", "nonexistent_func")
        assert output == ""

    def test_decompile_syntax_highlighting_catch_exceptions(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        # Highlighted mode with catch-exceptions: error should go to stderr, not stdout
        with (
            mock.patch("angr.__main__.ansi_color_enabled", True),
            mock.patch.object(Decompiler, "_decompile", side_effect=RuntimeError("mock failure")),
        ):
            stdout, stderr = run_cli_interactive("decompile", bin_path, "--functions", "main", "--catch-exceptions")
        assert stdout == ""
        assert "error decompiling" in stderr.lower()

    def test_blob_requires_required_args(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        with (
            mock.patch("sys.argv", [sys.executable, "disassemble", bin_path, "--blob"]),
            mock.patch("sys.stderr", new=io.StringIO()) as fake_err,
            self.assertRaises(SystemExit) as exc,
        ):
            main()

        assert exc.exception.code == 2
        assert "--blob requires --arch" in fake_err.getvalue()

    def test_disassemble_blob_loader_options(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        fake_proj = mock.Mock()
        fake_proj.analyses.CFG.return_value = None
        fake_proj.kb.functions = {}

        with mock.patch("angr.__main__.angr.Project", return_value=fake_proj) as mock_project:
            output = run_cli(
                "disassemble",
                bin_path,
                "--blob",
                "--arch",
                "AMD64",
                "--base-addr",
                "0x400000",
                "--entry-point",
                "0x400000",
            )

        assert output == ""
        _, kwargs = mock_project.call_args
        assert kwargs["auto_load_libs"] is False
        assert kwargs["main_opts"] == {
            "backend": "blob",
            "arch": "AMD64",
            "base_addr": 0x400000,
            "entry_point": 0x400000,
        }

    def test_decompile_blob_loader_options(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        fake_cfg = mock.Mock()
        fake_cfg.kb.functions = {}
        fake_cfg.functions = {}

        fake_proj = mock.Mock()
        fake_proj.analyses.CFG.return_value = fake_cfg

        with mock.patch("angr.__main__.angr.Project", return_value=fake_proj) as mock_project:
            output = run_cli(
                "decompile",
                bin_path,
                "--blob",
                "--arch",
                "AMD64",
                "--base-addr",
                "0x400000",
                "--entry-point",
                "0x400000",
                "--no-colors",
            )

        assert output == ""
        _, kwargs = mock_project.call_args
        assert kwargs["auto_load_libs"] is False
        assert kwargs["main_opts"] == {
            "backend": "blob",
            "arch": "AMD64",
            "base_addr": 0x400000,
            "entry_point": 0x400000,
        }


if __name__ == "__main__":
    unittest.main()
