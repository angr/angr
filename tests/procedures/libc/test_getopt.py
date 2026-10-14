#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import struct
import unittest

import angr
from angr import claripy


class TestGetopt(unittest.TestCase):
    # pylint: disable=no-self-use

    @staticmethod
    def _project():
        b = angr.load_shellcode(b"\x90\x90", "AMD64")
        # getopt's globals are data symbols the program reads back; create them
        # as externs so the SimProc can resolve their guest addresses.
        for name in ("optind", "optarg", "optopt", "opterr"):
            b.loader.extern_object.make_extern(name)
        return b

    @staticmethod
    def _layout(state, strings, base=0x700000):
        """Write a list of byte strings and a NULL-terminated argv array.

        Returns (argc, argv_ptr) and a dict name->addr for each string element.
        """
        addrs = []
        cur = base
        for s in strings:
            state.memory.store(cur, s + b"\x00")
            addrs.append(cur)
            cur += len(s) + 1
        argv_ptr = (cur + 0xF) & ~0xF
        ptr_fmt = "<Q"
        for i, a in enumerate(addrs):
            state.memory.store(argv_ptr + i * 8, struct.pack(ptr_fmt, a))
        state.memory.store(argv_ptr + len(addrs) * 8, struct.pack(ptr_fmt, 0))
        return len(addrs), argv_ptr, addrs

    def _getopt(self, state, b, argc, argv_ptr, optstr_addr, *extra, klass="getopt"):
        proc = angr.SIM_LIBRARIES["libc.so.6"][0].get(klass, arch=b.arch)
        proc.state = state
        return proc.run(argc, argv_ptr, optstr_addr, *extra)

    def _read_argv(self, state, argv_ptr, argc):
        return [state.solver.eval(state.memory.load(argv_ptr + i * 8, 8, endness="Iend_LE")) for i in range(argc)]

    def _read_optind(self, state, b):
        addr = b.loader.find_symbol("optind").rebased_addr
        return state.solver.eval(state.memory.load(addr, 4, endness=b.arch.memory_endness))

    def _read_optarg(self, state, b):
        addr = b.loader.find_symbol("optarg").rebased_addr
        return state.solver.eval(state.memory.load(addr, 8, endness=b.arch.memory_endness))

    def test_short_basic(self):
        b = self._project()
        state = b.factory.blank_state()
        # argv = ["prog", "-a", "-bvalue", "foo", "-c"], optstring "ab:c"
        argc, argv, addrs = self._layout(state, [b"prog", b"-a", b"-bvalue", b"foo", b"-c"])
        optstr = 0x680000
        state.memory.store(optstr, b"ab:c\x00")

        r1 = self._getopt(state, b, argc, argv, optstr)
        assert state.solver.eval(r1) == ord("a")
        assert self._read_optind(state, b) == 2

        r2 = self._getopt(state, b, argc, argv, optstr)
        assert state.solver.eval(r2) == ord("b")
        # optarg points at "value" inside argv[2] (just past "-b")
        assert self._read_optarg(state, b) == addrs[2] + 2
        assert self._read_optind(state, b) == 3

        # "foo" is an operand: like glibc, skip it and keep parsing options
        r3 = self._getopt(state, b, argc, argv, optstr)
        assert state.solver.eval(r3) == ord("c")

        # at the end, argv is permuted so the operand follows the options, and optind points at it
        r4 = self._getopt(state, b, argc, argv, optstr)
        assert state.solver.eval(r4) == 0xFFFFFFFF  # -1
        assert self._read_argv(state, argv, argc) == [addrs[0], addrs[1], addrs[2], addrs[4], addrs[3]]
        assert self._read_optind(state, b) == 4

    def _run_all(self, state, b, argc, argv, optstr):
        results = []
        for _ in range(argc + 1):
            r = state.solver.eval(self._getopt(state, b, argc, argv, optstr))
            if r == 0xFFFFFFFF:
                return results
            results.append(r)
        raise AssertionError(f"getopt did not return -1 after {argc + 1} calls: {results}")

    def test_operands_are_permuted(self):
        b = self._project()
        state = b.factory.blank_state()
        # "file -v" and a lone "-" operand, as in `prog file - -v -- -a`
        argc, argv, addrs = self._layout(state, [b"prog", b"file", b"-", b"-v", b"--", b"-a"])
        optstr = 0x680000
        state.memory.store(optstr, b"av\x00")
        assert self._run_all(state, b, argc, argv, optstr) == [ord("v")]
        # options first, then the operands in their original order; "--" stays before the operands after it
        assert self._read_argv(state, argv, argc) == [addrs[0], addrs[3], addrs[4], addrs[1], addrs[2], addrs[5]]
        assert self._read_optind(state, b) == 3

    def test_plus_stops_at_first_operand(self):
        b = self._project()
        state = b.factory.blank_state()
        argc, argv, addrs = self._layout(state, [b"prog", b"-a", b"file", b"-v"])
        optstr = 0x680000
        state.memory.store(optstr, b"+av\x00")
        assert self._run_all(state, b, argc, argv, optstr) == [ord("a")]
        assert self._read_optind(state, b) == 2
        assert self._read_argv(state, argv, argc) == addrs

    def test_dash_returns_operands_in_order(self):
        b = self._project()
        state = b.factory.blank_state()
        argc, argv, addrs = self._layout(state, [b"prog", b"file", b"-v"])
        optstr = 0x680000
        state.memory.store(optstr, b"-v\x00")
        r = self._getopt(state, b, argc, argv, optstr)
        # an operand is reported as the argument of option character 1
        assert state.solver.eval(r) == 1
        assert self._read_optarg(state, b) == addrs[1]
        assert self._run_all(state, b, argc, argv, optstr) == [ord("v")]

    def test_short_grouped_and_separate_arg(self):
        b = self._project()
        state = b.factory.blank_state()
        # argv = ["p", "-ab", "x"], optstring "ab:" -> 'a', then 'b' optarg="x"
        argc, argv, addrs = self._layout(state, [b"p", b"-ab", b"x"])
        optstr = 0x680000
        state.memory.store(optstr, b"ab:\x00")

        assert state.solver.eval(self._getopt(state, b, argc, argv, optstr)) == ord("a")
        r = self._getopt(state, b, argc, argv, optstr)
        assert state.solver.eval(r) == ord("b")
        # required arg taken from the next argv element "x"
        assert self._read_optarg(state, b) == addrs[2]
        assert self._read_optind(state, b) == 3

    def test_short_unknown_option(self):
        b = self._project()
        state = b.factory.blank_state()
        argc, argv, _ = self._layout(state, [b"p", b"-z"])
        optstr = 0x680000
        state.memory.store(optstr, b"ab\x00")
        r = self._getopt(state, b, argc, argv, optstr)
        assert state.solver.eval(r) == ord("?")
        addr = b.loader.find_symbol("optopt").rebased_addr
        assert state.solver.eval(state.memory.load(addr, 4, endness=b.arch.memory_endness)) == ord("z")

    def test_double_dash_terminates(self):
        b = self._project()
        state = b.factory.blank_state()
        argc, argv, _ = self._layout(state, [b"p", b"--", b"-a"])
        optstr = 0x680000
        state.memory.store(optstr, b"a\x00")
        r = self._getopt(state, b, argc, argv, optstr)
        assert state.solver.eval(r) == 0xFFFFFFFF
        # optind advanced past the "--"
        assert self._read_optind(state, b) == 2

    def test_symbolic_argv_falls_back(self):
        b = self._project()
        state = b.factory.blank_state()
        optstr = 0x680000
        state.memory.store(optstr, b"a\x00")
        sym_argv = claripy.BVS("argv", 64)
        optind = self._read_optind(state, b)
        r = self._getopt(state, b, 2, sym_argv, optstr)
        # unconstrained: no concrete commitment, both -1 and an option char possible
        assert len(state.solver.eval_upto(r, 3)) > 1
        # and nothing changes
        assert self._read_optind(state, b) == optind
        assert state.libc.getopt_optind == 1
        assert state.libc.getopt_nextchar == 0

    @staticmethod
    def _write_option(state, addr, name_ptr, has_arg, flag_ptr, val):
        state.memory.store(addr, struct.pack("<Q", name_ptr))
        state.memory.store(addr + 8, struct.pack("<i", has_arg))
        state.memory.store(addr + 16, struct.pack("<Q", flag_ptr))
        state.memory.store(addr + 24, struct.pack("<i", val))

    def test_getopt_long(self):
        b = self._project()
        state = b.factory.blank_state()
        # argv = ["p", "--verbose", "--file=out", "x"]
        argc, argv, addrs = self._layout(state, [b"p", b"--verbose", b"--file=out", b"x"])
        optstr = 0x680000
        state.memory.store(optstr, b"\x00")  # empty short optstring
        # longopts table: {"verbose",0,NULL,'v'},{"file",1,NULL,'f'},{NULL,...}
        names = 0x690000
        state.memory.store(names, b"verbose\x00")
        state.memory.store(names + 16, b"file\x00")
        table = 0x6A0000
        self._write_option(state, table, names, 0, 0, ord("v"))
        self._write_option(state, table + 32, names + 16, 1, 0, ord("f"))
        self._write_option(state, table + 64, 0, 0, 0, 0)
        longindex = 0x6B0000

        r1 = self._getopt(state, b, argc, argv, optstr, table, longindex, klass="getopt_long")
        assert state.solver.eval(r1) == ord("v")
        assert state.solver.eval(state.memory.load(longindex, 4, endness=b.arch.memory_endness)) == 0

        r2 = self._getopt(state, b, argc, argv, optstr, table, longindex, klass="getopt_long")
        assert state.solver.eval(r2) == ord("f")
        # optarg = "out" (just past "--file=")
        assert self._read_optarg(state, b) == addrs[2] + len(b"--file=")
        assert state.solver.eval(state.memory.load(longindex, 4, endness=b.arch.memory_endness)) == 1

        r3 = self._getopt(state, b, argc, argv, optstr, table, longindex, klass="getopt_long")
        assert state.solver.eval(r3) == 0xFFFFFFFF

    def test_getopt_long_inline_values(self):
        b = self._project()
        state = b.factory.blank_state()
        argc, argv, addrs = self._layout(state, [b"p", b"--level=hi", b"--verbose=x"])
        optstr = 0x680000
        state.memory.store(optstr, b"\x00")
        # {"level", optional_argument, NULL, 'L'}, {"verbose", no_argument, NULL, 'v'}
        names = 0x690000
        state.memory.store(names, b"level\x00")
        state.memory.store(names + 16, b"verbose\x00")
        table = 0x6A0000
        self._write_option(state, table, names, 2, 0, ord("L"))
        self._write_option(state, table + 32, names + 16, 0, 0, ord("v"))
        self._write_option(state, table + 64, 0, 0, 0, 0)

        r1 = self._getopt(state, b, argc, argv, optstr, table, 0, klass="getopt_long")
        assert state.solver.eval(r1) == ord("L")
        # optarg = "hi" (just past "--level=")
        assert self._read_optarg(state, b) == addrs[1] + len(b"--level=")

        # an option that takes no argument rejects "=x"
        r2 = self._getopt(state, b, argc, argv, optstr, table, 0, klass="getopt_long")
        assert state.solver.eval(r2) == ord("?")
        assert self._read_optind(state, b) == 3

    def _long_case(self, klass, optstring, options, args):
        """Run getopt_long(_only) to completion; return [(ret, optind, optopt, longindex)] and the final optarg."""
        b = self._project()
        state = b.factory.blank_state()
        argc, argv, _ = self._layout(state, [b"p", *args])
        optstr = 0x680000
        state.memory.store(optstr, optstring + b"\x00")
        table, names = 0x6A0000, 0x690000
        for i, (name, has_arg, flag, val) in enumerate(options):
            state.memory.store(names + 16 * i, name + b"\x00")
            self._write_option(state, table + 32 * i, names + 16 * i, has_arg, flag, val)
        self._write_option(state, table + 32 * len(options), 0, 0, 0, 0)
        longindex = 0x6B0000
        optopt = b.loader.find_symbol("optopt").rebased_addr
        results = []
        for _ in range(argc + 1):
            state.memory.store(longindex, struct.pack("<i", -1))
            state.memory.store(optopt, struct.pack("<i", 0))
            r = state.solver.eval(self._getopt(state, b, argc, argv, optstr, table, longindex, klass=klass))
            if r == 0xFFFFFFFF:
                return results, self._read_optarg(state, b)
            results.append(
                (
                    r,
                    self._read_optind(state, b),
                    state.solver.eval(state.memory.load(optopt, 4, endness="Iend_LE")),
                    state.solver.eval(state.memory.load(longindex, 4, endness="Iend_LE")),
                )
            )
        raise AssertionError(f"getopt did not return -1: {results}")

    # Expected values below come from glibc.

    def test_long_only_prefers_short_option(self):
        foo = [(b"foo", 0, 0, ord("F"))]
        assert self._long_case("getopt_long_only", b"f", foo, [b"-f"])[0] == [(ord("f"), 2, 0, 0xFFFFFFFF)]
        assert self._long_case("getopt_long_only", b"f", foo, [b"-fo"])[0] == [(ord("F"), 2, 0, 0)]

    def test_long_only_unknown_option(self):
        foo = [(b"foo", 0, 0, ord("F"))]
        assert self._long_case("getopt_long_only", b"f", foo, [b"-xyz"])[0] == [(ord("?"), 2, 0, 0xFFFFFFFF)]

    def test_long_alias_prefix_is_not_ambiguous(self):
        col = [(b"color", 0, 0, ord("C")), (b"colour", 0, 0, ord("C"))]
        assert self._long_case("getopt_long", b"", col, [b"--col"])[0] == [(ord("C"), 2, 0, 0)]
        # options that differ are ambiguous
        col = [(b"color", 0, 0, ord("C")), (b"colour", 0, 0, ord("U"))]
        assert self._long_case("getopt_long", b"", col, [b"--col"])[0] == [(ord("?"), 2, 0, 0xFFFFFFFF)]

    def test_long_missing_argument(self):
        # optopt is the option's val even with a flag pointer, and longindex is left alone on error
        req = [(b"req", 1, 0x6C0000, ord("R"))]
        assert self._long_case("getopt_long", b":", req, [b"--req"])[0] == [(ord(":"), 2, ord("R"), 0xFFFFFFFF)]

    def test_semicolon_is_not_an_option(self):
        assert self._long_case("getopt_long", b"W;a", [], [b"-;"])[0] == [(ord("?"), 2, ord(";"), 0xFFFFFFFF)]

    def test_optarg_cleared_on_each_call(self):
        results, optarg = self._long_case("getopt_long", b"+f:", [], [b"-fx", b"a"])
        assert results == [(ord("f"), 2, 0, 0xFFFFFFFF)]
        assert optarg == 0


if __name__ == "__main__":
    unittest.main()
