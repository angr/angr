#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment.expression import Const, Load
from angr.analyses.decompiler.known_patterns import PConst, PLoad
from angr.analyses.decompiler.known_patterns.dsl import MatchCtx, MatchState
from angr.analyses.decompiler.known_patterns.edit import describe
from angr.analyses.decompiler.known_patterns.serialize import dumps, loads

STDOUT_HERE = 0x603848
STDOUT_THERE = 0x403D90


def _load_of(addr: int) -> Load:
    return Load(1, Const(2, addr, 64), 8, "Iend_LE")


class TestSymbolicConstants(unittest.TestCase):
    """A constant pinned to a symbol matches that symbol's address in whatever binary is
    being matched, and nothing in a binary without the symbol."""

    def test_symbol_resolves_per_binary(self):
        pat = PLoad(PConst(symbol="stdout"), size=8)
        here = MatchCtx(symbol_addr_fn={"stdout": STDOUT_HERE}.get)
        there = MatchCtx(symbol_addr_fn={"stdout": STDOUT_THERE}.get)

        assert pat.match(_load_of(STDOUT_HERE), MatchState(), here) is not None
        assert pat.match(_load_of(STDOUT_THERE), MatchState(), there) is not None
        assert pat.match(_load_of(STDOUT_THERE), MatchState(), here) is None
        assert pat.match(_load_of(STDOUT_HERE), MatchState(), there) is None

    def test_no_resolver_or_unknown_symbol_matches_nothing(self):
        pat = PConst(symbol="stdout")
        assert pat.match(Const(1, STDOUT_HERE, 64), MatchState(), MatchCtx()) is None
        assert pat.match(Const(1, STDOUT_HERE, 64), MatchState(), MatchCtx(symbol_addr_fn={}.get)) is None

    def test_pinned_address_is_not_portable(self):
        pat = PConst(value=STDOUT_HERE)
        there = MatchCtx(symbol_addr_fn={"stdout": STDOUT_THERE}.get)
        assert pat.match(Const(1, STDOUT_THERE, 64), MatchState(), there) is None

    def test_symbol_round_trips_and_describes(self):
        pat = PLoad(PConst(symbol="stdout", name="s"), size=8)
        assert loads(dumps(pat)) == pat
        assert describe(pat.addr) == "&stdout:s" or "&stdout" in describe(pat.addr)


if __name__ == "__main__":
    unittest.main()
