#!/usr/bin/env python3
"""Regression tests for Rust-flavor decompiler crashes on real crates (rustc 1.92/1.98, -O3)."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import networkx

import angr
from tests.common import bin_location, recover_call_tree_cfg

RUST_BINARIES_BASE = os.path.join(bin_location, "tests", "x86_64", "rust")


def _decompile_rust(binary: str, func_addr: int, depth: int, rustc_version: str = "1.92.0"):
    proj = angr.Project(os.path.join(RUST_BINARIES_BASE, binary), auto_load_libs=False)
    recover_call_tree_cfg(proj, [func_addr], depth=depth)
    callees = networkx.descendants(proj.kb.functions.callgraph, func_addr)
    proj.analyses.CompleteCallingConventions(prioritize_func_addrs={func_addr} | callees, skip_other_funcs=True)
    proj.rustc_version = rustc_version
    proj.analyses.RustSymbolRecovery()
    proj.analyses.TypeDBLoader()
    dec = proj.analyses.Decompiler(proj.kb.functions[func_addr], flavor="rust", fail_fast=True)
    assert dec.codegen is not None and dec.codegen.text is not None
    return dec.codegen.text


class TestRustDecompilerCrashes(unittest.TestCase):
    def test_format_macro_argument_from_phi(self):
        # <jql_parser::tokens::LensValue as core::fmt::Display>::fmt: the formatted value's stack slot is defined by a
        # phi; it used to become a write!() argument, leaving a Phi for codegen
        text = _decompile_rust("jql", 0x5087A0, depth=0)
        assert "Phi" not in text
        assert "core::fmt::write(" in text

    def test_rcc_phi_with_undefined_predecessor_value(self):
        # hexyl::run::{{closure}} calls hexyl::parse_byte_offset, whose ret2arg0 path crosses a phi that has no value
        # for one predecessor; RustCallingConvention used to fail with "expected an Expression"
        with self.assertNoLogs("angr.rust.analyses.rust_calling_convention.rust_calling_convention", level="ERROR"):
            _decompile_rust("hexyl", 0x464240, depth=1)


if __name__ == "__main__":
    unittest.main()
