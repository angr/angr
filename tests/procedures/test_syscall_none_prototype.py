#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import unittest

import archinfo

from angr.procedures.definitions import SIM_LIBRARIES, SimSyscallLibrary


class TestSyscallNonePrototype(unittest.TestCase):
    """
    Regression test: syscalls registered with a ``None`` prototype (signature unknown, e.g. ``capset``) must not make
    ``has_prototype()`` disagree with ``get_prototype()``. Otherwise ``SimSyscallLibrary.get()`` asserts in
    ``_apply_numerical_metadata`` when the CFG or SimOS resolves such a syscall.
    """

    def _linux_syscall_library(self) -> SimSyscallLibrary:
        lib = SIM_LIBRARIES["linux"][0]
        assert isinstance(lib, SimSyscallLibrary)
        return lib

    def _library_with_a_none_prototype(self):
        """A copy of the Linux definitions with one syscall's prototype set to ``None``.

        The shipped definitions used to carry such entries -- ``capset`` was one -- and this
        test borrowed one. They are all declared now, so the entry is made here instead: what
        is under test is how the library answers for a ``None`` prototype, not whether one
        happens to be shipped.
        """
        lib = self._linux_syscall_library().copy()
        # copy() copies the outer mapping and not the per-ABI dicts inside it, so the
        # entry goes in a dict of this test's own rather than the shipped library's.
        lib.syscall_prototypes["amd64"] = dict(lib.syscall_prototypes["amd64"])
        number, name = min(lib.syscall_number_mapping["amd64"].items())
        lib.syscall_prototypes["amd64"][name] = None
        return lib, number, name

    def test_none_prototype_is_not_reported_as_present(self):
        lib, _, name = self._library_with_a_none_prototype()

        # has_prototype() and get_prototype() must agree: no usable prototype.
        assert not lib.has_prototype("amd64", name), name
        assert lib.get_prototype("amd64", name, deref=True) is None, name

    def test_real_prototype_still_present(self):
        lib = self._linux_syscall_library()
        assert lib.has_prototype("amd64", "read")
        assert lib.get_prototype("amd64", "read", deref=True) is not None

    def test_get_none_prototype_syscall_does_not_crash(self):
        lib, number, _ = self._library_with_a_none_prototype()
        arch = archinfo.arch_from_id("amd64")

        # This used to raise `assert proto is not None` in _apply_numerical_metadata.
        proc = lib.get(number, arch, ["amd64"])
        assert proc.is_syscall
        assert proc.guessed_prototype


if __name__ == "__main__":
    unittest.main()
