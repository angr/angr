#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import unittest

import archinfo

from angr.procedures.definitions import SIM_LIBRARIES


class TestSyscallNonePrototype(unittest.TestCase):
    """
    Regression test: syscalls registered with a ``None`` prototype (signature unknown, e.g. ``capset``) must not make
    ``has_prototype()`` disagree with ``get_prototype()``. Otherwise ``SimSyscallLibrary.get()`` asserts in
    ``_apply_numerical_metadata`` when the CFG or SimOS resolves such a syscall.
    """

    def _linux_syscall_library(self):
        return SIM_LIBRARIES["linux"][0]

    def test_none_prototype_is_not_reported_as_present(self):
        lib = self._linux_syscall_library()
        none_names = [name for name, proto in lib.syscall_prototypes["amd64"].items() if proto is None]
        assert none_names, "expected at least one None-prototype syscall in the linux definitions"

        for name in none_names:
            # has_prototype() and get_prototype() must agree: no usable prototype.
            assert not lib.has_prototype("amd64", name), name
            assert lib.get_prototype("amd64", name, deref=True) is None, name

    def test_real_prototype_still_present(self):
        lib = self._linux_syscall_library()
        assert lib.has_prototype("amd64", "read")
        assert lib.get_prototype("amd64", "read", deref=True) is not None

    def test_get_none_prototype_syscall_does_not_crash(self):
        lib = self._linux_syscall_library()
        arch = archinfo.arch_from_id("amd64")
        none_names = [name for name, proto in lib.syscall_prototypes["amd64"].items() if proto is None]
        name = none_names[0]
        number = next(num for num, nm in lib.syscall_number_mapping["amd64"].items() if nm == name)

        # This used to raise `assert proto is not None` in _apply_numerical_metadata.
        proc = lib.get(number, arch, ["amd64"])
        assert proc.is_syscall
        assert proc.guessed_prototype


if __name__ == "__main__":
    unittest.main()
