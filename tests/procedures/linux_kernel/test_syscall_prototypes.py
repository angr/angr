#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures.linux_kernel"  # pylint:disable=redefined-builtin

import inspect
import os
import unittest

import archinfo

import angr
from angr.procedures.definitions import SIM_LIBRARIES, SimSyscallLibrary
from angr.sim_type import SimTypeFunction
from tests.common import bin_location


class TestLinuxSyscallPrototypes(unittest.TestCase):
    """
    The Linux syscall definitions declare what their numbering names. A syscall with no
    declaration gets its prototype from whichever userspace library exports the same name:
    i386 number 126 used to arrive with libc's ``int sigprocmask(int, int *, int *)`` rather
    than the kernel's ``long sys_sigprocmask(int, old_sigset_t *, old_sigset_t *)``.
    """

    def _linux_syscall_library(self) -> SimSyscallLibrary:
        lib = SIM_LIBRARIES["linux"][0]
        assert isinstance(lib, SimSyscallLibrary)
        return lib

    def test_every_numbered_abi_has_prototypes(self):
        lib = self._linux_syscall_library()
        numbered = set(lib.syscall_number_mapping)
        assert numbered, "the linux definitions declare no syscall numbering"
        assert numbered <= set(lib.syscall_prototypes), sorted(numbered - set(lib.syscall_prototypes))
        for abi in sorted(numbered):
            # aarch64 had a numbering of 259 syscalls and no prototype table at all.
            assert lib.has_prototype(abi, "read"), abi

    def test_no_declaration_is_a_placeholder(self):
        lib = self._linux_syscall_library()
        placeholders = sorted(
            (abi, name)
            for abi, protos in lib.syscall_prototypes.items()
            for name, proto in protos.items()
            if proto is None
        )
        assert placeholders == [], placeholders

    def test_i386_sigprocmask_is_the_kernel_prototype(self):
        lib = self._linux_syscall_library()
        proto = lib.get_prototype("i386", "sigprocmask", arch=archinfo.arch_from_id("x86"))
        assert proto is not None
        assert len(proto.args) == 3
        assert proto.c_repr("sigprocmask") == "long (sigprocmask)(int, unsigned long *, unsigned long *)"

    def test_the_signal_return_entry_points_are_declared(self):
        lib = self._linux_syscall_library()
        # The architectures' own entry points, which include/linux/syscalls.h does not
        # declare and the amd64 list the base table comes from therefore does not either.
        for name in ("sigreturn", "rt_sigreturn"):
            proto = lib.get_prototype("i386", name)
            assert proto is not None, name
            assert len(proto.args) == 0, name

    def test_a_name_that_is_not_its_entry_point_takes_the_entry_point_s_declaration(self):
        lib = self._linux_syscall_library()
        # i386 59 "oldolduname" dispatches sys_olduname; on the generic ABI 80
        # "fstat" dispatches sys_newfstat and 71 "sendfile" sys_sendfile64.
        for abi, name, entry in (
            ("i386", "oldolduname", "olduname"),
            ("aarch64", "fstat", "newfstat"),
            ("aarch64", "sendfile", "sendfile64"),
        ):
            got = lib.get_prototype(abi, name)
            want = lib.get_prototype("amd64", entry) or lib.get_prototype("i386", entry)
            assert got is not None and want is not None, (abi, name, entry)
            assert got.c_repr(name) == want.c_repr(name), (abi, name, entry)

    def test_every_declaration_can_call_its_procedure(self):
        lib = self._linux_syscall_library()
        # SimProcedure.execute builds one argument per declared parameter and calls
        # run(*args), so a declaration whose arity run() cannot be called with raises
        # TypeError on every call to that syscall. One arch does for every ABI: these
        # definitions hold one procedure per name, and neither its signature nor the
        # number of declared parameters depends on the arch.
        arch = archinfo.arch_from_id("amd64")
        uncallable = []
        for abi in sorted(lib.syscall_number_mapping):
            for number, name in sorted(lib.syscall_number_mapping[abi].items()):
                procedure = lib.get(number, arch, [abi])
                prototype = procedure.prototype
                if prototype is None:
                    continue
                assert isinstance(prototype, SimTypeFunction), (abi, number, name)
                signature = inspect.signature(procedure.run)
                if any(p.kind is p.VAR_POSITIONAL for p in signature.parameters.values()):
                    continue  # run(*args) takes any arity
                try:
                    signature.bind(*[None] * len(prototype.args))
                except TypeError:
                    uncallable.append((abi, number, name, len(prototype.args), str(signature)))
        assert not uncallable, uncallable

    def test_an_aarch64_futex_wake_adds_no_parameters(self):
        # random() and funlockfile() each make a FUTEX_WAKE call that leaves x4 and x5
        # unset; rand() only calls random().
        proj = angr.Project(os.path.join(bin_location, "tests", "aarch64", "libc.so.6"), auto_load_libs=False)
        random = proj.loader.main_object.get_symbol("random")
        rand = proj.loader.main_object.get_symbol("rand")
        funlockfile = proj.loader.main_object.get_symbol("funlockfile")
        assert random is not None and rand is not None and funlockfile is not None
        cfg = proj.analyses.CFGFast(
            normalize=True,
            data_references=False,
            function_starts=[random.rebased_addr, rand.rebased_addr, funlockfile.rebased_addr],
            regions=[
                (random.rebased_addr, rand.rebased_addr + rand.size),
                (funlockfile.rebased_addr, funlockfile.rebased_addr + funlockfile.size),
            ],
            start_at_entry=False,
            symbols=False,
            function_prologues=False,
            force_smart_scan=False,
            force_complete_scan=False,
        )
        proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg.model)
        for symbol, nargs in ((random, 0), (rand, 0), (funlockfile, 1)):
            prototype = cfg.functions[symbol.rebased_addr].prototype
            assert prototype is not None, symbol.name
            assert len(prototype.args) == nargs, (symbol.name, prototype.c_repr(symbol.name))


if __name__ == "__main__":
    unittest.main()
