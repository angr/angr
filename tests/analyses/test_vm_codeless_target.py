#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import types
import unittest

import angr
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation


def _setup():
    # code at 0x1000 (executable), concrete bytes at 0x9000 and 0xa000 in a plain backer
    proj = angr.load_shellcode(b"\x90\xc3", arch="amd64", load_address=0x1000)
    proj.loader.memory.add_backer(0x9000, b"\x00" * 0x10 + b"\x90" * 0x10)
    state = proj.factory.blank_state()
    fake = types.SimpleNamespace(project=proj, _executable_address_ranges=[(0x1000, 0x1002)])
    fake._is_address_executable = types.MethodType(CFGVMDeobfuscation._is_address_executable, fake)
    return fake, state


class TestCodelessTarget(unittest.TestCase):
    def test_classification(self):
        fake, state = _setup()
        f = lambda a, jk="Ijk_Ret": CFGVMDeobfuscation._is_codeless_target(fake, state, a, jk)  # noqa: E731
        assert not f(0x1000)  # executable
        assert f(0x0)  # unmapped: symbolic bytes
        assert f(0x9000)  # zero-filled data
        assert not f(0x9010)  # concrete code in data (self-modifying)
        fake.project.hook(0x0, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
        assert not f(0x0)  # hooked


if __name__ == "__main__":
    unittest.main()
