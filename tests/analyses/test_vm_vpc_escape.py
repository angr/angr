#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import types
import unittest

from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation


def _fake_cfg(composite=()):
    loader = types.SimpleNamespace(find_object_containing=lambda addr: None)
    project = types.SimpleNamespace(
        byte_code_regions=[(0x405000, 0x4938D0)], loader=loader, composite_vpc_values=set(composite)
    )
    return types.SimpleNamespace(project=project)


class TestVPCEscape(unittest.TestCase):
    def test_in_region(self):
        assert not CFGVMDeobfuscation._vpc_escaped_byte_code(_fake_cfg(), 0x43AB5D)

    def test_out_of_region(self):
        assert CFGVMDeobfuscation._vpc_escaped_byte_code(_fake_cfg(), 0x87574C)

    def test_branch_sum_vpc_is_not_an_escape(self):
        # huffman_ultra_vmp: the loop branch VPC is 0x43ab5d + 0x43abef
        branch_vpc = 0x43AB5D + 0x43ABEF
        assert not CFGVMDeobfuscation._vpc_escaped_byte_code(_fake_cfg([branch_vpc]), branch_vpc)


if __name__ == "__main__":
    unittest.main()
