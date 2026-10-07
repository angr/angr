#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest

import archinfo

from angr.calling_conventions import SimCCSystemVAMD64
from angr.knowledge_plugins.callsite_prototypes import CallsitePrototypeKind, CallsitePrototypes
from angr.knowledge_plugins.plugin import DEFAULT_FLAVOR
from angr.rust import RUST_FLAVOR
from angr.sim_type import SimTypeFunction, SimTypeInt


class TestCallsitePrototypes(unittest.TestCase):
    def test_flavors(self):
        arch = archinfo.ArchAMD64()
        cc = SimCCSystemVAMD64(arch)
        c_proto = SimTypeFunction([SimTypeInt()], SimTypeInt()).with_arch(arch)
        rust_proto = SimTypeFunction([], None).with_arch(arch)
        manual_proto = SimTypeFunction([SimTypeInt(), SimTypeInt()], None).with_arch(arch)

        cp = CallsitePrototypes(None)
        cp.set_prototype(0x1000, cc, c_proto)
        cp.set_prototype(0x1000, cc, manual_proto, manual=True)
        cp.set_prototype(0x2000, cc, c_proto)

        # the default flavor is what None means, and a flavor without entries falls back to it
        assert cp.get_prototype(0x1000, flavor=DEFAULT_FLAVOR) is c_proto
        assert cp.get_prototype(0x1000, flavor=RUST_FLAVOR) is c_proto
        assert cp.has_prototype(0x1000, flavor=RUST_FLAVOR)
        assert not cp.has_prototype_for_flavor(0x1000, flavor=RUST_FLAVOR)
        assert cp.flavors == [DEFAULT_FLAVOR]

        # a flavor's own entry hides the default one of the same kind only
        cp.set_prototype(0x1000, cc, rust_proto, flavor=RUST_FLAVOR)
        assert cp.get_prototype(0x1000, flavor=RUST_FLAVOR) is rust_proto
        assert cp.get_prototype(0x1000) is c_proto
        assert cp.is_prototype_manual(0x1000, flavor=RUST_FLAVOR) is True
        assert cp.get_prototype(0x1000, kind=CallsitePrototypeKind.MANUAL, flavor=RUST_FLAVOR) is manual_proto
        assert cp.get_prototype(0x2000, flavor=RUST_FLAVOR) is c_proto
        assert cp.is_prototype_manual(0x3000, flavor=RUST_FLAVOR) is None
        assert sorted(cp.flavors) == sorted([DEFAULT_FLAVOR, RUST_FLAVOR])

        # items() lists a flavor's own entries; len() counts every flavor's
        assert [(a, k) for a, k, _, _ in cp.items(RUST_FLAVOR)] == [(0x1000, CallsitePrototypeKind.INFERRED)]
        assert len(list(cp.items())) == 3
        assert len(cp) == 4

        copied = cp.copy()
        cp.remove_prototype(0x1000, flavor=RUST_FLAVOR)
        assert cp.get_prototype(0x1000, flavor=RUST_FLAVOR) is c_proto
        assert copied.get_prototype(0x1000, flavor=RUST_FLAVOR) is rust_proto


if __name__ == "__main__":
    unittest.main()
