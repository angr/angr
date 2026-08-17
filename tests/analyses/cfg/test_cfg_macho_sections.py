#!/usr/bin/env python
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

from archinfo.arch_arm import get_real_address_if_arm

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def sections_holding_blocks(project, cfg):
    """The names of the sections the blocks CFGFast produced begin in."""
    names = set()
    for node in cfg.model.nodes():
        if node.is_simprocedure or not node.size:
            continue
        addr = get_real_address_if_arm(project.arch, node.addr)
        section = project.loader.main_object.find_section_containing(addr)
        if section is not None:
            names.add(section.name)
    return names


class TestCfgMachOSections(unittest.TestCase):
    def test_cstring_and_unwind_info_are_not_scanned(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware.macho")
        project = angr.Project(bin_path, auto_load_libs=False)
        cfg = project.analyses.CFGFast()

        text = project.loader.main_object.sections_map["__TEXT,__text"]
        assert (text.vaddr, text.vaddr + text.memsize) in cfg.regions
        for name in ("__TEXT,__cstring", "__TEXT,__unwind_info"):
            section = project.loader.main_object.sections_map[name]
            assert (section.vaddr, section.vaddr + section.memsize) not in cfg.regions

        assert cfg.kb.functions.get_by_addr(project.entry) is not None
        assert sections_holding_blocks(project, cfg) == {"__text", "__stubs", "__stub_helper"}

    def test_objc_string_sections_are_not_scanned(self):
        # This image places the Objective-C name tables directly after __stub_helper, so a decode that runs off
        # the end of the stubs marches through them.
        bin_path = os.path.join(test_location, "armhf", "FileProtection-05.armv7.macho")
        project = angr.Project(bin_path, auto_load_libs=False)
        cfg = project.analyses.CFGFast()

        assert len(cfg.kb.functions) > 200
        assert sections_holding_blocks(project, cfg) == {"__text", "__stub_helper", "__symbolstub1"}


if __name__ == "__main__":
    unittest.main()
