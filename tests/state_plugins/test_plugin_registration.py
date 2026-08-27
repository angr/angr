#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.state_plugins"  # pylint:disable=redefined-builtin

import collections
import unittest

import archinfo

import angr
from angr import sim_options as o
from angr.state_plugins.plugin import SimStatePlugin


class TestPluginRegistration(unittest.TestCase):
    """
    Tests for the order in which SimState registers and initializes a preset plugin.
    """

    def test_a_preset_plugin_is_initialized_once(self):
        # register_plugin() used to initialize the plugin and _init_plugin() used to initialize it again, so
        # every plugin the preset supplied ran init_state() twice.
        project = angr.load_shellcode(b"\x90\x90\xc3", arch="amd64")
        state = project.factory.blank_state()

        counts: collections.Counter = collections.Counter()
        original = SimStatePlugin.init_state

        def counting(self):
            counts[id(self)] += 1
            return original(self)

        SimStatePlugin.init_state = counting
        try:
            fresh = project.factory.blank_state()
            fresh.history  # noqa: B018  pylint:disable=pointless-statement
            fresh.solver  # noqa: B018  pylint:disable=pointless-statement
        finally:
            SimStatePlugin.init_state = original

        assert counts, "no plugin was initialized"
        assert set(counts.values()) == {1}, dict(counts)
        assert state is not fresh

    def test_a_plugin_may_look_itself_up_while_initializing(self):
        # SimStateHistory.init_state() reads the program counter. On an architecture whose PC register is
        # unset, that read fills the register symbolically, which records an event on the history plugin that
        # is still being constructed. Registering only after init_state() returned made that lookup miss and
        # build a second plugin, without end.
        arch = archinfo.ArchPcode("dsPIC33F:LE:24:default")
        project = angr.load_shellcode(b"\x00" * 6, arch=arch, load_address=0x1000, engine=angr.engines.UberEnginePcode)
        state = project.factory.blank_state(
            mode="fastpath",
            add_options={o.SYMBOL_FILL_UNCONSTRAINED_MEMORY, o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
        )

        state.registers.load("pc")

        assert state.history is not None


if __name__ == "__main__":
    unittest.main()
