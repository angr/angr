from __future__ import annotations

import sys

import angr


def test_platform_capabilities():
    assert angr.capabilities.emscripten == (sys.platform == "emscripten")
    assert angr.capabilities.ailment
    assert angr.capabilities.capstone
    assert angr.capabilities.vex
    assert angr.capabilities.z3
