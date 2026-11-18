from __future__ import annotations

import os
from typing import cast

import angr
from angr.state_plugins import SimStateCGC
from tests.common import bin_location

BINARY = os.path.join(bin_location, "tests", "i386", "patchrex", "indirect_jump_test_Ofast")

# The instruction pointer the dump was taken at, which differs from the file's own entry point.
DUMP_EIP = 0x8048250

# A region a CGC process dump carries that the file itself does not map.
STACK_ADDR = 0xBAAAB000
STACK_DATA = b"\x11" * 0x1000


def backed_project(**main_opts) -> angr.Project:
    """
    A project built the way a CGC crash replay builds one: the binary plus a snapshot of the process it came from.
    """
    return angr.Project(
        BINARY,
        auto_load_libs=False,
        main_opts={
            "backend": "backedcgc",
            "memory_backer": {STACK_ADDR: STACK_DATA},
            "register_backer": {"eip": DUMP_EIP, "esp": STACK_ADDR, "eax": 0x1234},
            **main_opts,
        },
    )


def test_entry_state_without_recorded_writes_or_an_allocation_base():
    # A dump that carries neither still has to produce an entry state, and has to leave the CGC defaults alone
    # rather than replace them with None.
    state = backed_project().factory.entry_state()

    assert state.addr == DUMP_EIP
    assert cast(SimStateCGC, state.cgc).allocation_base == SimStateCGC().allocation_base
    assert state.posix.dumps(1) == b""


def test_entry_state_replays_the_dumped_writes_and_allocation_base():
    state = backed_project(writes_backer=[4, 8], current_allocation_base=0xB7000000).factory.entry_state()

    assert cast(SimStateCGC, state.cgc).allocation_base == 0xB7000000
    assert len(state.posix.dumps(1)) == 12
