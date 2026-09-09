from __future__ import annotations

import archinfo

import angr
from angr import claripy
from tests.common import minimal_project


def test_memory_find_empty_cases():
    state = angr.SimState(project=minimal_project(archinfo.ArchAMD64()))

    addr = claripy.BVV(0x1204F0D, 64)
    target = claripy.BVV(0, 8)

    fdata = b"POST /deviceService/queryDeviceInfoByNickName.do HTTP/1.1"

    state.memory.store(addr, fdata, len(fdata))

    result = state.memory.find(
        addr,
        target,
        128,
        max_symbolic_bytes=60,
        chunk_size=None,
        char_size=1,
    )

    assert result is not None
