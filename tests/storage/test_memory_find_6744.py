from __future__ import annotations

import claripy

import angr


def test_memory_find_empty_cases():
    state = angr.SimState(arch="AMD64")

    addr = claripy.BVV(0x1204F0D, 32)
    target = claripy.BVV(0, 8)

    with open("test_data_6744", "rb") as f:
        fdata = f.read()

    state.memory.store(addr, fdata, len(fdata))

    result, constraints, index = state.memory.find(
        addr,
        target,
        128,
        max_symbolic_bytes=60,
        chunk_size=None,
        char_size=1,
    )

    assert result is not None
