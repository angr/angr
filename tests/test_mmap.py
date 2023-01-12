import logging

from angr import SimState

l = logging.getLogger("angr.tests.syscalls.mmap")


def test_mmap_base_copy():
    state = SimState(arch="AMD64", mode="symbolic")

    mmap_base = 0x12345678

    state.heap.mmap_base = mmap_base

    # Sanity check
    assert state.heap.mmap_base == mmap_base

    state_copy = state.copy()

    assert state_copy.heap.mmap_base == mmap_base


if __name__ == "__main__":
    g = globals().copy()
    for func_name, func in g.items():
        if func_name.startswith("test_") and hasattr(func, "__call__"):
            func()
