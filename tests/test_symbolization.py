import angr
import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_fauxware_symbolization():
    p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
    sm = p.factory.simulation_manager()

    assert not sm.one_active.regs.rsp.symbolic

    sm.one_active.symbolizer.set_symbolization_for_all_pages()
    sm.one_active.symbolizer.resymbolize()

    # assert sm.one_active.regs.rsp.symbolic
    assert sm.one_active.symbolizer.symbolized_count

    # make sure pointers get symbolized at runtime
    n = sm.one_active.symbolizer.symbolized_count
    sm.run()
    assert not sm.errored
    assert not sm.active
    assert sm.one_deadended.symbolizer.symbolized_count > n


if __name__ == "__main__":
    test_fauxware_symbolization()
