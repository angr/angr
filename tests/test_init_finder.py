
import os

import nose.tools

import angr


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_p2im_drone():
    bin_path = os.path.join(test_location, "armel", "p2im_drone.elf")
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFG(data_references=True)

    func = cfg.functions["Peripherals_Init"]
    state = proj.factory.blank_state()
    prop = proj.analyses.Propagator(func=func, base_state=state)

    init_finder = proj.analyses.InitializationFinder(func=func, replacements=prop.replacements)
    overlay = init_finder.overlay

    # h12c1.Instance
    nose.tools.assert_equal(state.solver.eval_one(overlay.load(0x20001500, 4, endness='Iend_LE')), 0x40005400)
    # hi2c1.Init.AddressingMode
    nose.tools.assert_equal(state.solver.eval_one(overlay.load(0x20001500+4+0xc, 4, endness='Iend_LE')), 0x4000)
    # h12c1.Init.NoStretchMode
    nose.tools.assert_equal(state.solver.eval_one(overlay.load(0x20001500+4+0x1c, 4, endness='Iend_LE')), 0)


if __name__ == "__main__":
    test_p2im_drone()
