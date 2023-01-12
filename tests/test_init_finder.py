# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import unittest

import angr


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestInitFinder(unittest.TestCase):
    def test_p2im_drone(self):
        bin_path = os.path.join(test_location, "armel", "p2im_drone.elf")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(data_references=True)

        func = cfg.functions["Peripherals_Init"]
        state = proj.factory.blank_state()
        prop = proj.analyses.Propagator(func=func, base_state=state)

        init_finder = proj.analyses.InitializationFinder(func=func, replacements=prop.replacements)
        overlay = init_finder.overlay

        # h12c1.Instance
        assert state.solver.eval_one(overlay.load(0x20001500, 4, endness="Iend_LE")) == 0x40005400
        # hi2c1.Init.AddressingMode
        assert state.solver.eval_one(overlay.load(0x20001500 + 4 + 0xC, 4, endness="Iend_LE")) == 0x4000
        # h12c1.Init.NoStretchMode
        assert state.solver.eval_one(overlay.load(0x20001500 + 4 + 0x1C, 4, endness="Iend_LE")) == 0


if __name__ == "__main__":
    unittest.main()
