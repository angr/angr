
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

    init_finder = proj.analyses.InitializationsFinder(func=func, replacements=prop.replacements)

    # import ipdb; ipdb.set_trace()


if __name__ == "__main__":
    test_p2im_drone()
