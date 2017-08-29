import angr
import logging
import os

l = logging.getLogger("angr_tests")
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 '../../binaries/tests'))

def test_vfg_paths():
    p = angr.Project(os.path.join(test_location, "x86_64/track_user_input"))
    main_addr = p.loader.find_symbol("main").rebased_addr
    printf_addr = 0x4005e1 # actually where it returns

    vfg = p.analyses.VFG(context_sensitivity_level=1, interfunction_level=5)
    paths = vfg.get_paths(main_addr, printf_addr)

if __name__ == '__main__':
    test_vfg_paths()
