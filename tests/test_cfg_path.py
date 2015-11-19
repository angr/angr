import angr
import logging
import os

l = logging.getLogger("angr_tests")
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 '../../binaries/tests'))

p = angr.Project(os.path.join(test_location, "x86_64/track_user_input"))
main_addr = p.loader.main_bin.get_symbol("main").addr
printf_addr = 0x400470

cfg = p.analyses.CFG(keep_state=True)
paths = cfg.get_paths(main_addr, printf_addr)

