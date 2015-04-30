#!/usr/bin/env python
import nose
import logging
l = logging.getLogger("angr_tests")

try:
    # pylint: disable=W0611,F0401
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr
import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_amd64():
    strstr_amd64 = angr.Project(test_location + "/x86_64/strstr", load_options={'auto_load_libs': True}, exclude_sim_procedures=['strstr'])
    explorer = angr.surveyors.Explorer(strstr_amd64, find=[0x4005FB]).run()
    s = explorer.found[0].state
    result = s.se.any_str(s.mem_expr(s.reg_expr(16), 9))
    nose.tools.assert_equals(result, 'hi there\x00')

if __name__ == "__main__":
    test_amd64()
