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

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
fauxware_nolibs = None

def setup_module():
	global fauxware_nolibs
	fauxware_nolibs = angr.Project(test_location + "/fauxware/fauxware", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True)

def test_backdoor():
	results = fauxware_nolibs.explore(fauxware_nolibs.initial_exit(), find=(0x4006ed,), avoid=(0x4006aa,0x4006fd), max_repeats=10)
	stdin = results['found'][0].last_run.initial_state['posix'].dumps(0)
	nose.tools.assert_in("SOSNEAKY", stdin)
	nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

if __name__ == "__main__":
	setup_module()
	test_backdoor()
