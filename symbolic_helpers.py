#!/usr/bin/env python
'''This module includes some helper functions to avoid recursive imports.'''

import logging
l = logging.getLogger("symbolic_helpers")
l.setLevel(logging.DEBUG)

########################
### Helper functions ###
########################

def get_size(t):
	for s in 64, 32, 16, 8, 1:
		if str(s) in t:
			return s
	raise Exception("Unable to determine length of %s." % t)
