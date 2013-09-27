#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import idalink
import symbolic_irsb

import logging
l = logging.getLogger("symbolic")
l.setLevel(logging.DEBUG)

z3.init("/opt/python/lib/libz3.so")

######################
### Symbolic state ###
######################
import collections
state = collections.namedtuple("State", ("temps", "registers", "memory", "constraints"))
state.temps = { }
state.constraints = [ ]
state.registers = { }
state.memory = { }

def translate_recursive(start):
	#TODO
	pass
