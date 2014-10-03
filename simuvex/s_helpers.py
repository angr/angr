#!/usr/bin/env python
'''This module includes some helper functions to avoid recursive imports.'''

import functools

import logging
l = logging.getLogger("simuvex.s_helpers")
#l.setLevel(logging.DEBUG)

########################
### Helper functions ###
########################

def size_bits(t):
    '''Returns size, in BITS, of a type.'''
    for s in 256, 128, 64, 32, 16, 8, 1:
        if str(s) in t:
            return s
    raise Exception("Unable to determine length of %s." % t)

def size_bytes(t):
    '''Returns size, in BYTES, of a type.'''
    s = size_bits(t)
    if s == 1:
        raise Exception("size_bytes() is seeing a bit!")
    return s/8

def translate_irconst(state, c):
    size = size_bits(c.type)
    t = type(c.value)
    if t in (int, long):
        return state.se.BitVecVal(c.value, size)
    raise Exception("Unsupported constant type: %s" % type(c.value))

# Gets and removes a value from a dict. Returns a default value if it's not there
def get_and_remove(kwargs, what, default=None):
    if what in kwargs:
        v = kwargs[what]
        del kwargs[what]
        return v
    else:
        return default

#####################################
### Various decorators for tricks ###
#####################################

def flagged(f):
    f.flagged = True
    return f

def ondemand(f):
    name = f.__name__

    @functools.wraps(f)
    def demander(self, *args, **kwargs):
        # only cache default calls
        if len(args) + len(kwargs) == 0:
            if hasattr(self, "_" + name):
                return getattr(self, "_" + name)

            a = f(self, *args, **kwargs)
            setattr(self, "_" + name, a)
            return a
        return f(self, *args, **kwargs)

    return demander
