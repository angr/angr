#!/usr/bin/env python

import logging

l = logging.getLogger("simuvex.plguins.s_memory")

from .plugin import SimStatePlugin

class SimMemory(SimStatePlugin):
    def __init__(self):
        SimStatePlugin.__init__(self)

    def store(self, addr, data, size, condition=None, fallback=None):
        '''
        Returns the address of bytes equal to 'what', starting from 'start'.
        '''
        raise NotImplementedError()

    def load(self, addr, size, condition=None, fallback=None):
        raise NotImplementedError()

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None):
        '''
        Returns the address of bytes equal to 'what', starting from 'start'.
        '''
        raise NotImplementedError()
