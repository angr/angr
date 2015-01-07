#!/usr/bin/env python

import logging

l = logging.getLogger("simuvex.plugins.memory")

from .plugin import SimStatePlugin

from itertools import count

event_id = count()

class SimMemory(SimStatePlugin):
    def __init__(self):
        SimStatePlugin.__init__(self)
        self.id = None

    @staticmethod
    def _deps_unpack(a):
        if isinstance(a, SimAST):
            reg_deps = set(a._info['reg_deps']) if 'reg_deps' in a._info else None
            tmp_deps = set(a._info['tmp_deps']) if 'tmp_deps' in a._info else None
            return a._a, reg_deps, tmp_deps
        else:
            return a, None, None

    def store(self, addr, data, size=None, condition=None, fallback=None):
        '''
        Stores content into memory.

        @param addr: a claripy expression representing the address to store at
        @param data: the data to store (claripy expression)
        @param size: a claripy expression representing the size of the data to store
        @param condition: (optional) a claripy expression representing a condition
                          if the store is conditional
        @param fallback: (optional) a claripy expression representing what the write
                         should resolve to if the condition evaluates to false (default:
                         whatever was there before)
        '''
        addr_e,_,_ = self._deps_unpack(addr)
        data_e,_,_ = self._deps_unpack(data)
        size_e,_,_ = self._deps_unpack(size)
        condition_e,_,_ = self._deps_unpack(condition)
        fallback_e,_,_ = self._deps_unpack(fallback)

        if o.AUTO_REFS in self.state.options:
            ref_size = size if size is not None else data_e.size()
            r = SimActionData(self.state, self.id, 'write', addr=addr, data=data, size=ref_size, condition=condition, fallback=fallback)
            self.state.log._add_action(r)

        return self._store(addr_e, data_e, size=size_e, condition=condition_e, fallback=fallback_e)

    def _store(self, addr, data, size=None, condition=None, fallback=None):
        raise NotImplementedError()

    def load(self, addr, size, condition=None, fallback=None):
        '''
        Loads size bytes from dst.

            @param dst: the address to load from
            @param size: the size (in bytes) of the load
            @param condition: a claripy expression representing a condition for a conditional load
            @param fallback: a fallback value if the condition ends up being False

        There are a few possible return values. If no condition or fallback are passed in,
        then the return is the bytes at the address, in the form of a claripy expression.
        For example:

            <A BVV(0x41, 32)>

        On the other hand, if a condition and fallback are provided, the value is conditional:

            <A If(condition, BVV(0x41, 32), fallback)>
        '''

        addr,_,_ = self._deps_unpack(addr)
        size,_,_ = self._deps_unpack(size)
        condition,_,_ = self._deps_unpack(condition)
        fallback,_,_ = self._deps_unpack(fallback)

        r,c = self._load(addr, size, condition=condition, fallback=fallback)

        if o.AST_DEPS in self.state.options and self.id == 'reg':
            r = SimAST(r, info={'reg_deps': {addr}})

        if o.AUTO_REFS in self.state.options:
            ref_size = size if size is not None else r.size()
            a = SimActionData(self.state, self.id, 'read', addr=addr, data=r, size=ref_size, condition=condition, fallback=fallback)
            self.state.log._add_action(a)

        return r,c

    def _load(self, addr, size, condition=None, fallback=None):
        raise NotImplementedError()

    def find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None):
        '''
        Returns the address of bytes equal to 'what', starting from 'start'. Note that,
        if you don't specify a default value, this search could cause the state to go
        unsat if no possible matching byte exists.

            @param start: the start address
            @param what: what to search for
            @param max_search: search at most this many bytes
            @param max_symbolic_bytes: search through at most this many symbolic bytes
            @param default: the default value, if what you're looking for wasn't found

            @returns an expression representing the address of the matching byte
        '''
        addr,_,_ = self._deps_unpack(addr)
        what,_,_ = self._deps_unpack(what)
        default,_,_ = self._deps_unpack(default)

        r,c,m = self._find(addr, what, max_search=max_search, max_symbolic_bytes=max_symbolic_bytes, default=default)
        if o.AST_DEPS in self.state.options and self.id == 'reg':
            r = SimAST(r, info={'reg_deps': {addr}})

        return r,c,m

    def _find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None):
        raise NotImplementedError()

    def copy_contents(self, dst, src, size, condition=None, src_memory=None):
        '''
        Copies data within a memory.

        @param dst: claripy expression representing the address of the destination
        @param src: claripy expression representing the address of the source
        @param src_memory: (optional) copy data from this SimMemory instead of self
        @param size: claripy expression representing the size of the copy
        @param condition: claripy expression representing a condition, if the write should
                          be conditional. If this is determined to be false, the size of
                          the copy will be 0
        '''
        dst,_,_ = self._deps_unpack(dst)
        src,_,_ = self._deps_unpack(src)
        size,_,_ = self._deps_unpack(size)
        condition,_,_ = self._deps_unpack(condition)

        return self._copy_contents(dst, src, size, condition=condition, src_memory=src_memory)

    def _copy_contents(self, dst, src, size, condition=None, src_memory=None):
        raise NotImplementedError()

from ..s_ast import SimAST
from .. import s_options as o
from ..s_action import SimActionData
