#!/usr/bin/env python

import logging

l = logging.getLogger("simuvex.plugins.memory")

from .plugin import SimStatePlugin

from itertools import count

event_id = count()

class SimMemory(SimStatePlugin):
	def __init__(self):
		SimStatePlugin.__init__(self)

	def store(self, addr, data, size=None, condition=None, fallback=None):
		'''
		Stores content into memory.

		@param addr: a claripy expression representing the address to store at
		@param data: the data to store
		@param size: a claripy expression representing the size of the data to store
		@param condition: (optional) a claripy expression representing a condition if the store is conditional
		@param fallback: (optional) a claripy expression representing what the write should resolve to if the
						 condition evaluates to false (default: whatever was there before)
		'''
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
		raise NotImplementedError()
