#!/usr/bin/env python

from .s_ref import RefTypes
import s_options as o

class SimRun(object):
	def __init__(self, options = None, mode = "static"):
		# the options and mode
		if options is None:
			options = o.default_options[mode]
		self.options = options
		self.mode = mode

		self._exits = [ ]

		self._refs = { }
		self.options = options
		for t in RefTypes:
			self._refs[t] = [ ]

	def refs(self):
		return self._refs

	def exits(self):
		return self._exits

	# Categorize and add a sequence of refs to this run
	def add_refs(self, *refs):
		for r in refs:
			if o.SYMBOLIC not in self.options and r.is_symbolic():
				continue

			self._refs[type(r)].append(r)

	# Categorize and add a sequence of exits to this run
	def add_exits(self, *exits):
		for e in exits:
			if o.SYMBOLIC not in self.options and e.sim_value.is_symbolic():
				continue

			self._exits.append(e)

	# Copy the references
	def copy_refs(self, other):
		for ref_list in other.refs().itervalues():
			self.add_refs(*ref_list)

	# Copy the exits
	def copy_exits(self, other):
		self.add_exits(*other.exits())
