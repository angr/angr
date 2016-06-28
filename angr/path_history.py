import logging
import weakref
import simuvex

l = logging.getLogger("angr.path_history")

class PathHistory(object):
	def __init__(self, parent=None):
		self._parent = parent
		self._runstr = None
		self._target = None
		self._jump_source = None
		self._jump_avoidable = None
		self._guard = None
		self._jumpkind = None
		self._events = ()
		self._addrs = ()

	__slots__ = ('_parent', '_addrs', '_runstr', '_target', '_guard', '_jumpkind', '_events', '_jump_source', '_jump_avoidable')

	def __getstate__(self):
		attributes = ('_addrs', '_runstr', '_target', '_guard', '_jumpkind', '_events')
		state = {name: getattr(self,name) for name in attributes}
		return state

	def __setstate__(self, state):
		for name, value in state.iteritems():
			setattr(self,name,value)

	def _record_state(self, state, events=None):
		self._events = events if events is not None else state.log.events
		self._jumpkind = state.scratch.jumpkind
		self._jump_source = state.scratch.source
		self._jump_avoidable = state.scratch.avoidable
		self._target = state.scratch.target
		self._guard = state.scratch.guard

		if state.scratch.bbl_addr_list is not None:
			self._addrs = state.scratch.bbl_addr_list
		elif state.scratch.bbl_addr is not None:
			self._addrs = [ state.scratch.bbl_addr ]
		else:
			# state.scratch.bbl_addr may not be initialized as final states from the "flat_successors" list. We need to get
			# the value from _target in that case.
			if self.addr is None and not self._target.symbolic:
				self._addrs = [ self._target._model_concrete.value ]
			else:
				# FIXME: redesign so this does not happen
				l.warning("Encountered a path to a SimProcedure with a symbolic target address.")

		if simuvex.o.TRACK_ACTION_HISTORY not in state.options:
			self._events = weakref.proxy(self._events)

	def _record_run(self, run):
		self._runstr = str(run)

	@property
	def _actions(self):
		return [ ev for ev in self._events if isinstance(ev, simuvex.SimAction) ]

	@property
	def addr(self):
		return self._addrs[0]

	@addr.setter
	def addr(self, v):
		self._addrs = [ v ]

	def copy(self):
		c = PathHistory(parent=self._parent)
		c._addrs = self._addrs
		c._runstr = self._runstr
		c._jump_source = self._jump_source
		c._target = self._target
		c._guard = self._guard
		c._jumpkind = self._jumpkind
		c._events = self._events
		return c

	def closest_common_ancestor(self, other):
		"""
		Find the common ancestor between this PathHistory and 'other'.

		:param other:	the PathHistory to find a common ancestor with.
		:return:		the common ancestor PathHistory, or None if there isn't one
		"""
		our_history_iter = reversed(HistoryIter(self))
		their_history_iter = reversed(HistoryIter(other))
		sofar = set()

		while True:
			our_done = False
			their_done = False

			try:
				our_next = next(our_history_iter)
				if our_next in sofar:
					# we found it!
					return our_next
				sofar.add(our_next)
			except StopIteration:
				# we ran out of items during iteration
				our_done = True

			try:
				their_next = next(their_history_iter)
				if their_next in sofar:
					# we found it!
					return their_next
				sofar.add(their_next)
			except StopIteration:
				# we ran out of items during iteration
				their_done = True

			# if we ran out of both lists, there's no common ancestor
			if our_done and their_done:
				return None

class TreeIter(object):
	def __init__(self, start, end=None):
		self._start = start
		self._end = end

	def _iter_nodes(self):
		n = self._start
		while n is not self._end:
			yield n
			n = n._parent

	def __iter__(self):
		for i in self.hardcopy:
			yield i

	def __reversed__(self):
		raise NotImplementedError("Why are you using this class")

	@property
	def hardcopy(self):
		# lmao
		return list(reversed(tuple(reversed(self))))

	def __len__(self):
		return len(self.hardcopy)

	def __getitem__(self, k):
		if isinstance(k, slice):
			raise ValueError("Please use .hardcopy to use slices")
		if k >= 0:
			raise ValueError("Please use .hardcopy to use nonnegative indexes")
		i = 0
		for item in reversed(self):
			i -= 1
			if i == k:
				return item
		raise IndexError(k)

	def count(self, v):
		"""
		Count occurrences of value v in the entire history. Note that the subclass must implement the __reversed__
		method, otherwise an exception will be thrown.
		:param object v: The value to look for
		:return: The number of occurrences
		:rtype: int
		"""
		ctr = 0
		for item in reversed(self):
			if item == v:
				ctr += 1
		return ctr

class HistoryIter(TreeIter):
	def __reversed__(self):
		for hist in self._iter_nodes():
			yield hist

class AddrIter(TreeIter):
	def __reversed__(self):
		for hist in self._iter_nodes():
			for a in iter(hist._addrs):
				yield a

class RunstrIter(TreeIter):
	def __reversed__(self):
		for hist in self._iter_nodes():
			if hist._runstr is not None:
				yield hist._runstr

class TargetIter(TreeIter):
	def __reversed__(self):
		for hist in self._iter_nodes():
			if hist._target is not None:
				yield hist._target

class GuardIter(TreeIter):
	def __reversed__(self):
		for hist in self._iter_nodes():
			if hist._guard is not None:
				yield hist._guard

class JumpkindIter(TreeIter):
	def __reversed__(self):
		for hist in self._iter_nodes():
			if hist._jumpkind is not None:
				yield hist._jumpkind

class EventIter(TreeIter):
	def __reversed__(self):
		for hist in self._iter_nodes():
			try:
				for ev in iter(hist._events):
					yield ev
			except ReferenceError:
				hist._events = ()

class ActionIter(TreeIter):
	def __reversed__(self):
		for hist in self._iter_nodes():
			try:
				for ev in iter(hist._actions):
					yield ev
			except ReferenceError:
				hist._events = ()
