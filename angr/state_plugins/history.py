import operator
import claripy
import logging
l = logging.getLogger("angr.state_plugins.history")

from .plugin import SimStatePlugin
class SimStateHistory(SimStatePlugin):
    """
    This class keeps track of historically-relevant information for paths.
    """

    def __init__(self, parent=None, clone=None):
        SimStatePlugin.__init__(self)

        # attributes handling the progeny of this history object
        self.parent = parent if clone is None else clone.parent
        self.merged_from = [ ] if clone is None else list(clone.merged_from)
        self.merge_conditions = [ ] if clone is None else list(clone.merge_conditions)
        self.depth = (0 if parent is None else parent.length + 1) if clone is None else clone.depth
        self.extra_depth = (0 if parent is None else parent.extra_depth) if clone is None else clone.depth

        # a string description of this history
        self.description = None if clone is None else clone.description

        # the control flow transfer information from this history onwards (to the current state)
        self.jump_target = None if clone is None else clone.jump_target
        self.jump_source = None if clone is None else clone.jump_source
        self.jump_avoidable = None if clone is None else clone.jump_avoidable
        self.jump_guard = None if clone is None else clone.jump_guard
        self.jumpkind = None if clone is None else clone.jumpkind

        # the execution log for this history
        self.recent_events = [ ] if clone is None else list(clone.recent_events)
        self.recent_bbl_addrs = [ ] if clone is None else list(clone.recent_bbl_addrs)
        self.recent_ins_addrs = [ ] if clone is None else list(clone.recent_ins_addrs)
        self.last_stmt_idx = None if clone is None else clone.last_stmt_idx

        # numbers of blocks, syscalls, and instructions that were executed in this step
        self.recent_block_count = 0 if clone is None else clone.recent_block_count
        self.recent_syscall_count = 0 if clone is None else clone.recent_syscall_count
        self.recent_instruction_count = -1 if clone is None else clone.recent_instruction_count

        # satness stuff
        self._all_constraints = ()
        self._satisfiable = None

    def merge(self, others, merge_conditions, common_ancestor=None):
        raise Exception('TODO')

    def widen(self, others):
        raise Exception('TODO')

    def copy(self):
        return SimStateHistory(clone=self)

    #def _record_state(self, state, strong_reference=True):
    #   else:
    #       # state.scratch.bbl_addr may not be initialized as final states from the "flat_successors" list. We need to get
    #       # the value from _target in that case.
    #       if self.addr is None and not self._target.symbolic:
    #           self._addrs = [ self._target._model_concrete.value ]
    #       else:
    #           # FIXME: redesign so this does not happen
    #           l.warning("Encountered a path to a SimProcedure with a symbolic target address.")
    #
    #   if o.UNICORN in state.options:
    #       self.extra_length += state.scratch.executed_block_count - 1
    #
    #   if o.TRACK_ACTION_HISTORY in state.options:
    #       self._events = state.history.events
    #
    #   # record constraints, added constraints, and satisfiability
    #   self._all_constraints = state.se.constraints
    #   self._fresh_constraints = state.history.fresh_constraints
    #
    #   if isinstance(state.se._solver, claripy.frontend_mixins.SatCacheMixin):
    #       self._satisfiable = state.se._solver._cached_satness
    #   else:
    #       self._satisfiable = None
    #
    #   # record the state as a weak reference
    #   self._state_weak_ref = weakref.ref(state)
    #
    #   # and as a strong ref
    #   if strong_reference:
    #       self._state_strong_ref = state

    def demote(self):
        """
        Demotes this PathHistory node, causing it to convert references to the state
        to weakrefs.
        """
        print "TODO: demote", self

    def reachable(self):
        if self._satisfiable is not None:
            pass
        elif self.state is not None:
            self._satisfiable = self.state.se.satisfiable()
        else:
            solver = claripy.Solver()
            solver.add(self._all_constraints)
            self._satisfiable = solver.satisfiable()

        return self._satisfiable

    #
    # Log handling
    #

    def add_event(self, event_type, **kwargs):
        new_event = SimEvent(self.state, event_type, **kwargs)
        self.recent_events.append(new_event)

    def add_action(self, action):
        self.recent_events.append(action)

    def extend_actions(self, new_actions):
        self.recent_events.extend(new_actions)

    #
    # Convenient accessors
    #

    @property
    def recent_constraints(self):
        return ( ev.constraint for ev in self.recent_events if isinstance(ev, SimActionConstraint) )
    @property
    def recent_actions(self):
        return ( ev for ev in self.recent_events if isinstance(ev, SimAction) )

    @property
    def weighted_depth(self):
        return self.depth + self.extra_depth

    @property
    def lineage(self):
        return HistoryIter(self)
    @property
    def parents(self):
        if self.parent:
            for p in self.parent.lineage:
                yield p
    @property
    def all_events(self):
        return LambdaIterIter(self, operator.attrgetter('recent_events'))
    @property
    def all_actions(self):
        return LambdaIterIter(self, operator.attrgetter('recent_actions'))
    @property
    def all_jumpkinds(self):
        return LambdaAttrIter(self, operator.attrgetter('jumpkind'))
    @property
    def all_jump_guards(self):
        return LambdaAttrIter(self, operator.attrgetter('jump_guard'))
    @property
    def all_jump_targets(self):
        return LambdaAttrIter(self, operator.attrgetter('jump_target'))
    @property
    def all_descriptions(self):
        return LambdaAttrIter(self, operator.attrgetter('description'))
    @property
    def all_bbl_addrs(self):
        return LambdaIterIter(self, operator.attrgetter('recent_bbl_addrs'))
    @property
    def all_ins_addrs(self):
        return LambdaIterIter(self, operator.attrgetter('recent_ins_addrs'))

    #
    # Merging support
    #

    def closest_common_ancestor(self, other):
        """
        Find the common ancestor between this PathHistory and 'other'.

        :param other:    the PathHistory to find a common ancestor with.
        :return:        the common ancestor PathHistory, or None if there isn't one
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

    def constraints_since(self, other):
        """
        Returns the constraints that have been accumulated since `other`.

        :param other: a prior PathHistory object
        :returns: a list of constraints
        """

        constraints = [ ]
        cur = self
        while cur is not other and cur is not None:
            constraints.extend(cur.recent_constraints)
            cur = cur.parent
        return constraints

class TreeIter(object):
    def __init__(self, start, end=None):
        self._start = start
        self._end = end

    def _iter_nodes(self):
        n = self._start
        while n is not self._end:
            yield n
            n = n.parent

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
        return self._start.length

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

class LambdaAttrIter(TreeIter):
    def __init__(self, start, f, **kwargs):
        TreeIter.__init__(self, start, **kwargs)
        self._f = f

    def __reversed__(self):
        for hist in self._iter_nodes():
            a = self._f(hist)
            if a is not None:
                yield a

class LambdaIterIter(LambdaAttrIter):
    def __init__(self, start, f, reverse=True, **kwargs):
        LambdaAttrIter.__init__(self, start, f, **kwargs)
        self._f = f
        self._reverse = reverse

    def __reversed__(self):
        for hist in self._iter_nodes():
            for a in reversed(self._f(hist)) if self._reverse else self._f(hist):
                yield a

SimStateHistory.register_default('history', SimStateHistory)
from .sim_action import SimAction, SimActionConstraint
from .sim_event import SimEvent
