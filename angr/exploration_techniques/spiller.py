import logging

l = logging.getLogger("angr.exploration_techniques.spiller")

import ana
from . import ExplorationTechnique

class SpilledState(ana.Storable):
    def __init__(self, state):
        self.state = state

    def _ana_getstate(self):
        return (self.state,)

    def _ana_setstate(self, s):
        self.state = s[0]

class Spiller(ExplorationTechnique):
    """
    Automatically spill states out. It can spill out states to a different stash, spill
    them out to ANA, or first do the former and then (after enough states) the latter.
    """

    def __init__(
        self,
        src_stash="active", min=5, max=10, #pylint:disable=redefined-builtin
        staging_stash="spill_stage", staging_min=10, staging_max=20,
        pickle_callback=None, unpickle_callback=None, priority_key=None
    ):
        """
        Initializes the spiller.

        @param max: the number of states that are *not* spilled
        @param src_stash: the stash from which to spill states (default: active)
        @param staging_stash: the stash *to* which to spill states (default: "spill_stage")
        @param staging_max: the number of states that can be in the staging stash before things get spilled to ANA (default: None. If staging_stash is set, then this means unlimited, and ANA will not be used).
        @param priority_key: a function that takes a state and returns its numberical priority (MAX_INT is lowest priority). By default, self.state_priority will be used, which prioritizes by object ID.
        """
        super(Spiller, self).__init__()
        self.max = max
        self.min = min
        self.src_stash = src_stash
        self.staging_stash = staging_stash
        self.staging_max = staging_max
        self.staging_min = staging_min

        # various callbacks
        self.priority_key = priority_key
        self.unpickle_callback = unpickle_callback
        self.pickle_callback = pickle_callback

        # tracking of pickled stuff
        self._pickled_states = [ ]
        self._ever_pickled = 0
        self._ever_unpickled = 0

    def _unpickle(self, n):
        self._pickled_states.sort()
        unpickled = [ SpilledState.ana_load(pid).state for _,pid in self._pickled_states[:n] ]
        self._pickled_states[:n] = [ ]
        self._ever_unpickled += len(unpickled)
        if self.unpickle_callback:
            map(self.unpickle_callback, unpickled)
        return unpickled

    def _get_priority(self, state):
        return (self.priority_key or self.state_priority)(state)

    def _pickle(self, states):
        if self.pickle_callback:
            map(self.pickle_callback, states)
        wrappers = [ SpilledState(state) for state in states ]
        self._ever_pickled += len(states)
        for w in wrappers:
            w.make_uuid()
        self._pickled_states += [ (self._get_priority(w.state), w.ana_store()) for w in wrappers ]

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        l.debug("STASH STATUS: active: %d, staging: %d", len(simgr.stashes[self.src_stash]), len(simgr.stashes[self.staging_stash]))

        states = simgr.stashes[self.src_stash]
        staged_states = simgr.stashes.setdefault(self.staging_stash, [ ]) if self.staging_stash else [ ]

        if len(states) < self.min:
            missing = (self.max + self.min) / 2 - len(states)
            l.debug("Too few states (%d/%d) in stash %s.", len(states), self.min, self.src_stash)
            if self.staging_stash:
                l.debug("... retrieving states from staging stash (%s)", self.staging_stash)
                staged_states.sort(key=self.priority_key or self.state_priority)
                states += staged_states[:missing]
                staged_states[:missing] = [ ]
            else:
                l.debug("... staging stash disabled; unpickling states")
                states += self._unpickle(missing)

        if len(states) > self.max:
            l.debug("Too many states (%d/%d) in stash %s", len(states), self.max, self.src_stash)
            states.sort(key=self.priority_key or self.state_priority)
            staged_states += states[self.max:]
            states[self.max:] = [ ]

        # if we have too few staged states, unpickle up to halfway between max and min
        if len(staged_states) < self.staging_min:
            l.debug("Too few states in staging stash (%s)", self.staging_stash)
            staged_states += self._unpickle((self.staging_min + self.staging_max) / 2 - len(staged_states))

        if len(staged_states) > self.staging_max:
            l.debug("Too many states in staging stash (%s)", self.staging_stash)
            self._pickle(staged_states[self.staging_max:])
            staged_states[self.staging_max:] = [ ]

        simgr.stashes[self.src_stash] = states
        simgr.stashes[self.staging_stash] = staged_states
        return simgr

    @staticmethod
    def state_priority(state):
        return id(state)
