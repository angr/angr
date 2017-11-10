import os
import time
import signal
import logging
import hashlib
import resource
import cPickle as pickle
from itertools import islice, izip


from ..misc import config
from . import ExplorationTechnique


l = logging.getLogger("angr.exploration_techniques.driller")


class Driller(ExplorationTechnique):
    """
    An exploration technique that symbolically follows an input looking for new
    state transitions.

    It has to be used with Tracer exploration technique. Results are put in
    'diverted' stash.
    """
    
    def __init__(self, input, trace, fuzz_bitmap=None, tag=None, redis=None):
        """
        :param input      : Input string to feed to the binary.
        :param trace      : The basic block trace.
        :param fuzz_bitmap: AFL's bitmap of state transitions. Defaults to saying every transition is worth satisfying.
        :param tag        : Tag of this Driller instance.
        :param redis      : Redis instance for coordinating multiple Driller instances.
        """

        super(Driller, self).__init__()
        self.input = input
        self.trace = trace
        self.fuzz_bitmap = fuzz_bitmap or "\xff" * 65535
        self.tag = tag
        self.redis = redis

        # Set of encountered basic block transition.
        self._encounters = set()

        # Set of all the generated inputs.
        self.generated = set()

        # Set the memory limit specified in the config.
        if config.MEM_LIMIT is not None:
            resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))

    def setup(self, simgr):
        self.project = simgr._project
        self.identifier = os.path.basename(self.project.filename)
        self.completed = False

        # Do not re-trace the same input.
        if self.redis and self.redis.sismember(self.identifier + '-traced', self.input):
            self.completed = True

        # Start time.
        self._start_time = time.time()

        l.debug("[%s] drilling started on %s.", self.identifier, time.ctime(self._start_time))

        # Write out debug info if desired.
        if l.level == logging.DEBUG:
            if config.DEBUG_DIR:
                self._write_debug_info()
            else:
                l.warning("Debug directory is not set. Will not log fuzzing bitmap.")

        # Update traced.
        if self.redis:
            self.redis.sadd(self.identifier + '-traced', self.input)

        self._set_concretizations(simgr.one_active)

        # Update encounters with known state transitions.
        self._encounters.update(izip(self.trace, islice(self.trace, 1, None)))

    def complete(self, simgr):
        return self.completed or not simgr.active or simgr.one_active.globals['bb_cnt'] >= len(self.trace)

    def step(self, simgr, stash, **kwargs):
        simgr.step(**kwargs)

        # Check here to see if a crash has been found.
        if self.redis and self.redis.sismember(self.identifier + '-finished', True):
            self.completed = True
            return simgr

        # Mimic AFL's indexing scheme.
        if 'missed' in simgr.stashes and simgr.missed:
            # A bit ugly, might be replaced by tracer.predecessors[-1] or crash_monitor.last_state.
            prev_addr = simgr.one_missed.history.bbl_addrs[-1]
            prev_loc = prev_addr
            prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
            prev_loc &= len(self.fuzz_bitmap) - 1
            prev_loc = prev_loc >> 1

            for state in simgr.missed:
                cur_loc = state.addr
                cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                cur_loc &= len(self.fuzz_bitmap) - 1

                hit = bool(ord(self.fuzz_bitmap[cur_loc ^ prev_loc]) ^ 0xff)

                transition = (prev_addr, state.addr)

                l.debug("Found %#x -> %#x transition.", transition[0], transition[1])

                if not hit and transition not in self._encounters and not self._has_false(state):
                    state.preconstrainer.remove_preconstraints()

                    if state.satisfiable():
                        # A completely new state transition, let's try to
                        # accelerate AFL by finding a number of deeper inputs.
                        l.debug("Found a completely new transition, exploring to some extent.")

                        self._writeout(prev_addr, state)
                        self._symbolic_explorer_stub(state)

                    else:
                        l.debug("State at %#x is not satisfiable.", transition[1])

                else:
                    l.debug("%#x -> %#x transition has already been encountered.", transition[0], transition[1])

        return simgr

    #
    # Private methods
    #

    def _symbolic_explorer_stub(self, state):
        # Create a new simgr and step it forward up to 1024 accumulated active
        # states or steps.
        steps = 0
        accumulated = 1

        new_simgr = self.project.factory.simgr(state, immutable=False, hierarchy=False)

        l.debug("[%s] started symbolic exploration at %s", self.identifier, time.ctime())

        while new_simgr.active and accumulated < 1024:
            new_simgr.step()
            steps += 1

            # Dump all inputs.
            accumulated = steps * (len(new_simgr.active) + len(new_simgr.deadended))

        l.debug("[%s] stopped symbolic exploration at %s", self.identifier, time.ctime())

        for dumpable in new_simgr.deadended:
            try:
                if dumpable.satisfiable():
                    self._writeout(dumpable.history.bbl_addrs[-1], dumpable)
            except IndexError:
                # If the state we're trying to dump wasn't actually satisfiable.
                pass

    def _writeout(self, prev_addr, state):
        t_pos = state.posix.files[0].pos
        state.posix.files[0].seek(0)

        # Read up the length.
        generated = state.posix.read_from(0, t_pos)
        generated = state.se.eval(generated, cast_to=str)
        state.posix.files[0].seek(t_pos)

        key = (len(generated), prev_addr, state.addr)

        # Check here to see if the generation is worth writing to disk. If we
        # generated too many inputs which are not really different we'll
        # seriously slow down AFL.
        if self._in_catalogue(*key):
            return
        else:
            self._encounters.add((prev_addr, state.addr))
            self._add_to_catalogue(*key)

        l.debug("[%s] dumping input for %#x -> %#x.", self.identifier, prev_addr, state.addr)

        self.generated.add((key, generated))

        # Publish it out in real-time so that inputs get there immediately.
        if self.redis:
            channel = self.identifier + '-generated'
            self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated, 'tag': self.tag}))

        else:
            l.debug("Generated: %s.", generated.encode('hex'))

    def _in_catalogue(self, length, prev_addr, next_addr):
        # Check if a generated input has already been generated earlier during
        # the run or by another thread.
        key = '%x%x%x\n' % (length, prev_addr, next_addr)

        if self.redis:
            return self.redis.sismember(self.identifier + '-catalogue', key)

        # No redis means no coordination, so no catalogue.
        return False

    def _add_to_catalogue(self, length, prev_addr, next_addr):
        if self.redis:
            key = '%x%x%x\n' % (length, prev_addr, next_addr)
            self.redis.sadd(self.identifier + '-catalogue', key)

    def _write_debug_info(self):
        m = hashlib.md5()
        m.update(self.input)
        f_name = os.path.join(config.DEBUG_DIR, self.identifier + '_' + m.hexdigest() + '.py')

        with open(f_name, 'w+') as f:
            f.write("binary = %r\n", self.project.filename
                    + "started = '%s'\n" % time.ctime(self._start_time)
                    + "input = %r\n" % self.input
                    + "fuzz_bitmap = %r\n" % self.fuzz_bitmap)

            l.debug("Debug log written to %s.", f_name)

    @staticmethod
    def _has_false(state):
        # Check if the state is unsat even if we remove preconstraints.
        claripy_false = state.se.false
        if state.scratch.guard.cache_key == claripy_false.cache_key:
            return True

        for c in state.se.constraints:
            if c.cache_key == claripy_false.cache_key:
                return True

        return False

    @staticmethod
    def _set_concretizations(state):
        flag_vars = set()
        for b in state.cgc.flag_bytes:
            flag_vars.update(b.variables)

        state.unicorn.always_concretize.update(flag_vars)

        # Let's put conservative thresholds for now.
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

