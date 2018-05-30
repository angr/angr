from collections import defaultdict

import claripy
import functools

import logging
l = logging.getLogger("angr.exploration_techniques.oppologist")

from ..errors import AngrError, SimError, SimUnsupportedError, SimCCallError
from .. import sim_options

exc_list = (AngrError, SimError, claripy.ClaripyError, TypeError, ValueError, ArithmeticError, MemoryError)

from . import ExplorationTechnique


class Oppologist(ExplorationTechnique):
    """
    The Oppologist is an exploration technique that forces uncooperative code through qemu.
    """

    def __init__(self):
        ExplorationTechnique.__init__(self)

    @staticmethod
    def _restore_state(old, new):
        new.release_plugin('unicorn')
        new.register_plugin('unicorn', old.unicorn.copy())
        new.options = old.options.copy()
        return new

    def _oppologize(self, state, pn, **kwargs):
        l.debug("... pn: %s", pn)

        pn.options.add(sim_options.UNICORN)
        pn.options.add(sim_options.UNICORN_AGGRESSIVE_CONCRETIZATION)
        pn.unicorn.max_steps = 1
        pn.unicorn.countdown_symbolic_registers = 0
        pn.unicorn.countdown_symbolic_memory = 0
        pn.unicorn.countdown_nonunicorn_blocks = 0
        pn.unicorn.countdown_stop_point = 0
        ss = self.project.factory.successors(pn, throw=True, **kwargs)

        fixup = functools.partial(self._restore_state, state)

        l.debug("... successors: %s", ss)

        return {'active': map(fixup, [ s for s in ss.flat_successors ]),
                'unconstrained': map(fixup, ss.unconstrained_successors),
                'unsat': map(fixup, ss.unsat_successors),
                }

    @staticmethod
    def _combine_results(*results):
        all_results = defaultdict(list)

        for stashes_dict in results:
            for stash, paths in stashes_dict.iteritems():
                all_results[stash].extend(paths)

        return {stash: paths for stash, paths in all_results.iteritems()}

    def _delayed_oppology(self, state, e, **kwargs):
        ss = self.project.factory.successors(state, num_inst=e.executed_instruction_count, **kwargs)
        need_oppologizing = [ s for s in ss.flat_successors if s.addr == e.ins_addr ]

        results = [{'active': [ s for s in ss.flat_successors if s.addr != e.ins_addr ],
                    'unconstrained': ss.unconstrained_successors,
                    'unsat': ss.unsat_successors,
                  }]

        results += map(functools.partial(self._oppologize, state, **kwargs), need_oppologizing)
        return self._combine_results(*results)

    def step_state(self, simgr, state, successor_func=None, **kwargs):
        try:
            kwargs.pop('throw', None)
            ss = self.project.factory.successors(state, **kwargs)

            return {'active': ss.flat_successors,
                    'unconstrained': ss.unconstrained_successors,
                    'unsat': ss.unsat_successors,
                    }
        except (SimUnsupportedError, SimCCallError) as e:
            l.debug("Errored on path %s after %d instructions", state, e.executed_instruction_count)
            try:
                if e.executed_instruction_count:
                    return self._delayed_oppology(state, e, **kwargs)
                else:
                    return self._oppologize(state, state.copy(), **kwargs)
            except exc_list: #pylint:disable=broad-except
                l.error("Oppologizer hit an error.", exc_info=True)
                return simgr.step_state(state, **kwargs)
        except exc_list: #pylint:disable=broad-except
            l.error("Original block hit an error.", exc_info=True)
            return simgr.step_state(state, **kwargs)
