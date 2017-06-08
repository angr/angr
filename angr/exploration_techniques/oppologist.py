from collections import defaultdict

import pyvex
import claripy
import simuvex
import functools

import logging
l = logging.getLogger("angr.exploration_techniques.Oppologist")

from ..errors import AngrError
exc_list = (AngrError, simuvex.SimError, claripy.ClaripyError, TypeError, ValueError, ArithmeticError, MemoryError)

from . import ExplorationTechnique
class Oppologist(ExplorationTechnique):
    """
    The Oppologist is an exploration technique that forces uncooperative code through qemu.
    """

    def __init__(self):
        ExplorationTechnique.__init__(self)

    @staticmethod
    def _restore_path(old, new):
        new.state.release_plugin('unicorn')
        new.state.register_plugin('unicorn', old.state.unicorn.copy())
        new.state.options = set(old.state.options)
        return new

    def _oppologize(self, p, pn, **kwargs):
        l.debug("... pn: %s", pn)

        irsb = self.project.factory.block(pn.addr).vex
        addrs = [ s.addr for s in irsb.statements if isinstance(s, pyvex.IRStmt.IMark) ]
        if len(addrs) > 1:
            stops = [ addrs[1] ]
        else:
            stops = None

        pn.state.options.add(simuvex.options.UNICORN)
        pn.state.options.add(simuvex.options.UNICORN_AGGRESSIVE_CONCRETIZATION)
        pn.state.unicorn.max_steps = 1
        pn.state.unicorn.countdown_symbolic_registers = 0
        pn.state.unicorn.countdown_symbolic_memory = 0
        pn.state.unicorn.countdown_nonunicorn_blocks = 0
        pn.step(extra_stop_points=stops, throw=True, **kwargs)

        fixup = functools.partial(self._restore_path, p)

        l.debug("... successors: %s", pn.successors)

        return {'active': map(fixup, [ pp for pp in pn.successors if not pp.errored ]),
                'unconstrained': map(fixup, pn.unconstrained_successors),
                'unsat': map(fixup, pn.unsat_successors),
                'errored': map(fixup, [ pp for pp in pn.successors if pp.errored ]),
                }

    @staticmethod
    def _combine_results(*results):
        all_results = defaultdict(list)

        for stashes_dict in results:
            for stash, paths in stashes_dict.iteritems():
                all_results[stash].extend(paths)

        return {stash: paths for stash, paths in all_results.iteritems()}

    def _delayed_oppology(self, p, e, **kwargs):
        try:
            p.step(num_inst=e.executed_instruction_count, throw=True, **kwargs)
        except Exception: #pylint:disable=broad-except
            return {'errored': p.step(num_inst=e.executed_instruction_count, **kwargs)}

        need_oppologizing = [ pp for pp in p.successors if pp.addr == e.ins_addr ]

        results = [{'active': [ pp for pp in p.successors if pp.addr != e.ins_addr ],
                    'unconstrained': p.unconstrained_successors,
                    'unsat': p.unsat_successors,
                  }]

        results += map(functools.partial(self._oppologize, p, **kwargs), need_oppologizing)
        return self._combine_results(*results)

    def step_path(self, path, **kwargs):
        try:
            path.step(throw=True, **kwargs)
            return None
        except (simuvex.SimUnsupportedError, simuvex.SimCCallError) as e:
            l.debug("Errored on path %s after %d instructions", path, e.executed_instruction_count)
            try:
                if e.executed_instruction_count:
                    return self._delayed_oppology(path, e, **kwargs)
                else:
                    return self._oppologize(path, path.copy(), **kwargs)
            except exc_list: #pylint:disable=broad-except
                l.error("Oppologizer hit an error.", exc_info=True)
                return None
        except exc_list: #pylint:disable=broad-except
            l.error("Original block hit an error.", exc_info=True)
            return None
