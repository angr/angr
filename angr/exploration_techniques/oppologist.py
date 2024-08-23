from __future__ import annotations
import claripy
import functools

import logging

l = logging.getLogger(name=__name__)

from ..errors import AngrError, SimError, SimUnsupportedError, SimCCallError
from .. import sim_options
from ..engines.successors import SimSuccessors

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
        new.release_plugin("unicorn")
        new.register_plugin("unicorn", old.unicorn.copy())
        new.options = old.options.copy()

    def _oppologize(self, simgr, state, pn, **kwargs):
        l.debug("... pn: %s", pn)

        pn.options.add(sim_options.UNICORN)
        pn.options.add(sim_options.UNICORN_AGGRESSIVE_CONCRETIZATION)
        pn.unicorn.max_steps = 1
        pn.unicorn.countdown_symbolic_stop = 0
        pn.unicorn.countdown_unsupported_stop = 0
        pn.unicorn.countdown_nonunicorn_blocks = 0
        pn.unicorn.countdown_stop_point = 0
        ss = simgr.successors(pn, throw=True, **kwargs)

        fixup = functools.partial(self._restore_state, state)

        l.debug("... successors: %s", ss)
        for s in ss.flat_successors + ss.unconstrained_successors + ss.unsat_successors + ss.successors:
            fixup(s)

        return ss

    @staticmethod
    def _combine_results(*results):
        final = SimSuccessors(results[0].addr, results[0].initial_state)
        final.description = "Oppology"
        final.sort = "Oppologist"

        for med in results:
            final.processed = True
            final.successors.extend(med.successors)
            final.all_successors.extend(med.all_successors)
            final.flat_successors.extend(med.flat_successors)
            final.unsat_successors.extend(med.unsat_successors)
            final.unconstrained_successors.extend(med.unsat_successors)

        return final

    def _delayed_oppology(self, simgr, state, e, **kwargs):
        ss = simgr.successors(state, num_inst=e.executed_instruction_count, **kwargs)
        need_oppologizing = [s for s in ss.flat_successors if s.addr == e.ins_addr]
        ss.flat_successors = [s for s in ss.flat_successors if s.addr != e.ins_addr]
        results = [ss]

        results.extend(map(functools.partial(self._oppologize, simgr, state, **kwargs), need_oppologizing))
        return self._combine_results(*results)

    def successors(self, simgr, state, **kwargs):
        try:
            kwargs.pop("throw", None)
            return simgr.successors(state, **kwargs)

        except (SimUnsupportedError, SimCCallError) as e:
            l.debug("Errored on path %s after %d instructions", state, e.executed_instruction_count)
            try:
                if e.executed_instruction_count:
                    return self._delayed_oppology(simgr, state, e, **kwargs)
                return self._oppologize(simgr, state, state.copy(), **kwargs)
            except exc_list as err:
                l.error("Oppologizer hit an error while trying to perform repairs", exc_info=True)
                raise e from err
        except Exception:  # pylint:disable=broad-except
            l.error("Original block hit an unsupported error", exc_info=True)
            raise
