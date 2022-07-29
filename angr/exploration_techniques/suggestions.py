import logging
import claripy

from . import ExplorationTechnique
from ..misc.ux import once
from ..misc.picklable_lock import PicklableLock
from ..state_plugins.sim_action import SimActionConstraint
from ..state_plugins.sim_action_object import SimActionObject

l = logging.getLogger(__name__)

def ast_weight(ast, memo=None):
    if isinstance(ast, SimActionObject):
        ast = ast.ast
    if not isinstance(ast, claripy.ast.Base):
        return 0

    if memo is None:
        memo = {}

    result = memo.get(ast.cache_key, None)
    if result is not None:
        return result

    result = 1 + sum(ast_weight(arg, memo) for arg in ast.args)
    memo[ast.cache_key] = result
    return result


class Suggestions(ExplorationTechnique):
    """
    An exploration technique which analyzes failure cases and logs suggestions for how to mitigate them in future
    analyses.
    """
    def __init__(self):
        super().__init__()
        self.suggested = set()
        self.lock = PicklableLock()

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        for state in simgr.stashes.get('interrupted', []):
            if id(state) in self.suggested:
                continue
            self.suggested.add(id(state))

            try:
                event = state.history.events[-1]
            except IndexError:
                continue
            if event.type != 'insufficient_resources':
                continue

            with self.lock:  # do not interleave logs
                self.report(state, event)

        return simgr

    @staticmethod
    def report(state, event):
        if once('suggestion_technique'):
            l.warning("Some of your states hit a resource limit. set logger %s to INFO for suggestions.", __name__)
            l.info("Create your simulation manager with `suggestions=False` to disable this.")

        if event.objects['type'] is claripy.errors.ClaripySolverInterruptError:
            if event.objects['reason'][0] == 'timeout':
                limit_number = state.solver._solver.timeout
                limit_kind = 'hit a solver timeout of %s ms.' % limit_number
                limit_minimum = 60 * 1000
            elif event.objects['reason'][0] == 'max. memory exceeded':
                limit_number = state.solver._solver.max_memory
                limit_kind = 'hit a solver memory limit of %s MB.' % limit_number
                limit_minimum = 1024
            else:
                limit_number = None
                limit_kind = 'hit an unknown resource limit. are you manually mucking with the z3 backend?'
                limit_minimum = None
            l.info('%s %s', state, limit_kind)
            if limit_number is not None and limit_minimum is not None and limit_number < limit_minimum:
                l.info("The minimum recommended limit is %s. Consider turning it up?", limit_minimum)

            log = []
            for history in state.history.lineage:
                for constraint_event in history.recent_events:
                    if isinstance(constraint_event, SimActionConstraint):
                        constraint = constraint_event.constraint.ast
                        if constraint is history.jump_guard:
                            src_addr = history.jump_source
                            dst_addr = history.jump_target
                            transition_type = 'jumping'
                        else:
                            if constraint_event.sim_procedure is None:
                                src_addr = constraint_event.ins_addr
                            else:
                                src_addr = constraint_event.sim_procedure.addr
                            block = state.block(src_addr, num_inst=2)
                            try:
                                dst_addr = block.instruction_addrs[1]
                            except IndexError:
                                dst_addr = history.jump_target
                            transition_type = 'stepping'
                        if type(dst_addr) is int:
                            dst_addr = claripy.BVV(dst_addr, state.arch.bits)
                        log.append((constraint, ast_weight(constraint), src_addr, dst_addr, transition_type, len(log)))

            log.sort(key=lambda t: t[1], reverse=True)
            max_delta_idx = None
            if len(log) > 1:
                deltas = [b[1] - a[1] for a, b in zip(log, log[1:])]
                max_delta_idx, max_delta = max(enumerate(deltas))
                if max_delta < 2**10:
                    max_delta_idx = None
            if max_delta_idx is None and log and log[0][1] >= 2**16:
                for max_delta_idx, t in enumerate(log):
                    if t[1] < 2**16:
                        max_delta_idx -= 1
                        break
            if max_delta_idx is not None:
                l.info(
                    "%d constraint%s abnormally complex.",
                    max_delta_idx + 1,
                    's are' if max_delta_idx > 0 else ' is'
                )
                descriptions = []
                for t in sorted(log[:max_delta_idx+1], key=lambda t: t[5]):
                    if max_delta_idx < 10:
                        l.info(
                            "...generated %s from %s to %s",
                            t[4],
                            state.project.loader.describe_addr(t[2]),
                            state.project.loader.describe_addr(t[3].args[0])
                            if t[3].op == 'BVV' else '<symbol>'
                        )
                    descriptions.extend(state.solver.describe_variables(t[0]))
                descriptions = set(descriptions)
                seen_apis = set()
                for description in descriptions:
                    if description[0] == 'api':
                        if description[1] not in seen_apis:
                            seen_apis.add(description[1])
                            l.info("...using variables originating in %s (hook it?)", description[1])
                    elif description[0] == 'mem':
                        if '##mem' not in seen_apis:
                            seen_apis.add('##mem')
                            l.info("...using unconstrained memory (add ZERO_FILL_UNCONSTRAINED_MEMORY?)")
                    elif description[0] == 'reg':
                        if '##reg' not in seen_apis:
                            seen_apis.add('##reg')
                            l.info("...using unconstrained registers (add ZERO_FILL_UNCONSTRAINED_REGISTERS?)")
                    elif description[0] == 'file':
                        api = 'file##' + description[1]
                        if api not in seen_apis:
                            seen_apis.add(api)
                            l.info("...using variables from file %s", description[1])
                    else:
                        l.info("...using uncategorized variable %s", description)
