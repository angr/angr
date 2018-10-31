import logging
l = logging.getLogger(name=__name__)

from .engine import SimEngine

#pylint: disable=arguments-differ

class SimEngineProcedure(SimEngine):
    """
    An engine for running SimProcedures
    """

    def process(self, state, procedure,
            ret_to=None,
            inline=None,
            force_addr=None,
            **kwargs):
        """
        Perform execution with a state.

        :param state:       The state with which to execute
        :param procedure:   An instance of a SimProcedure to run
        :param ret_to:      The address to return to when this procedure is finished
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        return super(SimEngineProcedure, self).process(state, procedure,
                ret_to=ret_to,
                inline=inline,
                force_addr=force_addr)

    def _check(self, state, *args, **kwargs):
        return True

    def _process(self, state, successors, procedure, ret_to=None):
        successors.sort = 'SimProcedure'

        # fill in artifacts
        successors.artifacts['is_syscall'] = procedure.is_syscall
        successors.artifacts['name'] = procedure.display_name
        successors.artifacts['no_ret'] = procedure.NO_RET
        successors.artifacts['adds_exits'] = procedure.ADDS_EXITS

        # Update state.scratch
        state.scratch.sim_procedure = procedure
        state.history.recent_block_count = 1

        # prepare and run!
        state._inspect('simprocedure',
                       BP_BEFORE,
                       simprocedure_name=procedure.display_name,
                       simprocedure_addr=successors.addr,
                       simprocedure=procedure
                       )
        if procedure.is_syscall:
            state._inspect('syscall', BP_BEFORE, syscall_name=procedure.display_name)

        cleanup_options = o.AUTO_REFS not in state.options
        if cleanup_options:
            state.options.add(o.AST_DEPS)
            state.options.add(o.AUTO_REFS)

        # do it
        inst = procedure.execute(state, successors, ret_to=ret_to)
        successors.artifacts['procedure'] = inst

        if cleanup_options:
            state.options.discard(o.AST_DEPS)
            state.options.discard(o.AUTO_REFS)

        if procedure.is_syscall:
            state._inspect('syscall', BP_AFTER, syscall_name=procedure.display_name)
        state._inspect('simprocedure',
                       BP_AFTER,
                       simprocedure_name=procedure.display_name,
                       simprocedure_addr=successors.addr,
                       simprocedure=inst
                       )

        successors.description = 'SimProcedure ' + procedure.display_name
        if procedure.is_syscall:
            successors.description += ' (syscall)'
        if procedure.is_stub:
            successors.description += ' (stub)'
        successors.processed = True

from .. import sim_options as o
from ..state_plugins.inspect import BP_BEFORE, BP_AFTER
