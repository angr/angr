import logging
l = logging.getLogger("simuvex.engines.procedure")

from .engine import SimEngine

#pylint: disable=arguments-differ

class SimEngineProcedure(SimEngine):
    """
    An engine for running SimProcedures
    """

    def process(self, state, procedure,
            ret_to=None,
            inline=None,
            force_addr=None):
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

    def _process(self, state, successors, procedure, ret_to=None):
        successors.description = 'SimProcedure ' + procedure.display_name
        if procedure.is_syscall:
            successors.description += ' (syscall)'

        # Update state.scratch
        state.scratch.sim_procedure = procedure
        state.scratch.executed_block_count = 1

        # prepare and run!
        state._inspect('simprocedure',
                       BP_BEFORE,
                       name=procedure.display_name,
                       addr=successors.addr)
        if procedure.is_syscall:
            state._inspect('syscall', BP_BEFORE, syscall_name=procedure.display_name)

        cleanup_options = o.AUTO_REFS not in state.options
        if cleanup_options:
            state.options.add(o.AST_DEPS)
            state.options.add(o.AUTO_REFS)

        # do it
        procedure.execute(state, successors, ret_to=ret_to)

        if cleanup_options:
            state.options.discard(o.AST_DEPS)
            state.options.discard(o.AUTO_REFS)

        if procedure.is_syscall:
            state._inspect('syscall', BP_AFTER, syscall_name=procedure.display_name)
        state._inspect('simprocedure',
                       BP_AFTER,
                       name=procedure.display_name,
                       addr=successors.addr)

        successors.processed = True

from .. import s_options as o
from ..plugins.inspect import BP_BEFORE, BP_AFTER
