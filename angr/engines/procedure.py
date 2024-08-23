from __future__ import annotations
import logging

l = logging.getLogger(name=__name__)

from .engine import SuccessorsMixin

# pylint: disable=arguments-differ


class ProcedureMixin:
    """
    A mixin for SimEngine which adds the ``process_procedure`` method for calling a SimProcedure and adding its results
    to a SimSuccessors.
    """

    def process_procedure(self, state, successors, procedure, ret_to=None, arguments=None, **kwargs):
        successors.sort = "SimProcedure"

        # fill in artifacts
        successors.artifacts["is_syscall"] = procedure.is_syscall
        successors.artifacts["name"] = procedure.display_name
        successors.artifacts["no_ret"] = procedure.NO_RET
        successors.artifacts["adds_exits"] = procedure.ADDS_EXITS

        # Update state.scratch
        state.scratch.sim_procedure = procedure
        state.history.recent_block_count = 1

        # prepare and run!
        if procedure.is_syscall:
            state._inspect("syscall", BP_BEFORE, syscall_name=procedure.display_name)

        cleanup_options = o.AUTO_REFS not in state.options and o.ADD_AUTO_REFS in state.options
        if cleanup_options:
            state.options.add(o.AST_DEPS)
            state.options.add(o.AUTO_REFS)

        # do it
        inst = procedure.execute(state, successors, ret_to=ret_to, arguments=arguments)
        successors.artifacts["procedure"] = inst

        if cleanup_options:
            state.options.discard(o.AST_DEPS)
            state.options.discard(o.AUTO_REFS)

        if procedure.is_syscall:
            state._inspect("syscall", BP_AFTER, syscall_name=procedure.display_name, simprocedure=inst)

        successors.description = "SimProcedure " + procedure.display_name
        if procedure.is_syscall:
            successors.description += " (syscall)"
        if procedure.is_stub:
            successors.description += " (stub)"
        successors.processed = True


class ProcedureEngine(ProcedureMixin, SuccessorsMixin):
    """
    A SimEngine that you may use if you only care about processing SimProcedures. *Requires* the procedure
    kwarg to be passed to process.
    """

    def process_successors(self, successors, procedure=None, **kwargs):
        if procedure is None:
            raise errors.SimEngineError("Must provide the procedure explicitly to use ProcedureEngine")
        self.process_procedure(self.state, successors, procedure, **kwargs)


from .. import sim_options as o
from .. import errors
from ..state_plugins.inspect import BP_BEFORE, BP_AFTER
