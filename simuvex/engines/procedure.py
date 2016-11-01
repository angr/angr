#!/usr/bin/env python

import logging
l = logging.getLogger(name = "simuvex.s_procedure")

from .engine import SimEngine

class SimEngineProcedure(SimEngine):
    ADDS_EXITS = False
    NO_RET = False
    IS_SYSCALL = False

    local_vars = ()

    def _process_request(
        self, request,
        **kwargs
    ):
        procedure = request.kwargs['procedure']

        # Update state.scratch
        request.active_state.scratch.bbl_addr = self.addr if force_bbl_addr is None else force_bbl_addr
        request.active_state.scratch.sim_procedure = self.__class__.__name__
        request.active_state.scratch.executed_block_count = 1

        request.ret_to = kwargs.get('ret_to', None)

        # prepare and run!
        cleanup_options = o.AUTO_REFS not in request.active_state.options:
        if cleanup_options:
            request.active_state.options.add(o.AST_DEPS)
            request.active_state.options.add(o.AUTO_REFS)

        # do it
        procedure.setup_and_run(request)

        if cleanup_options:
            request.active_state.options.discard(o.AST_DEPS)
            request.active_state.options.discard(o.AUTO_REFS)

    def initialize_run(self):
        pass

    def handle_run(self):
        self.handle_procedure()

    def handle_procedure(self):
        raise Exception("SimProcedure.handle_procedure() has been called. This should have been overwritten in class %s.", self.__class__)

    @classmethod
    def static_exits(cls, arch, blocks):  # pylint: disable=unused-argument
        """
        Get new exits by performing static analysis and heuristics. This is a fast and best-effort approach to get new
        exits for scenarios where states are not available (e.g. when building a fast CFG).

        :param arch: Architecture of the current project.
        :param list blocks: Blocks that are executed before reaching this SimProcedure.
        :return: A list of tuples. Each tuple is (address, jumpkind).
        :rtype: list
        """

        if cls.ADDS_EXITS:
            raise SimProcedureError("static_exits() is not implemented for SimProcedure %s" % cls.__name__)

        else:
            # This SimProcedure does not add any new exit
            return [ ]

from .. import s_options as o
from ..s_errors import SimProcedureError, SimProcedureArgumentError
from ..s_type import SimTypePointer
from ..s_action import SimActionExit
