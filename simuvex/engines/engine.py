import logging

l = logging.getLogger('simuvex.engines.engine')

class SimEngine(object):
    """
    How to actually execute stuff.
    Abstracts over VEX, Python (simprocedures), Unicorn, LLVM, and hopefully more in the future.
    """

    def process(self, request):
        """
        Processes a SimEngineRequest, turning its input state into output states.

        :param engine_request: The SimEngineRequest to process.
        :returns: the same SimEngineRequest
        """
        self._process_request(request)
        self._finalize_request(request)
        request.engine = self

    def process_state(self, state, *args, **kwargs):
        """
        Creates and processes a SimEngineInput subclass instance for this engine.
        """

        ei = SimEngineRequest(state, *args, **kwargs)
        return self.process(ei)

    def _process_request(self, request):
        """
        Processes the request.
        """
        raise NotImplementedError()

    @staticmethod
    def _finalize_request(request):
        """
        Finalizes the request.
        """
        # do some cleanup
        if o.DOWNSIZE_Z3 in request.input_state.options:
            request.input_state.downsize()
            for s in s.successors:
                s.downsize()

        # now delete the final state if the run was not inlined
        if not request.inline:
            request.active_state = None

        # record if the exit is unavoidable
        if len(request.flat_successors) == 1 and len(request.unconstrained_successors) == 0:
            request.flat_successors[0].scratch.avoidable = False

    #
    # State management
    #

    @staticmethod
    def _preprocess_input_state(request):
        """
        Preprocesses the input state.

        :param request: the SimEngineRequest
        """

        # make a copy of the initial state for actual processing, if needed
        if not request.inline and o.COW_STATES in request.input_state.options:
            request.active_state = request.input_state.copy()
        else:
            request.active_state = request.input_state

        # first, clear the log (unless we're inlining)
        if not request.inline:
            request.active_state.log.clear()
            request.active_state.scratch.clear()

from simuvex import s_options as o
from .request import SimEngineRequest
