class SimEngineRequest(object):
    """
    This class serves as a container for the input to SimEngine and output from a SimEngine.
    """

    def __init__(self, state, inline=False, force_bbl_addr=None, *args, **kwargs):
        """
        Create a SimEngineRequest.
        """
        self.kwargs = kwargs
        self.args = args
        self.input_state = state

        # whether or not the execution should be "inlined"
        self.inline = inline

        # an override for the address of the state
        self.force_bbl_addr = force_bbl_addr

        # The successors of this SimRun
        self.successors = [ ]
        self.all_successors = [ ]
        self.flat_successors = [ ]
        self.unsat_successors = [ ]
        self.unconstrained_successors = [ ]

        # the engine that should process or did process this request
        self.engine = None
        self.processed = False

        # the name (for stringification)
        self.custom_name = None

        # some scratch stuff for the VEX engine
        self.irsb = None
        self.conditional_guards = None
        self.last_imark = None

        # some scratch stuff for the SimProcedure engine
        self.procedure = None
        self.sim_kwargs = None
        self.ret_to = None
        self.ret_expr = None

    @property
    def addr(self):
        if self.force_bbl_addr is not None:
            return self.input_state.any_int(self.input_state.pc)
        else:
            return self.force_bbl_addr

    def __repr__(self):
        start_str = "%s to %s" % (self.input_state.scratch.jumpkind, self.addr)

        if self.processed:
            successor_strings = [ ]
            if len(self.flat_successors) != 0:
                successor_strings.append("%d sat")
            if len(self.unsat_successors) != 0:
                successor_strings.append("%d unsat")
            if len(self.unconstrained_successors) != 0:
                successor_strings.append("%d unconstrained")

            if len(successor_strings) != 0:
                successors = "successors (%s)" % ", ".join(successor_strings)

            processed_str = " - ".join((successors, self.engine.describe(self)))
        else:
            processed_str = "unprocessed"

        return "<SimEngineRequest %s - %s>" % (start_str, processed_str)
