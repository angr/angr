import logging
import signal
import sys
from angr.engines import SimEngine
from angr_targets.concrete import ConcreteTarget


l = logging.getLogger("angr.engines.concrete")
#l.setLevel(logging.DEBUG)


def timeout_handler():
    l.critical("[ERROR] Timeout error during resuming of concrete process")
    # situation is compromised, better to exit.
    sys.exit()


class SimEngineConcrete(SimEngine):
    """
    Concrete execution using a concrete target provided by the user.
    """
    def __init__(self, project):
        l.info("Initializing SimEngineConcrete with ConcreteTarget provided.")
        super(SimEngineConcrete, self).__init__()
        self.project = project
        if isinstance(self.project.concrete_target, ConcreteTarget):
            self.target = self.project.concrete_target

        else:
            l.warn("Error, you must provide an instance of a ConcreteTarget to initialize a SimEngineConcrete.")
            self.target = None

        self.segment_registers_already_init = False
        self.unexpected_stop_points_limit = 4

    def process(self, state,
                step=None,
                extra_stop_points=None,
                inline=False,
                force_addr=None,
                **kwargs):
        """
        :param state:               The state with which to execute
        :param step:                How many basic blocks we want to execute
        :param extra_stop_points:   A collection of addresses at which execution should halt
        :param inline:              This is an inline execution. Do not bother copying the state.
        :param force_addr:          Force execution to pretend that we're working at this concrete
                                    address
        :returns:                   A SimSuccessors object categorizing the results of the run and
                                    whether it succeeded.
        """
        return super(SimEngineConcrete, self).process(state,
                    step=step,
                    extra_stop_points=extra_stop_points,
                    inline=inline,
                    force_addr=force_addr,
                    **kwargs)

    def _check(self, state, **kwargs):
        return True

    def _process(self, state, successors, step, extra_stop_points=None, concretize=None, **kwargs):

        # setup the concrete process and resume the execution
        self.to_engine(state, extra_stop_points, concretize, **kwargs)

        # sync angr with the current state of the concrete process using
        # the state plugin
        state.concrete.sync()

        successors.engine = "SimEngineConcrete"
        successors.sort = "SimEngineConcrete"
        successors.add_successor(state, state.ip, state.se.true, state.unicorn.jumpkind)
        successors.description = "Concrete Successors "
        successors.processed = True

    def to_engine(self, state, extra_stop_points, concretize):
        """
        Handle the concrete execution of the process
        This method takes care of:
        1- Set the breakpoints on the addresses provided by the user
        2- Concretize the symbolic variables and perform the write inside the concrete process
        3- Continue the program execution.

        :param state:               The state with which to execute
        :param extra_stop_points:   list of a addresses where to stop the concrete execution and return to the simulated one
        :param concretize:          list of tuples (address, symbolic variable) that are going to be written
                                    in the concrete process memory
        :return:
        """
        l.info("Entering in SimEngineConcrete: simulated address %s concrete address %s stop points %s" %
               (hex(state.addr), hex(self.target.read_register("pc")), extra_stop_points))

        if concretize:
            l.warn("Concretize variables before entering inside the SimEngineConcrete | "
                   "Be patient this could take a while.")

            for sym_var in concretize:
                sym_var_address = state.se.eval(sym_var[0])
                sym_var_value = state.se.eval(sym_var[1], cast_to=str)
                l.debug("Concretize memory at address %s with value %s" % (hex(sym_var_address), sym_var_value))
                self.target.write_memory(sym_var_address, sym_var_value)

        # Set breakpoint on remote target
        for stop_point in extra_stop_points:
            l.debug("Setting breakpoints at %s " % hex(stop_point))
            self.target.set_breakpoint(stop_point, temporary=True)

        # Set up the timeout if requested
        if self.target.timeout:
            original_sigalrm_handler = signal.getsignal(signal.SIGALRM)
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(self.target.timeout)

        # resuming of the concrete process, if the target won't reach the
        # breakpoint specified by the user the timeout will abort angr execution.
        self.target.run()

        # reset the alarm
        if self.target.timeout:
            signal.alarm(0)

        # handling the case in which the program stops at a point different than the breakpoints set
        # by the user. In these case we try to resume the execution hoping that the concrete process will
        # reach the correct address.

        unexpected_breakpoint_cnt = 0

        while self.target.read_register("pc") not in extra_stop_points:
            print(extra_stop_points)
            unexpected_breakpoint_cnt = unexpected_breakpoint_cnt + 1
            if unexpected_breakpoint_cnt == self.unexpected_stop_points_limit:
                l.warn("Reached max number of hits of not expected breakpoints. Aborting.")
            else:
                if self.target.timeout:
                    signal.alarm(self.target.timeout)
                self.target.run()
                l.warn("Stopped a pc %s but breakpoint set to %s so resuming concrete execution"
                       % (hex(self.target.read_register("pc")), [hex(bp) for bp in extra_stop_points]))

        # restoring old sigalrm handler
        if self.target.timeout:
            signal.signal(signal.SIGALRM, original_sigalrm_handler)

        # removing all breakpoints set by Symbion
        for breakpoint in extra_stop_points:
            l.debug("Removing breakpoint at %s" % hex(breakpoint))
            self.target.remove_breakpoint(breakpoint)



