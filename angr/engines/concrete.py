import logging
import signal
import sys

from .engine import SimEngine
from ..errors import SimConcreteMemoryError, SimConcreteRegisterError

l = logging.getLogger("angr.engines.concrete")

try:
    from angr_targets.concrete import ConcreteTarget
except ImportError as e:
    l.error("Can't find angr_targets project!")


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
        if isinstance(self.project.concrete_target, ConcreteTarget) and \
                self.check_concrete_target_methods(self.project.concrete_target):
            self.target = self.project.concrete_target

        else:
            l.warning("Error, you must provide an instance of a ConcreteTarget to initialize a SimEngineConcrete.")
            self.target = None
            sys.exit()

        self.segment_registers_already_init = False
        self.unexpected_stop_points_limit = 4

    def _check(self, state, *args, **kwargs):
        return True

    def _process(self, new_state, successors, *args, ** kwargs):
        # setup the concrete process and resume the execution
        self.to_engine(new_state, kwargs['extra_stop_points'], kwargs['concretize'])

        # sync angr with the current state of the concrete process using
        # the state plugin
        new_state.concrete.sync()

        successors.engine = "SimEngineConcrete"
        successors.sort = "SimEngineConcrete"
        successors.add_successor(new_state, new_state.ip, new_state.solver.true, new_state.unicorn.jumpkind)
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
        :param extra_stop_points:   list of a addresses where to stop the concrete execution and return to the
                                    simulated one
        :param concretize:          list of tuples (address, symbolic variable) that are going to be written
                                    in the concrete process memory
        :return:
        """

        l.debug("Entering in SimEngineConcrete: simulated address %s concrete address %s stop points %s",
                hex(state.addr), hex(self.target.read_register("pc")), map(hex, extra_stop_points))

        if concretize:
            l.debug("SimEngineConcrete is concretizing variables before resuming the concrete process")

            for sym_var in concretize:
                sym_var_address = state.solver.eval(sym_var[0])
                sym_var_value = state.solver.eval(sym_var[1], cast_to=bytes)
                l.debug("Concretize memory at address %s with value %s", hex(sym_var_address), str(sym_var_value))
                self.target.write_memory(sym_var_address, sym_var_value, raw=True)

        # Set breakpoint on remote target
        for stop_point in extra_stop_points:
            l.debug("Setting breakpoints at %s ", hex(stop_point))
            self.target.set_breakpoint(stop_point, temporary=True)

        # Set up the timeout if requested
        original_sigalrm_handler = None
        if self.target.timeout:
            original_sigalrm_handler = signal.getsignal(signal.SIGALRM)
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(self.target.timeout)

        # resuming of the concrete process, if the target won't reach the
        # breakpoint specified by the user the timeout will abort angr execution.
        l.debug("SimEngineConcrete is resuming the concrete process")
        self.target.run()
        l.debug("SimEngineConcrete has successfully resumed the process")

        # reset the alarm
        if self.target.timeout:
            signal.alarm(0)

        # handling the case in which the program stops at a point different than the breakpoints set
        # by the user. In these case we try to resume the execution hoping that the concrete process will
        # reach the correct address.

        unexpected_breakpoint_cnt = 0

        while self.target.read_register("pc") not in extra_stop_points:
            unexpected_breakpoint_cnt = unexpected_breakpoint_cnt + 1
            if unexpected_breakpoint_cnt == self.unexpected_stop_points_limit:
                l.warning("Reached max number of hits of not expected breakpoints. Aborting.")
            else:
                if self.target.timeout:
                    signal.alarm(self.target.timeout)
                self.target.run()
                l.warning("Stopped a pc %s but breakpoint set to %s so resuming concrete execution",
                          hex(self.target.read_register("pc")), [hex(bp) for bp in extra_stop_points])

        # restoring old sigalrm handler
        if self.target.timeout:
            signal.signal(signal.SIGALRM, original_sigalrm_handler)

        # removing all breakpoints set by Symbion
        for stop_point in extra_stop_points:
            l.debug("Removing breakpoint at %s", hex(stop_point))
            self.target.remove_breakpoint(stop_point)

    @staticmethod
    def check_concrete_target_methods(concrete_target):
        """
        Check if the concrete target methods return the correct type of data
        :return: True if the concrete target is compliant
        """
        entry_point = concrete_target.read_register("pc")
        if not type(entry_point) is int:
            l.error("read_register result type is %s, should be <type 'int'>", (type(entry_point)))
            return False

        mem_read = concrete_target.read_memory(entry_point, 0x4)

        if not type(mem_read) is bytes:
            l.error("read_memory result type is %s, should be <type 'str'>", (type(mem_read)))
            return False

        try:
            concrete_target.read_register("not_existent_reg")
            l.error("read_register should raise a SimConcreteRegisterError when accessing non existent registers")
            return False

        except SimConcreteRegisterError:
            l.warning("read_register raise a SimConcreteRegisterError, ok!")

        try:
            concrete_target.read_memory(0x0, 0x4)
            l.error("read_memory should raise a SimConcreteMemoryError when accessing non mapped memory")
            return False

        except SimConcreteMemoryError:
            l.warning("read_register raise a SimConcreteMemoryError, ok!")

        return True
