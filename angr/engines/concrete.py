import logging

from ..engines import SimEngine
from ..state_plugins.inspect import BP_AFTER

#pylint: disable=arguments-differ

l = logging.getLogger("angr.engines.concrete")


class ConcreteTarget(object):
    """
    Concrete target used inside the SimConcreteEngine.
    This object is defined in the Angr script.
    """
    def _init_(self):
        return

    def read_memory(self, address, length, **kwargs):
        raise NotImplementedError()

    def write_memory(self, address, data, **kwargs):
        raise NotImplementedError()

    def is_valid_address(self, address, **kwargs):
        raise NotImplementedError()

    def read_register(self, register, **kwargs):
        raise NotImplementedError()

    def write_register(self, register, value, **kwargs):
        raise NotImplementedError()

    def set_breakpoint(self, address, **kwargs):
        raise NotImplementedError()

    def remove_breakpoint(self, address, **kwargs):
        raise NotImplementedError()

    def set_watchpoint(self, address, **kwargs):
        raise NotImplementedError()

    def remove_watchpoint(self, address, **kwargs):
        raise NotImplementedError()

    def run(self):
        raise NotImplementedError()




class SimEngineConcrete(SimEngine):
    """
    Concrete execution inside a concrete target provided by the user.
    :param target: receive and wraps a ConcreteTarget inside this SimConcreteEngine
    """
    def __init__(self, concrete_target=None):

        super(SimEngineConcrete, self).__init__()

        self.target = concrete_target

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
                force_addr=force_addr)

    def _check(self, state, **kwargs):
        return True

    def _process(self, state, successors, step, extra_stop_points):
        pass

    def from_engine(self):
        """
        Handling the switch between the concrete execution and Angr.
        This method takes care of:
        1- Synchronize registers
        2- Substitute the CLEMemory backer of the State with a ConcreteCLEMemory object
           that redirects the read inside the concrete process.
        3- Flush all the pages loaded until now.

        :return:
        """
        '''
        # sync Angr registers with the one getting from
        # the concrete target
        regs = []
        for reg in registers:
            regs.append(self._target.ReadRegister(reg))

        self.state.sync_regs(regs)

        # Fix the memory of the newly created state
        # 1) fix the memory backers of this state, this is accomplished
        #    by plugging the ConcreteCLEMemory to the backers
        # 2) flush the pages so they will be initialized by the backers content when
        # 	Angr access it.

        self.project.loader.backers = ConcreteCLEMemory(self._target)
        self._state.mem.flush_pages()
        '''

    def to_engine(self):
        """
        Handling the switch between the execution in Angr and the concrete target.
        This method takes care of:
        1- Set the breakpoint on the address provided by the user
        2- Concretize the symbolic variables and perform the write inside the concrete process
        3- Continue the program execution.
        :return:
        """

        '''
        to_concretize_address = None

        # Set breakpoint on remote target
        self._target.SetBreakpoint(break_address)

        while True:
            # Concretize required symbolic vars and set watchpoints on remote target over the
            # not yet concretized symbolic variables
            if to_concretize_address != None:
                concrete_value = self._getSolutions(to_concretize_address)
                self._target.WriteMemory(to_concretize_address, concrete_value)

            # we set/update watchpoints to all the addresses containing symbolic variables now
            self._target.UpdateWatchPoints(self.state.GetSymVarAddresses())

            # Continue the execution of the binary
            stop_point = self._target.Run()

            if stop_point.reason == "BREAKPOINT_HIT":  # if we have a breakpoint hit this mean the execution inside the concrete engine must be stopped.
                break

            elif stop_point.reason == "WATCHPOINT_HIT":  # if we hit a watchpoint we need to concretize the sym_var hit and restart the execution.
                to_concretize_address = stop_point.address

            elif stop_point.reason == "OTHER_REASONS":
                ...  # handle reason

        return
        '''
