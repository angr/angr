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

    def read_memory(self,address, length):
        raise NotImplementedError()

    def write_memory(self,address, data):
        raise NotImplementedError()

    def is_valid_address(self,address):
        raise NotImplementedError()

    def read_register(self,register):
        raise NotImplementedError()

    def write_register(self,register):
        raise NotImplementedError()

    def set_breakpoint(self,address):
        raise NotImplementedError()

    def remove_breakpoint(self,address):
        raise NotImplementedError()

    def set_watchpoint(self,address):
        raise NotImplementedError()

    def remove_watchpoint(self,address):
        raise NotImplementedError()

    def cont(self):
        raise NotImplementedError()

    def wait(self):
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
        # Whatever checks before turning on this engine
        # TODO
        return True

    def _process(self, state, successors, step, extra_stop_points):
        self.to_engine(state, extra_stop_points)
        self.from_engine()
        return

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
            regs.append(self._target.read_register(reg))

        self.state.sync_regs(regs)

        # Fix the memory of the newly created state
        # 1) fix the memory backers of this state, this is accomplished
        #    by plugging the ConcreteCLEMemory to the backers
        # 2) flush the pages so they will be initialized by the backers content when
        # 	Angr access it.

        self.project.loader.backers = ConcreteCLEMemory(self._target)
        self._state.mem.flush_pages()
        '''

    def to_engine(self,state, extra_stop_points):
        """
        Handling the switch between the execution in Angr and the concrete target.
        This method takes care of:
        1- Set the breakpoint on the address provided by the user
        2- Concretize the symbolic variables and perform the write inside the concrete process
        3- Continue the program execution.
        :return:
        """

        to_concretize_address = None

        # Set breakpoint on remote target
        for stop_point in extra_stop_points:
            self._target.set_breakpoint(stop_point)

        # Concretize everything inside the state! # TODO-BIG absolutely don't know how!
        # concretize_stuff = state.concretize_everything()

        # Continue the execution of the binary
        stop_point = self._target.run()

        if stop_point.reason == "BREAKPOINT_HIT":  # if we have a breakpoint hit this mean the execution inside the concrete engine must be stopped.
            return True
        elif stop_point.reason == "OTHER_REASONS":
            return False



