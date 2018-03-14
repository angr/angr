import logging
import cle as cle

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
        l.warning("Initializing SimEngineConcrete with ConcreteTarget provided.")
        super(SimEngineConcrete, self).__init__()
        if isinstance(concrete_target,ConcreteTarget):
            self.target = concrete_target
        else:
            print "Error, you must provide an instance of a ConcreteTarget to initialize" \
                  "a SimEngineConcrete."
            self.target = None

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
                **kwargs
                )

    def _check(self, state, **kwargs):
        # Whatever checks before turning on this engine
        # TODO
        return True

    def _process(self, state, successors, step, extra_stop_points = None, concretize = None, **kwargs ):
        self.to_engine(state, extra_stop_points, concretize, **kwargs)
        self.from_engine(state, **kwargs)

        successors.engine = "SimEngineConcrete"
        successors.sort = "SimEngineConcrete"
        successors.add_successor(state, state.ip, state.se.true, state.unicorn.jumpkind)
        successors.description = "Concrete Successors "
        successors.processed = True


    def from_engine(self,state,**kwargs):
        """
        Handling the switch between the concrete execution and Angr.
        This method takes care of:
        1- Synchronize registers
        2- Substitute the CLEMemory backer of the State with a ConcreteCLEMemory object
           that redirects the read inside the concrete process.
        3- Flush all the pages loaded until now.

        :return:
        """

        #blank_state = state.project.factory.blank_state()

        # sync Angr registers with the one getting from
        # the concrete target

        # registers that we don't want to concretize.
        regs_blacklist = []

        for reg in state.arch.registers:
            if reg not in regs_blacklist:
                try:
                    reg_value = self.target.read_register(reg)
                    #print "Storing " + str(reg_value) + " inside reg " + reg
                    state.registers.store(reg, state.se.BVV(reg_value, state.arch.bits))
                except Exception, e:
                    #l.warning("Can't set register " + reg)
                    pass
                    # TODO need to decide how to handle this

        # Fix the memory of the newly created state
        # 1) fix the memory backers of this state, this is accomplished
        #    by substituting the CLEMemory object with a ConcreteCLEMemory object
        #    that will redirect the read to the remote target.

        # 2) flush the pages so they will be initialized by the backers content when
        # 	 Angr will access it.

        state.project.loader.backers = cle.ConcreteClemory(self.target)
        state.memory.flush_pages()

    def to_engine(self, state, extra_stop_points, concretize, **kwargs):
        """
        Handling the switch between the execution in Angr and the concrete target.
        This method takes care of:
        1- Set the breakpoint on the address provided by the user
        2- Concretize the symbolic variables and perform the write inside the concrete process
        3- Continue the program execution.
        :return:
        """

        if concretize != []:
            l.warning("Concretize variables before entering inside the SimEngineConcrete | "
                      "Be patient this could take a while.")
            for sym_var in concretize:
                sym_var_address = state.se.eval(sym_var[0])
                sym_var_value = state.se.eval(sym_var[1], cast_to=str)
                l.info("Concretizing memory at address " + hex(sym_var_address) + " with value " + sym_var_value)
                self.target.write_memory(sym_var_address, sym_var_value)

        '''
        # Getting rid of this later 
        #-------------------------------------------------------------------------------------------------
        # TODO what if we have multiple solutions?
        # TODO what if we concretize also registers? If not, we are going to refuse to step the SimState?
        # TODO what if we concretize file sym vars?

        # get all the registered symbolic variables inside this state
        # succ.se.get_variables('mem')  only for the memory
        # succ.se.get_variables('reg')  only for register
        # succ.se.get_variables('file') only for file
        #
        # symbolic_vars is f.i:
        # ('mem', 576460752303357952L, 1), <BV64 mem_7ffffffffff0000_5_64{UNINITIALIZED}>)
        #
        symbolic_vars = list(state.se.get_variables('mem'))

        # dictionary of memory address to concretize
        # f.i. to_concretize_memory[0x7ffffffffff0000] = 0xdeadbeef
        #      ...
        to_concretize_memory = {}

        for sym_var in symbolic_vars:
            sym_var_address = sym_var[0][1]
            sym_var_name = sym_var[1]
            sym_var_sol = state.se.eval(sym_var_name)
            self.target.write_memory(sym_var_address,sym_var_sol)
        '''

        # Set breakpoint on remote target
        for stop_point in extra_stop_points:
            l.info("Setting breakpoints at " + hex(stop_point))
            self.target.set_breakpoint(stop_point)

        # Continue the execution of the binary
        #stop_point = self.target.run()

        self.target.run()

        '''
        if stop_point.reason == "BREAKPOINT_HIT":
            return True
        elif stop_point.reason == "OTHER_REASONS":
            return False
        '''


