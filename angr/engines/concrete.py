from angr.engines import SimEngine
from angr_targets.concrete import ConcreteTarget
from angr_targets.segment_registers import *
import logging
import struct
from angr.errors import SimMemoryError


#pylint: disable=arguments-differ
#l = logging.getLogger("angr.engines.concrete")
l.setLevel(logging.DEBUG)


class SimEngineConcrete(SimEngine):
    """
    Concrete execution inside a concrete target provided by the user.
    :param target: receive and wraps a ConcreteTarget inside this SimConcreteEngine
    """
    def __init__(self,project ):
        l.info("Initializing SimEngineConcrete with ConcreteTarget provided.")
        super(SimEngineConcrete, self).__init__()
        self.project = project
        if isinstance(self.project.concrete_target,ConcreteTarget):
            self.target = self.project.concrete_target
        else:
            l.warn("Error, you must provide an instance of a ConcreteTarget to initialize a SimEngineConcrete.")
            self.target = None
        self.segment_registers_already_init = False

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
       # self.from_engine(state, **kwargs)
        state.concrete.sync()

        successors.engine = "SimEngineConcrete"
        successors.sort = "SimEngineConcrete"
        successors.add_successor(state, state.ip, state.se.true, state.unicorn.jumpkind)
        successors.description = "Concrete Successors "
        successors.processed = True



    def to_engine(self, state, extra_stop_points, concretize, **kwargs):
        """
        Handling the switch between the execution in Angr and the concrete target.
        This method takes care of:
        1- Set the breakpoint on the address provided by the user
        2- Concretize the symbolic variables and perform the write inside the concrete process
        3- Continue the program execution.
        :return:
        """
        l.info("Entering in SimEngineConcrete: simulated address 0x%x concrete address 0x%x stop points %s"%(state.addr, self.target.read_register("pc"),extra_stop_points ))
        if concretize != []:
            l.info("Concretize variables before entering inside the SimEngineConcrete | "
                      "Be patient this could take a while.")
            for sym_var in concretize:
                sym_var_address = state.se.eval(sym_var[0])
                sym_var_value = state.se.eval(sym_var[1], cast_to=str)
                l.debug("Concretizing memory at address " + hex(sym_var_address) + " with value " + sym_var_value)
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
            l.debug("Setting breakpoints at " + hex(stop_point))
            self.target.set_breakpoint(stop_point, temporary=True)

        # Continue the execution of the binary
        #stop_point = self.target.run()
        self.target.run()
        while(self.target.read_register("pc") not in extra_stop_points):
            self.target.run()
            print("Stopped a pc %x but breakpoint set to %s so resuming concrete execution"%(self.target.read_register("pc"),[hex(bp) for bp in  extra_stop_points]))



        '''
        if stop_point.reason == "BREAKPOINT_HIT":
            return True
        elif stop_point.reason == "OTHER_REASONS":
            return False
        '''


