from angr.engines import SimEngine
from angr_targets.concrete import ConcreteTarget
from angr_targets.segment_registers import *
from archinfo import ArchX86, ArchAMD64
import logging
import struct


#pylint: disable=arguments-differ
l = logging.getLogger("angr.engines.concrete")
#l.setLevel(logging.DEBUG)


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
        self.from_engine(state, **kwargs)

        successors.engine = "SimEngineConcrete"
        successors.sort = "SimEngineConcrete"
        successors.add_successor(state, state.ip, state.se.true, state.unicorn.jumpkind)
        successors.description = "Concrete Successors "
        successors.processed = True

    def from_engine(self, state, **kwargs):
        """
        Handling the switch between the concrete execution and Angr.
        This method takes care of:
        1- Synchronize registers
        2- Substitute the CLEMemory backer of the State with a ConcreteCLEMemory object
           that redirects the read inside the concrete process.
        3- Flush all the pages loaded until now.

        :return:
        """
        whitelist = []
        # Setting a concrete memory backend
        state.memory.mem._memory_backer.set_concrete_target(self.target)

        # Sync Angr registers with the one getting from the concrete target
        # registers that we don't want to concretize.
        regs_blacklist = ['fs', 'gs']
        l.info("Synchronizing general purpose registers")

        for reg_key, reg_name in state.arch.register_names.items():
            if reg_name not in regs_blacklist:
                try:
                    reg_value = self.target.read_register(reg_name)
                    l.debug("Storing " + hex(reg_value) + " inside reg " + reg_name)
                    state.registers.store(reg_name, state.se.BVV(reg_value, state.arch.bits))
                except Exception, e:
                    #l.warning("Can't set register " + reg)
                    pass
                    # TODO need to decide how to handle this

        # Initialize the segment register value if not already initialized
        if not self.segment_registers_already_init:
            l.debug("Synchronizing segments registers")
            if isinstance(state.arch, ArchAMD64):
                if self.project.simos.name == "Linux":
                    state.regs.fs = read_fs_register_linux_x64(self.target)
                elif self.project.simos.name == "Win32":
                    state.regs.gs = read_gs_register_windows_x64(self.target)
            elif isinstance(state.arch, ArchX86):
                if self.project.simos.name == "Linux":
                    # Setup the GDT structure in the angr memory and populate the field containing the gs value
                    # (mandatory for handling access to segment registers)
                    gs = read_gs_register_linux_x86(self.target)
                    setup_gdt(state,0x0,gs)

                    # Synchronize the address of vsyscall in simprocedures dictionary with the concrete value
                    _vsyscall_address = self.target.read_memory(gs + 0x10, self.project.arch.bits / 8)
                    _vsyscall_address = struct.unpack(self.project.arch.struct_fmt(), _vsyscall_address)[0]
                    self.project.rehook_symbol(_vsyscall_address, '_vsyscall')

                elif self.project.simos.name == "Win32":
                    # Setup the GDT structure in the angr memory and populate the field containing the fs value
                    # (mandatory for handling access to segment registers)
                    fs = read_fs_register_windows_x86(self.target)
                    setup_gdt(state, fs,0x0)

                # Avoid flushing the page containing the GDT in this way these addresses will always be read from the angr memory
                gdt_addr = GDT_ADDR
                gdt_size = GDT_LIMIT
                whitelist.append((gdt_addr,gdt_addr+gdt_size))
            self.segment_registers_already_init = True

        # Synchronize the imported functions addresses (.got, IAT) in the concrete process with ones used in the SimProcedures dictionary
        if self.project._should_use_sim_procedures:
            l.info("Restoring SimProc using concrete memory")
            for reloc in self.project.loader.main_object.relocs:
                func_address = self.target.read_memory(reloc.rebased_addr, self.project.arch.bits / 8)
                func_address = struct.unpack(self.project.arch.struct_fmt(), func_address)[0]
                l.debug("Re-hooking SimProc " + reloc.symbol.name + " with address " + hex(func_address))
                self.project.rehook_symbol(func_address, reloc.symbol.name)
        else:
            l.warn("SimProc not restored, you are going to simulate also the code of external libraries!")

        # flush the angr memory in order to synchronize them with the content of the concrete process memory when a read/write to the page is performed
        state.memory.flush_pages(whitelist)
        l.info("Exiting SimEngineConcrete: simulated address %x concrete address %x "%(state.addr, self.target.read_register("pc")))


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



        '''
        if stop_point.reason == "BREAKPOINT_HIT":
            return True
        elif stop_point.reason == "OTHER_REASONS":
            return False
        '''


