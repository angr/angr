from .plugin import SimStatePlugin
from angr.errors import ConcreteRegisterError
from angr_targets.segment_registers import *
import struct
import logging
from archinfo import ArchX86, ArchAMD64

l = logging.getLogger("state_plugin.concrete")
# l.setLevel(logging.DEBUG)


class Concrete(SimStatePlugin):
    def __init__(self, segment_registers_already_init=False):
        self.segment_registers_already_init = segment_registers_already_init

    def copy(self, _memo):
        conc = Concrete(segment_registers_already_init=True)
        return conc

    def merge(self):
        pass

    def widen(self):
        pass

    def set_state(self, state):
        SimStatePlugin.set_state(self, state)

    def sync(self):
        """
        Handling the switch between the concrete execution and angr.
        This method takes care of:
        1- Synchronize registers
        2- Substitute the CLEMemory backer of the self.state with a ConcreteCLEMemory object
           that redirects the read inside the concrete process.
        3- Flush all the pages loaded until now.

        :return:
        """

        l.debug("Sync the state with the concrete memory inside the Concrete plugin")

        self.target = self.state.project.concrete_target
        whitelist = []

        # Setting a concrete memory backend
        self.state.memory.mem._memory_backer.set_concrete_target(self.target)

        # Sync Angr registers with the one getting from the concrete target
        # registers that we don't want to concretize.
        regs_blacklist = ['fs', 'gs']
        l.info("Synchronizing general purpose registers")

        for reg_key, reg_name in self.state.arch.register_names.items():
            if reg_name not in regs_blacklist:
                try:
                    reg_value = self.target.read_register(reg_name)
                    setattr(self.state.regs, reg_name, reg_value)
                    l.debug("Register: %s value: %x " % (reg_name,
                                                         self.state.se.eval(getattr(self.state.regs, reg_name),
                                                                            cast_to=int)))
                except ConcreteRegisterError as exc:
                    l.debug("Can't set register %s reason: %s, if this register is not used "
                            "this message can be ignored" % (reg_name, exc))
                    
        # Initialize the segment register value if not already initialized
        if not self.segment_registers_already_init:
            l.debug("Synchronizing segments registers")
            if isinstance(self.state.arch, ArchAMD64):
                if self.state.project.simos.name == "Linux":
                    self.state.regs.fs = read_fs_register_linux_x64(self.target)
                elif self.state.project.simos.name == "Win32":
                    self.state.regs.gs = read_gs_register_windows_x64(self.target)
            elif isinstance(self.state.arch, ArchX86):
                if self.state.project.simos.name == "Linux":
                    # Setup the GDT structure in the angr memory and populate the field containing the gs value
                    # (mandatory for handling access to segment registers)
                    gs = read_gs_register_linux_x86(self.target)
                    setup_gdt(self.state, 0x0, gs)

                    # Synchronize the address of vsyscall in simprocedures dictionary with the concrete value
                    _vsyscall_address = self.target.read_memory(gs + 0x10, self.state.project.arch.bits / 8)
                    _vsyscall_address = struct.unpack(self.state.project.arch.struct_fmt(), _vsyscall_address)[0]
                    self.state.project.rehook_symbol(_vsyscall_address, '_vsyscall')

                elif self.state.project.simos.name == "Win32":
                    # Setup the GDT structure in the angr memory and populate the field containing the fs value
                    # (mandatory for handling access to segment registers)
                    fs = read_fs_register_windows_x86(self.target)
                    setup_gdt(self.state, fs, 0x0)

                # Avoid flushing the page containing the GDT in this way these addresses will always be read from the angr memory
                gdt_addr = GDT_ADDR
                gdt_size = GDT_LIMIT
                whitelist.append((gdt_addr, gdt_addr+gdt_size))
            self.segment_registers_already_init = True

        # Synchronize the imported functions addresses (.got, IAT) in the
        # concrete process with ones used in the SimProcedures dictionary

        # if self.state.project._should_use_sim_procedures and not self.state.project.loader.main_object.pic:
        if self.state.project._should_use_sim_procedures:
            l.info("Restoring SimProc using concrete memory")
            for reloc in self.state.project.loader.main_object.relocs:
                if reloc.symbol is not None:  # consider only reloc with a symbol
                    l.debug("Trying to re-hook SimProc %s" % reloc.symbol.name)
                    l.debug("reloc.rebased_addr: %s " % hex(reloc.rebased_addr))

                    func_address = self.target.read_memory(reloc.rebased_addr, self.state.project.arch.bits / 8)
                    func_address = struct.unpack(self.state.project.arch.struct_fmt(), func_address)[0]
                    self.state.project.rehook_symbol(func_address, reloc.symbol.name)
        else:
            l.warn("SimProc not restored, you are going to simulate also the code of external libraries!")

        # flush the angr memory in order to synchronize them with the content of the
        # concrete process memory when a read/write to the page is performed
        self.state.memory.flush_pages(whitelist)
        l.info("Exiting SimEngineConcrete: simulated address %x concrete address %x "
               % (self.state.addr, self.target.read_register("pc")))


from .. import sim_options as options

from angr.sim_state import SimState
SimState.register_default('concrete', Concrete)
