from .plugin import SimStatePlugin
from angr.errors import ConcreteRegisterError
import struct
import logging
from archinfo import ArchX86, ArchAMD64

l = logging.getLogger("state_plugin.concrete")
#l.setLevel(logging.DEBUG)


class Concrete(SimStatePlugin):
    def __init__(self, segment_registers_already_init=False, whitelist=[]):
        self.segment_registers_already_init = segment_registers_already_init
        self.whitelist = []
        self.fs_register_bp = None


    def copy(self, _memo):
        print("COPYING FLAG WITH VALUE: " + str(self.segment_registers_already_init))
        conc = Concrete(segment_registers_already_init=self.segment_registers_already_init, whitelist=self.whitelist)
        return conc

    def merge(self):
        pass

    def widen(self):
        pass

    def set_state(self, state):
        SimStatePlugin.set_state(self, state)

    def sync(self):
        """
        Handle the switch between the concrete execution and angr.
        This method takes care of:
        1- Synchronize registers
        2- Set a concrete target to the memory backer so the memory reads are redirected in the concrete process memory.
        3- Flush all the pages loaded until now.

        :return:
        """

        l.debug("Sync the state with the concrete memory inside the Concrete plugin")

        target = self.state.project.concrete_target

        # Setting a concrete memory backend
        self.state.memory.mem._memory_backer.set_concrete_target(target)

        # Sync Angr registers with the one getting from the concrete target
        # registers that we don't want to concretize.
        regs_blacklist = ['fs', 'gs']
        l.info("Synchronizing general purpose registers")

        for reg_key, reg_name in self.state.arch.register_names.items():
            if reg_name not in regs_blacklist:
                try:
                    reg_value = target.read_register(reg_name)
                    setattr(self.state.regs, reg_name, reg_value)
                    l.debug("Register: %s value: %x " % (reg_name,
                                                         self.state.se.eval(getattr(self.state.regs, reg_name),
                                                                            cast_to=int)))
                except ConcreteRegisterError as exc:
                    l.debug("Can't set register %s reason: %s, if this register is not used "
                            "this message can be ignored" % (reg_name, exc))

        # Synchronize the imported functions addresses (.got, IAT) in the
        # concrete process with ones used in the SimProcedures dictionary
        if self.state.project._should_use_sim_procedures and not self.state.project.loader.main_object.pic:
            l.info("Restoring SimProc using concrete memory")
            for reloc in self.state.project.loader.main_object.relocs:
                if reloc.symbol is not None:  # consider only reloc with a symbol
                    l.debug("Trying to re-hook SimProc %s" % reloc.symbol.name)
                    l.debug("reloc.rebased_addr: %s " % hex(reloc.rebased_addr))

                    func_address = target.read_memory(reloc.rebased_addr, self.state.project.arch.bits / 8)
                    func_address = struct.unpack(self.state.project.arch.struct_fmt(), func_address)[0]
                    self.state.project.rehook_symbol(func_address, reloc.symbol.name)
        else:
            l.warn("SimProc not restored, you are going to simulate also the code of external libraries!")

        # flush the angr memory in order to synchronize them with the content of the
        # concrete process memory when a read/write to the page is performed
        self.state.memory.flush_pages(self.whitelist)
        l.info("Exiting SimEngineConcrete: simulated address %x concrete address %x "
               % (self.state.addr, target.read_register("pc")))

        # now we have to register a SimInspect in order to synchronize the segments register
        # on demand when the symbolic execution accesses it
        if not self.segment_registers_already_init:
            self.fs_register_bp = self.state.inspect.b('reg_read', reg_read_offset=self.state.project.simos.get_segment_register_name(),
                                                       action=self.sync_segments)
            print("BP IS " + str(self.fs_register_bp))

            l.debug("Set SimInspect breakpoint to the new state!")


    '''
     Segment registers synchronization is on demand as soon as the 
     symbolic execution access a segment register. 
    '''
    def sync_segments(self, state):
        print(state)
        target = state.project.concrete_target
        print("BEFORE SYNC SEGMENTS FLAG IS " + str(self.segment_registers_already_init))

        # Initialize the segment registers value if not already initialized
        if not self.segment_registers_already_init:
            if isinstance(state.arch, ArchAMD64):
                state.project.simos.initialize_segment_register_x64(state, target)
            elif isinstance(state.arch, ArchX86):
                gdt = state.project.simos.initialize_gdt_x86(state, target)
                self.whitelist.append((gdt.addr, gdt.addr + gdt.limit))

            self.segment_registers_already_init = True
            print("AFTER SYNC SEGMENTS FLAG IS " + str(self.segment_registers_already_init))

            state.inspect.remove_breakpoint('reg_read',bp=self.fs_register_bp)
            self.fs_register_bp = None


from .. import sim_options as options

from angr.sim_state import SimState
SimState.register_default('concrete', Concrete)
