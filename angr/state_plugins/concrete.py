
import cle
import io
import logging
import os
import re
import struct

from .plugin import SimStatePlugin
from ..errors import SimConcreteRegisterError
from archinfo import ArchX86, ArchAMD64

l = logging.getLogger("state_plugin.concrete")
#l.setLevel(logging.DEBUG)


class Concrete(SimStatePlugin):
    def __init__(self, segment_registers_initialized=False, segment_registers_callback_initialized=False,
                 whitelist=None, fs_register_bp=None, already_sync_objects_addresses=None,
                 ):

        super().__init__()

        self.segment_registers_initialized = segment_registers_initialized
        self.segment_registers_callback_initialized = segment_registers_callback_initialized

        if not whitelist:
            self.whitelist = []
        else:
            self.whitelist = whitelist

        self.synchronize_cle = False
        self.stubs_on_sync = False

        self.fs_register_bp = fs_register_bp

        if not already_sync_objects_addresses:
            self.already_sync_objects_addresses = []
        else:
            self.already_sync_objects_addresses = already_sync_objects_addresses

    def copy(self, _memo):
        conc = Concrete(segment_registers_initialized=self.segment_registers_initialized,
                        segment_registers_callback_initialized=self.segment_registers_callback_initialized,
                        whitelist=list(self.whitelist),
                        fs_register_bp=self.fs_register_bp,
                        already_sync_objects_addresses=list(self.already_sync_objects_addresses)
                        )
        return conc

    def merge(self, _others, _merge_conditions, _common_ancestor=None):
        pass

    def widen(self, _others):
        pass

    def set_state(self, state):
        SimStatePlugin.set_state(self, state)

    def sync(self):
        """
        Handle the switch between the concrete execution and angr.
        This method takes care of:
        1- Synchronize registers.
        2- Set a concrete target to the memory backer so the memory reads are redirected in the concrete process memory.
        3- If possible restore the SimProcedures with the real addresses inside the concrete process.
        4- Set an inspect point to sync the segments register as soon as they are read during the symbolic execution.
        5- Flush all the pages loaded until now.

        :return:
        """

        def _sync_segments(state):
            """
            Segment registers synchronization is on demand as soon as the
            symbolic execution access a segment register.
            """
            concr_target = state.project.concrete_target

            if isinstance(state.arch, ArchAMD64):
                state.project.simos.initialize_segment_register_x64(state, concr_target)
            elif isinstance(state.arch, ArchX86):
                gdt = state.project.simos.initialize_gdt_x86(state, concr_target)
                state.concrete.whitelist.append((gdt.addr, gdt.addr + gdt.limit))

            state.inspect.remove_breakpoint('reg_read', bp=state.concrete.fs_register_bp)
            state.concrete.segment_registers_initialized = True

            state.concrete.fs_register_bp = None

        l.debug("Sync the state with the concrete memory inside the Concrete plugin")

        # Configure plugin with state options
        if options.SYMBION_SYNC_CLE in self.state.options:
            self.synchronize_cle = True
        if options.SYMBION_KEEP_STUBS_ON_SYNC in self.state.options:
            self.stubs_on_sync = True

        target = self.state.project.concrete_target

        # Sync angr registers with the one getting from the concrete target
        # registers that we don't want to concretize.
        l.debug("Synchronizing general purpose registers")

        to_sync_register = list(filter(lambda x: x.concrete, self.state.arch.register_list))

        for register in to_sync_register:

            # before let's sync all the subregisters of the current register.
            # sometimes this can be helpful ( i.e. ymmm0 e xmm0 )
            if register.subregisters:
                subregisters_names = map(lambda x: x[0], register.subregisters)
                self._sync_registers(subregisters_names, target)

            # finally let's synchronize the whole register
            self._sync_registers([register.name], target)

        if self.synchronize_cle:
            self._sync_cle(target)

        # Synchronize the imported functions addresses (.got, IAT) in the
        # concrete process with ones used in the SimProcedures dictionary
        if self.state.project.use_sim_procedures and not self.state.project.loader.main_object.pic:
            self._sync_simproc()
        else:
            l.debug("SimProc not restored, you are going to simulate also the code of external libraries!")

        # flush the angr memory in order to synchronize them with the content of the
        # concrete process memory when a read/write to the page is performed
        self.state.memory.flush_pages(self.whitelist)
        l.info("Exiting SimEngineConcrete: simulated address %x concrete address %x ", self.state.addr,
               target.read_register("pc"))

        # now we have to register a SimInspect in order to synchronize the segments register
        # on demand when the symbolic execution accesses it
        if self.state.project.arch.name in ['X86', 'AMD64'] and not self.segment_registers_callback_initialized:
            segment_register_name = self.state.project.simos.get_segment_register_name()
            if segment_register_name:
                self.fs_register_bp = self.state.inspect.b('reg_read',
                                                           reg_read_offset=segment_register_name,
                                                           action=_sync_segments)

                self.segment_registers_callback_initialized = True

                l.debug("Set SimInspect breakpoint to the new state!")
            else:
                l.error("Can't set breakpoint to synchronize segments registers, horrible things will happen.")

    def _sync_registers(self, register_names, target):
        for register_name in register_names:
            try:
                reg_value = target.read_register(register_name)
                setattr(self.state.regs, register_name, reg_value)
                l.debug("Register: %s value: %x ", register_name, self.state.solver.eval(getattr(self.state.regs,
                                                                                                 register_name),
                                                                                         cast_to=int))
            except SimConcreteRegisterError as exc:
                l.debug("Can't set register %s reason: %s, if this register is not used "
                        "this message can be ignored", register_name, exc)

    def _sync_cle(self, target):

        def _check_mapping_name(cle_mapping_name, concrete_mapping_name):
            if cle_mapping_name == concrete_mapping_name:
                return True
            else:
                # removing version and extension information from the library name
                cle_mapping_name = re.findall(r"[\w']+", cle_mapping_name)
                concrete_mapping_name = re.findall(r"[\w']+", concrete_mapping_name)
                return cle_mapping_name[0] == concrete_mapping_name[0]

        l.debug("Synchronizing CLE backend with the concrete process memory mapping")
        try:
            vmmap = target.get_mappings()
        except NotImplementedError:
            l.critical("Can't synchronize CLE backend using the ConcreteTarget provided.")
            self.synchronize_cle = False  # so, deactivate this feature
            l.debug("CLE synchronization has been deactivated")
            return

        for mapped_object in self.state.project.loader.all_elf_objects:
            binary_name = os.path.basename(mapped_object.binary)

            # this object has already been sync, skip it.
            if binary_name in self.already_sync_objects_addresses:
                continue

            for mmap in vmmap:
                if _check_mapping_name(binary_name, mmap.name):
                    l.debug("Match! %s -> %s", mmap.name, binary_name)

                    # let's make sure that we have the header at this address to confirm that it is the
                    # base address.
                    # That's not a perfect solution, but should work most of the time.
                    result = target.read_memory(mmap.start_address, 0x10)

                    if self.state.project.loader.main_object.check_magic_compatibility(io.BytesIO(result)):
                        if mapped_object.mapped_base == mmap.start_address:
                            # We already have the correct address for this memory mapping
                            l.debug("Object %s is already rebased correctly at 0x%x", binary_name,
                                    mapped_object.mapped_base)
                            self.already_sync_objects_addresses.append(mmap.name)

                            break  # object has been synchronized, move to the next one!

                        # rebase the object if the CLE address doesn't match the real one,
                        # this can happen with PIE binaries and libraries.
                        l.debug("Remapping object %s mapped at address 0x%x at address 0x%x", binary_name,
                                mapped_object.mapped_base, mmap.start_address)

                        old_mapped_base = mapped_object.mapped_base
                        mapped_object.mapped_base = mmap.start_address  # Rebase now!

                        # TODO re-write this horrible thing
                        mapped_object.sections._rebase(abs(mmap.start_address - old_mapped_base))  # fix sections
                        mapped_object.segments._rebase(abs(mmap.start_address - old_mapped_base))  # fix segments

                        self.already_sync_objects_addresses.append(mmap.name)
                        break  # object has been synchronized, move to the next one!

    def _sync_simproc(self):

        l.debug("Restoring SimProc using concrete memory")

        for reloc in self.state.project.loader.main_object.relocs:
            if reloc.symbol:  # consider only reloc with a symbol
                l.debug("Trying to re-hook SimProc %s", reloc.symbol.name)
                # l.debug("reloc.rebased_addr: %#x " % reloc.rebased_addr)

                if self.state.project.simos.name == 'Win32':
                    func_address = self.state.project.concrete_target.read_memory(reloc.rebased_addr, self.state.arch.bytes)
                    func_address = struct.unpack(self.state.project.arch.struct_fmt(), func_address)[0]
                elif self.state.project.simos.name == 'Linux':
                    try:
                        func_address = self.state.project.loader.main_object.plt[reloc.symbol.name]
                    except KeyError:
                        continue
                else:
                    l.info("Can't synchronize simproc, binary format not supported.")
                    return

                l.debug("Function address hook is now: %#x ", func_address)
                self.state.project.rehook_symbol(func_address, reloc.symbol.name, self.stubs_on_sync)

                if self.synchronize_cle and not self.state.project.loader.main_object.contains_addr(func_address):
                    old_func_symbol = self.state.project.loader.find_symbol(reloc.symbol.name)

                    if old_func_symbol:  # if we actually have a symbol
                        owner_obj = old_func_symbol.owner

                        # calculating the new real address
                        new_relative_address = func_address - owner_obj.mapped_base

                        new_func_symbol = cle.backends.Symbol(owner_obj, old_func_symbol.name, new_relative_address,
                                                              old_func_symbol.size, old_func_symbol.type)

                        for new_reloc in self.state.project.loader.find_relevant_relocations(old_func_symbol.name):
                            if new_reloc.symbol.name == new_func_symbol.name and \
                                    new_reloc.value != new_func_symbol.rebased_addr:
                                l.debug("Updating CLE symbols metadata, moving %s from 0x%x to 0x%x",
                                        new_reloc.symbol.name,
                                        new_reloc.value,
                                        new_func_symbol.rebased_addr)

                                new_reloc.resolve(new_func_symbol)
                                new_reloc.relocate([])


from ..sim_state import SimState
from .. import sim_options as options
SimState.register_default('concrete', Concrete)
