
import logging

import archinfo
import cle
import simuvex

from .resolver import IndirectJumpResolver


l = logging.getLogger('resolvers.x86_elf_pic_plt')


class X86ElfPicPltResolver(IndirectJumpResolver):
    """
    In X86 ELF position-independent code, PLT stubs uses ebx to resolve library calls, where ebx stores the address to
    the beginning of the GOT. We resolve the target by forcing ebx to be the beginning of the GOT and simulate the
    execution in fast path mode.
    """

    def __init__(self, arch=archinfo.ArchX86(), project=None):  # pylint:disable=unused-argument
        super(X86ElfPicPltResolver, self).__init__(arch, timeless=True)

        self._got_addr_cache = { }

    def _got_addr(self, obj):

        if obj not in self._got_addr_cache:

            if not isinstance(obj, cle.MetaELF):
                self._got_addr_cache[obj] = None
            else:
                # ALERT: HACKS AHEAD

                got_plt_section = obj.sections_map.get('.got.plt', None)
                got_section = obj.sections_map.get('.got', None)
                if got_plt_section is not None:
                    l.debug('Use address of .got.plt section as the GOT base for object %s.', obj)
                    self._got_addr_cache[obj] = got_plt_section.vaddr + obj.rebase_addr
                elif got_section is not None:
                    l.debug('Use address of .got section as the GOT base for object %s.', obj)
                    self._got_addr_cache[obj] = got_section.vaddr + obj.rebase_addr
                else:
                    l.debug('Cannot find GOT base for object %s.', obj)
                    self._got_addr_cache[obj] = None

        return self._got_addr_cache[obj]

    def filter(self, cfg, addr, func_addr, block):

        section = cfg._addr_belongs_to_section(addr)
        if section.name != '.plt':
            return False

        if block.size != 6:
            return False

        if block.instructions != 1:
            return False

        # TODO: check whether ebx/edx is used

        return True

    def resolve(self, cfg, addr, func_addr, block):

        obj = cfg.project.loader.addr_belongs_to_object(addr)
        if obj is None:
            return False, [ ]

        got_addr = self._got_addr(obj)

        if got_addr is None:
            # cannot get the base address of GOT
            return False, [ ]

        state = cfg._initial_state.copy()
        state.regs.ebx = got_addr

        successors = simuvex.SimEngineVEX().process(state, block, force_addr=addr)

        if len(successors.flat_successors) != 1:
            return False, [ ]

        target = state.se.exactly_int(successors.flat_successors[0].ip)

        return True, [ target ]
