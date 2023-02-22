import logging

import archinfo
import cle

from .resolver import IndirectJumpResolver


l = logging.getLogger(name=__name__)


class X86ElfPicPltResolver(IndirectJumpResolver):
    """
    In X86 ELF position-independent code, PLT stubs uses ebx to resolve library calls, where ebx stores the address to
    the beginning of the GOT. We resolve the target by forcing ebx to be the beginning of the GOT and simulate the
    execution in fast path mode.
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)

        self._got_addr_cache = {}

    def _got_addr(self, obj):
        if obj not in self._got_addr_cache:
            if not isinstance(obj, cle.MetaELF):
                self._got_addr_cache[obj] = None
            else:
                # ALERT: HACKS AHEAD

                got_plt_section = obj.sections_map.get(".got.plt", None)
                got_section = obj.sections_map.get(".got", None)
                if got_plt_section is not None:
                    l.debug("Use address of .got.plt section as the GOT base for object %s.", obj)
                    self._got_addr_cache[obj] = got_plt_section.vaddr
                elif got_section is not None:
                    l.debug("Use address of .got section as the GOT base for object %s.", obj)
                    self._got_addr_cache[obj] = got_section.vaddr
                else:
                    l.debug("Cannot find GOT base for object %s.", obj)
                    self._got_addr_cache[obj] = None

        return self._got_addr_cache[obj]

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if not isinstance(self.project.arch, archinfo.ArchX86):
            return False

        section = self.project.loader.find_section_containing(addr)

        if section is None:
            return False

        if section.name != ".plt":
            return False

        if block.size != 6:
            return False

        if block.instructions != 1:
            return False

        # TODO: check whether ebx/edx is used

        return True

    def resolve(
        self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs
    ):  # pylint:disable=unused-argument
        obj = self.project.loader.find_object_containing(addr)
        if obj is None:
            return False, []

        got_addr = self._got_addr(obj)

        if got_addr is None:
            # cannot get the base address of GOT
            return False, []

        if cfg._initial_state is not None:
            state = cfg._initial_state.copy()
        else:
            state = self.project.factory.blank_state()
        state.regs.ebx = got_addr

        successors = self.project.factory.default_engine.process(state, block, force_addr=addr)

        if len(successors.flat_successors) != 1:
            return False, []

        target = state.solver.eval_one(successors.flat_successors[0].ip)

        return True, [target]
