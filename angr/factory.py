from simuvex import SimIRSB, SimProcedures, SimState, BP_BEFORE, BP_AFTER
from simuvex import s_options as o

import logging
l = logging.getLogger('angr.factory')

class AngrObjectFactory(object):
    def __init__(self, project):
        self._project = project
        self._lifter = Lifter(project)
        self.analyses = Analyses(project, {})  # The second argument should go away when we merge
        self.surveyors = Surveyors(project)
        self.block = self._lifter.lift

    def sim_block(self, state, max_size=None, num_inst=None,
                  stmt_whitelist=None, last_stmt=None, addr=None):
        """
         Returns a SimIRSB object with execution based on state

         Optional params:
         @param max_size         the maximum size of the block, in bytes
         @param num_inst         the maximum number of instructions
         @param stmt_whitelist   a list of stmt indexes to which to confine execution
         @param last_stmt        a statement index at which to stop execution
         @param addr             the address at which to start the block
        """
        if addr is None:
            addr = state.se.any_int(state.regs.ip)

        thumb = False
        if addr % state.arch.instruction_alignment != 0:
            if state.thumb:
                thumb = True
            else:
                raise AngrExitError("Address 0x%x does not align to alignment %d "
                                    "for architecture %s." % (addr,
                                    state.arch.instruction_alignment,
                                    state.arch.name))

        opt_level = 1 if o.OPTIMIZE_IR in state.options else 0
        backup_state = state if self._project._support_selfmodifying_code else None

        irsb = self.block(addr, max_size, num_inst, thumb=thumb, backup_state=backup_state, opt_level=opt_level)
        return SimIRSB(state, irsb, addr=addr, whitelist=stmt_whitelist, last_stmt=last_stmt)

    def sim_run(self, state, jumpkind="Ijk_Boring", **block_opts):
        """
        Returns a simuvex SimRun object (supporting refs() and
        exits()), automatically choosing whether to create a SimIRSB or
        a SimProcedure.

        Parameters:
        @param state        the state to analyze
        @param jumpkind     the jumpkind of the previous exit

        Additional keyword arguments will be passed directly into factory.sim_block
        if appropriate.
        """

        addr = state.se.any_int(state.regs.ip)

        if jumpkind.startswith("Ijk_Sys"):
            l.debug("Invoking system call handler (originally at 0x%x)", addr)
            return SimProcedures['syscalls']['handler'](state, addr=addr, ret_to=state.ip)

        if jumpkind in ("Ijk_EmFail", "Ijk_NoDecode", "Ijk_MapFail") or "Ijk_Sig" in jumpkind:
            raise AngrExitError("Cannot create run following jumpkind %s" % jumpkind)

        elif self._project.is_hooked(addr) and jumpkind != 'Ijk_NoHook':
            sim_proc_class, kwargs = self._project._sim_procedures[addr]
            l.debug("Creating SimProcedure %s (originally at 0x%x)",
                    sim_proc_class.__name__, addr)
            state._inspect('call', BP_BEFORE, function_name=sim_proc_class.__name__)
            r = sim_proc_class(state, addr=addr, sim_kwargs=kwargs)
            state._inspect('call', BP_AFTER, function_name=sim_proc_class.__name__)
            l.debug("... %s created", r)

        else:
            l.debug("Creating SimIRSB at 0x%x", addr)
            r = self.sim_block(state, addr=addr, **block_opts)

        return r

    def blank_state(self, **kwargs):
        return self._project._simos.state_blank(**kwargs)

    def entry_state(self, **kwargs):
        return self._project._simos.state_entry(**kwargs)

    def full_init_state(self, **kwargs):
        return self._project._simos.state_full_init(**kwargs)

    def path(self, state=None):
        if state is None:
            state = self.entry_state()

        return Path(self._project, state, jumpkind=state.scratch.jumpkind)

    def path_group(self, thing=None, **kwargs):
        if thing is None:
            thing = [self.path()]

        if isinstance(thing, (list, tuple)):
            thing = list(thing)
            for i, val in enumerate(thing):
                if isinstance(thing, SimState):
                    thing[i] = self.path(val)
                elif not isinstance(thing, Path):
                    raise AngrError("Bad type to initialize path group: %s" % repr(val))
        elif isinstance(thing, Path):
            thing = [thing]
        elif isinstance(thing, SimState):
            thing = [self.path(thing)]
        else:
            raise AngrError("BadType to initialze path group: %s" % repr(thing))

        return PathGroup(self._project, active_paths=thing, **kwargs)


from .analysis import Analyses
from .surveyor import Surveyors
from .lifter import Lifter
from .errors import AngrExitError, AngrError
from .path import Path
from .path_group import PathGroup
