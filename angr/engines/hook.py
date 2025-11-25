from __future__ import annotations
import logging

import claripy
import cle
from archinfo.arch_soot import SootAddressDescriptor

import angr
from .successors import SuccessorsEngine
from .procedure import ProcedureMixin

l = logging.getLogger(name=__name__)


# pylint: disable=abstract-method,unused-argument,arguments-differ
class HooksMixin(SuccessorsEngine, ProcedureMixin):
    """
    A SimEngine mixin which adds a SimSuccessors handler which will look into the project's hooks and run the hook at
    the current address.

    Will respond to the following parameters provided to the step stack:

    - procedure:        A SimProcedure instance to force-run instead of consulting the current hooks
    - ret_to:           An address to force-return-to at the end of the procedure
    """

    def _lookup_hook(self, state, procedure):
        # TODO this is moderately controversial. If the jumpkind was NoHook and the user provided the procedure
        # argument, which takes precedence?
        # tentative guess: passed argument takes priority
        if procedure is not None:
            return procedure

        # we have at this point entered the next step - we should check the "previous" jumpkind
        if state.history and state.history.parent and state.history.parent.jumpkind == "Ijk_NoHook":
            return None

        if isinstance(state._ip, claripy.ast.BV) and state._ip.symbolic:
            # symbolic IP is not supported
            return None
        addr = state.addr
        if isinstance(addr, tuple):
            addr = addr[0]
        if not isinstance(addr, int):
            return None

        procedure = self._get_proc_at_addr(state, addr)
        if procedure is not None:
            return procedure

        if not state.arch.name.startswith("ARM") or addr & 1 != 1:
            return None

        procedure = self._get_proc_at_addr(state, addr - 1)
        if procedure is not None:
            return procedure

        return None

    def _get_proc_at_addr(self, state, addr) -> angr.SimProcedure | None:
        procedure = self.project._sim_procedures.get(addr, None)
        if procedure is not None:
            return procedure
        if angr.options.RUN_HOOKS_AT_PLT in state.options:
            obj = self.project.loader.find_object_containing(addr)
            if obj is not None and isinstance(obj, cle.ELF) and addr in obj.reverse_plt:
                proc_name = obj.reverse_plt[addr]
                real_sym = self.project.loader.find_symbol(proc_name)
                assert real_sym is not None

                procedure = self.project._sim_procedures.get(real_sym.rebased_addr, None)
                if procedure is not None:
                    return procedure

        return None

    def process_successors(self, successors, *, procedure=None, **kwargs):
        state = self.state
        if procedure is None:
            procedure = self._lookup_hook(state, procedure)
        if procedure is None:
            return super().process_successors(successors, **kwargs)

        if isinstance(procedure.addr, SootAddressDescriptor):
            l.debug("Running %s (originally at %r)", repr(procedure), procedure.addr)
        else:
            l.debug(
                "Running %s (originally at %s)",
                repr(procedure),
                procedure.addr if procedure.addr is None else hex(procedure.addr),
            )

        return self.process_procedure(state, successors, procedure, **kwargs)
