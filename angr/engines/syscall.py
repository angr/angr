import angr
import logging

l = logging.getLogger(name=__name__)

from .engine import SuccessorsMixin
from .procedure import ProcedureMixin


# pylint:disable=abstract-method,arguments-differ
class SimEngineSyscall(SuccessorsMixin, ProcedureMixin):
    """
    A SimEngine mixin which adds a successors handling step that checks if a syscall was just requested and if so
    handles it as a step.
    """

    def process_successors(self, successors, **kwargs):
        state = self.state
        # we have at this point entered the next step so we need to check the previous jumpkind
        if (
            not state.history
            or not state.history.parent
            or not state.history.parent.jumpkind
            or not state.history.parent.jumpkind.startswith("Ijk_Sys")
        ):
            return super().process_successors(successors, **kwargs)

        l.debug("Invoking system call handler")
        sys_procedure = self.project.simos.syscall(state)

        if sys_procedure is None:
            if angr.sim_options.BYPASS_UNSUPPORTED_SYSCALL not in state.options:
                raise AngrUnsupportedSyscallError(
                    "Trying to perform a syscall on an emulated system which is not currently cofigured to support "
                    "syscalls. To resolve this, make sure that your SimOS is a subclass of SimUserspace, or set the "
                    "BYPASS_UNSUPPORTED_SYSCALL state option."
                )
            else:
                try:
                    cc = angr.SYSCALL_CC[state.arch.name][state.os_name](state.arch)
                except KeyError:
                    try:
                        l.warning("No syscall calling convention available for %s/%s", state.arch.name, state.os_name)
                        cc = angr.SYSCALL_CC[state.arch.name]["default"](state.arch)
                    except KeyError:
                        cc = None  # some default will get picked down the line...

                sys_procedure = angr.SIM_PROCEDURES["stubs"]["syscall"](cc=cc)

        return self.process_procedure(state, successors, sys_procedure, **kwargs)


from ..errors import AngrUnsupportedSyscallError
