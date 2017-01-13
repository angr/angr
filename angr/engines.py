from simuvex import SimEngine, SimProcedures, SimSuccessors, SimEngineProcedure

# pylint: disable=abstract-method,unused-argument

import logging
l = logging.getLogger('angr.engines')


class SimEngineFailure(SimEngine):
    def __init__(self, project):

        super(SimEngineFailure, self).__init__()

        self.project = project

    def _check(self, state, **kwargs):

        addr = state.se.any_int(state._ip)
        jumpkind = state.scratch.jumpkind

        if jumpkind in ('Ijk_EmFail', 'Ijk_MapFail') or jumpkind.startswith('Ijk_Sig'):
            return True
        if jumpkind == 'Ijk_NoDecode' and not self.project.is_hooked(addr):
            return True
        if jumpkind == 'Ijk_Exit':
            return True
        return False

    def process(self, state, **kwargs):
        addr = state.se.any_int(state._ip)

        if state.scratch.jumpkind in ("Ijk_EmFail", "Ijk_MapFail") or "Ijk_Sig" in state.scratch.jumpkind:
            raise AngrExitError("Cannot execute following jumpkind %s" % state.scratch.jumpkind)

        elif state.scratch.jumpkind == "Ijk_NoDecode" and not self.project.is_hooked(addr):
            raise AngrExitError("IR decoding error at %#x. You can hook this instruction with "
                                "a python replacement using project.hook"
                                "(%#x, your_function, length=length_of_instruction)." % (addr, addr))

        elif state.scratch.jumpkind == 'Ijk_Exit':
            l.debug('Execution terminated at %#x', addr)
            terminator = SimProcedures['stubs']['PathTerminator'](addr, state.arch)
            peng = self.project.factory.procedure_engine
            return peng.process(state, terminator, force_addr=addr)

        else:
            return SimSuccessors.failure()

    #
    # Pickling
    #

    def __setstate__(self, state):
        super(SimEngineFailure, self).__setstate__(state)
        self.project = state['project']

    def __getstate__(self):
        s = super(SimEngineFailure, self).__getstate__()
        s['project'] = self.project
        return s


class SimEngineSyscall(SimEngine):
    def __init__(self, project):
        super(SimEngineSyscall, self).__init__()

        self.project = project

    def _check(self, state, **kwargs):
        if not state.scratch.jumpkind.startswith('Ijk_Sys'):
            return False

        return True

    def process(self, state, **kwargs):
        addr = state.se.any_int(state._ip)

        l.debug("Invoking system call handler")

        # The ip_at_syscall register is misused to save the return address for this syscall
        ret_to = state.regs._ip_at_syscall

        sys_procedure = self.project._simos.handle_syscall(state)
        return self.project.factory.procedure_engine.process(
                state,
                sys_procedure,
                force_addr=addr,
                ret_to=ret_to)

    #
    # Pickling
    #

    def __setstate__(self, state):
        super(SimEngineSyscall, self).__setstate__(state)
        self.project = state['project']

    def __getstate__(self):
        s = super(SimEngineSyscall, self).__getstate__()
        s['project'] = self.project
        return s


class SimEngineHook(SimEngineProcedure):
    def __init__(self, project):
        super(SimEngineHook, self).__init__()

        self.project = project

    def check(self, state,
              procedure=None,
              **kwargs):
        """
        Check if SimEngineHook can handle the current state or not.

        :param simuvex.SimState state: The state to work with.
        :param SimProcedure procedure: An instance of a SimProcedure to run. Optional.
        :param kwargs:                 Other arguments.
        :return:                       True or False.
        :rtype:                        bool
        """

        return super(SimEngineHook, self).check(state, procedure, **kwargs)

    def process(self, state,
            procedure=None,
            ret_to=None,
            inline=None,
            force_addr=None, **kwargs):
        """
        Perform execution with a state.

        :param state:       The state with which to execute
        :param procedure:   An instance of a SimProcedure to run, optional
        :param ret_to:      The address to return to when this procedure is finished
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        return super(SimEngineHook, self).process(state, procedure,
                ret_to=ret_to,
                inline=inline,
                force_addr=force_addr)

    def _check(self, state, procedure=None, **kwargs):
        if state.scratch.jumpkind == 'Ijk_NoHook':
            return False

        if state._ip.symbolic:
            # symbolic IP is not supported
            return False

        addr = state.se.exactly_int(state._ip)

        if procedure is None:
            if addr not in self.project._sim_procedures:
                return False

        return super(SimEngineHook, self)._check(state, procedure, **kwargs)

    def _process(self, state, successors, procedure=None, **kwargs):
        addr = successors.addr
        if state.scratch.jumpkind == 'Ijk_NoHook':
            return

        if procedure is None:
            if addr not in self.project._sim_procedures:
                return
            else:
                procedure = self.project._sim_procedures[addr].instantiate(addr, state.arch)

        l.debug("Running %s (originally at %#x)", repr(procedure), addr)
        return super(SimEngineHook, self)._process(state, successors, procedure, **kwargs)

    #
    # Pickling
    #

    def __setstate__(self, state):
        super(SimEngineHook, self).__setstate__(state)
        self.project = state['project']

    def __getstate__(self):
        s = super(SimEngineHook, self).__getstate__()
        s['project'] = self.project
        return s

from .errors import AngrExitError
