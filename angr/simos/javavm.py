
from archinfo.arch_soot import SootAddressTerminator

from ..sim_state import SimState
from .simos import SimOS


class SimJavaVM(SimOS):
    def __init__(self, *args, **kwargs):
        super(SimJavaVM, self).__init__(*args, name='JavaVM', **kwargs)

    def state_blank(self, addr=None, initial_prefix=None, stack_size=None, **kwargs):
        if kwargs.get('mode', None) is None:
            kwargs['mode'] = self.project._default_analysis_mode
        if kwargs.get('arch', None) is None:
            kwargs['arch'] = self.arch
        if kwargs.get('os_name', None) is None:
            kwargs['os_name'] = self.name

        state = SimState(**kwargs)

        if addr is None: addr = self.project.entry
        state.regs._ip = addr
        state.regs._ip_binary = self.project.loader.main_object  # FIXME: what if the java binary is not the main object?
        state.regs._invoke_return_target = None
        state.regs._invoke_return_variable = None

        # Push the stack frame for the next function we are going to execute
        state.memory.push_stack_frame()

        new_frame = state.callstack.copy()
        new_frame.ret_addr = SootAddressTerminator()
        state.callstack.push(new_frame)

        return state
