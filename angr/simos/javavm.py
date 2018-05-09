
from archinfo.arch_soot import SootAddressTerminator

from ..sim_state import SimState
from .simos import SimOS
from ..engines.soot.values.arrayref import SimSootValue_ArrayRef
from ..engines.soot.values.local import SimSootValue_Local


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
        if kwargs.get('project', None) is None:
            kwargs['project'] = self.project


        state = SimState(self.project, **kwargs)

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

    def state_entry(self, args=None, env=None, argc=None, **kwargs):
        state = self.state_blank(**kwargs)

        # Push the array of command line arguments on the stack if any
        # TODO: deal with command line args in a proper way
        type_ = "String"
        args = [state.se.StringS("args", 1000)]
        # We need to allocate the array on the heap and return the reference
        local = SimSootValue_Local("param_0", type_)
        base_ref = SimSootValue_ArrayRef(0, type_, local, 1)
        for idx, elem in enumerate(args):
            ref = SimSootValue_ArrayRef(idx, type_, local, 1)
            state.memory.store(ref, elem)
        state.memory.store(local, base_ref)

        return state


