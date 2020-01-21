import angr
import claripy
import logging

l = logging.getLogger(name=__name__)

class LinuxLoader(angr.SimProcedure):
    NO_RET = True

    # pylint: disable=unused-argument,arguments-differ,attribute-defined-outside-init
    local_vars = ('initializers',)
    def run(self):
        self.initializers = self.project.loader.initializers
        self.run_initializer()

    def run_initializer(self):
        if len(self.initializers) == 0:
            self.project.simos.set_entry_register_values(self.state)
            self.jump(self.project.entry)
        else:
            addr = self.initializers[0]
            self.initializers = self.initializers[1:]
            self.call(addr, (self.state.posix.argc, self.state.posix.argv, self.state.posix.environ), 'run_initializer')

class IFuncResolver(angr.SimProcedure):
    NO_RET = True
    local_vars = ('saved_regs',)

    # pylint: disable=arguments-differ,unused-argument
    def run(self, funcaddr=None, gotaddr=None, funcname=None):
        self.saved_regs = {reg.name: self.state.registers.load(reg.name) for reg in self.arch.register_list if reg.argument}
        self.call(funcaddr, (), continue_at='after_call')

    def after_call(self, funcaddr=None, gotaddr=None, funcname=None):
        value = self.cc.return_val.get_value(self.state)
        for name, val in self.saved_regs.items():
            self.state.registers.store(name, val)

        self.state.memory.store(gotaddr, value, endness=self.state.arch.memory_endness)
        self.jump(value)

    def __repr__(self):
        return '<IFuncResolver %s>' % self.kwargs.get('funcname', None)
