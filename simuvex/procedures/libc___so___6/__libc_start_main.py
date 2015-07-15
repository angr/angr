import simuvex

######################################
# __libc_start_main
######################################
class __libc_start_main(simuvex.SimProcedure):
    #pylint:disable=arguments-differ,unused-argument,attribute-defined-outside-init

    ADDS_EXITS = True
    local_vars = ('main', 'argc', 'argv', 'init', 'fini')

    def run(self, main, argc, argv, init, fini):
        # TODO: handle symbolic and static modes
        # TODO: add argument types

        self.main = main
        self.argc = argc
        self.argv = argv
        self.init = init
        self.fini = fini

        if self.state.arch.name == "PPC32":
            # for some dumb reason, PPC passes arguments to libc_start_main in some completely absurd way
            self.argv = argc
            self.argc = main
            self.main = self.state.mem[self.state.regs.r8 + 4:].int.resolved
            self.init = self.state.mem[self.state.regs.r8 + 8:].int.resolved
            self.fini = self.state.mem[self.state.regs.r8 + 12:].int.resolved

        elif self.state.arch.name == "PPC64":
            self.main = self.state.mem[self.state.regs.r8 + 8:].long.resolved
            self.init = self.state.mem[self.state.regs.r8 + 16:].long.resolved
            self.fini = self.state.mem[self.state.regs.r8 + 24:].long.resolved

        # TODO: __cxa_atexit calls for various at-exit needs

        self.call(self.init, (self.argc, self.argv), 'after_init')

    def after_init(self, main, argc, argv, init, fini, exit_addr=0):
        self.call(self.main, (self.argc, self.argv), 'after_main')

    def after_main(self, main, argc, argv, init, fini, exit_addr=0):
        self.inline_call(simuvex.SimProcedures['libc.so.6']['exit'], 0)
