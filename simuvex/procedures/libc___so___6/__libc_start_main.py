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
            self.main = self.state.mem_expr(self.state.regs.r8 + 4, 4, endness=self.state.arch.memory_endness)
            # TODO: Properly set up R2 as well, just as in PPC64

        elif self.state.arch.name == "PPC64":
            self.main = self.state.mem_expr(self.state.regs.r8 + 8, 8, endness=self.state.arch.memory_endness)
            if self.state.libc.ppc64_abiv == 'ppc64_1':
                main_addr_ref = main
                self.main = self.state.mem_expr(main_addr_ref, 8, endness=self.state.arch.memory_endness)
                self.state.regs.r2 = self.state.mem_expr(main_addr_ref + 8, 8, endness=self.state.arch.memory_endness)

        if self.state.arch.name in ("MIPS32", "MIPS64"):
            self.state.regs.t9 = self.init

        # TODO: __cxa_atexit calls for various at-exit needs

        self.call(self.init, (argc, argv), 'after_init')
    def after_init(self, main, argc, argv, init, fini, exit_addr=0):
        if self.state.arch.name in ("MIPS32", "MIPS64"):
            self.state.regs.t9 = self.main
        self.call(self.main, (argc, argv), 'after_main')
    def after_main(self, main, argc, argv, init, fini, exit_addr=0):
        self.inline_call(simuvex.SimProcedures['libc.so.6']['exit'], 0)
