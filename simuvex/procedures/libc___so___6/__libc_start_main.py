import simuvex

######################################
# __libc_start_main
######################################
class __libc_start_main(simuvex.SimProcedure):
    #pylint:disable=arguments-differ,unused-argument,attribute-defined-outside-init

    ADDS_EXITS = True
    NO_RET = True
    local_vars = ('main', 'argc', 'argv', 'init', 'fini')

    def _initialize_ctype_table(self):
        """
        Initialize ptable for ctype

        See __ctype_b_loc.c in libc implementation
        """
        malloc = simuvex.SimProcedures['libc.so.6']['malloc']
        table = self.inline_call(malloc, 384).ret_expr
        table_ptr = self.inline_call(malloc, self.state.arch.bits / 8).ret_expr

        for pos, c in enumerate(self.state.libc.LOCALE_ARRAY):
            self.state.memory.store(table + pos, self.state.se.BVV(c, 8))
        self.state.memory.store(table_ptr,
                                table + 128,
                                size=self.state.arch.bits / 8,
                                endness=self.state.arch.memory_endness
                                )

        self.state.libc.ctype_table_ptr = table_ptr

    def run(self, main, argc, argv, init, fini):
        # TODO: handle symbolic and static modes
        # TODO: add argument types

        self._initialize_ctype_table()

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
        if isinstance(self.state.arch, ArchAMD64):
            # (rsp+8) must be aligned to 16 as required by System V ABI
            # ref: http://www.x86-64.org/documentation/abi.pdf , page 16
            self.state.regs.rsp = (self.state.regs.rsp & 0xfffffffffffffff0) - 8
        self.call(self.main, (self.argc, self.argv), 'after_main')

    def after_main(self, main, argc, argv, init, fini, exit_addr=0):
        self.inline_call(simuvex.SimProcedures['libc.so.6']['exit'], 0)

from archinfo import ArchAMD64
