
import logging

import pyvex
import simuvex

l = logging.getLogger("simuvex.procedures.libc___so___6.__libc_start_main")

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
                                table,
                                size=self.state.arch.bits / 8,
                                endness=self.state.arch.memory_endness
                                )

        self.state.libc.ctype_table_ptr = table_ptr

    @property
    def envp(self):
        return self.argv + (self.argc+1)*self.state.arch.bytes

    def run(self, main, argc, argv, init, fini):
        # TODO: handle symbolic and static modes
        # TODO: add argument types

        self._initialize_ctype_table()

        self.main, self.argc, self.argv, self.init, self.fini = self._extract_args(self.state, main, argc, argv, init,
                                                                                   fini)

        # TODO: __cxa_atexit calls for various at-exit needs

        self.call(self.init, (self.argc, self.argv, self.envp), 'after_init')

    def after_init(self, main, argc, argv, init, fini, exit_addr=0):
        if isinstance(self.state.arch, ArchAMD64):
            # (rsp+8) must be aligned to 16 as required by System V ABI
            # ref: http://www.x86-64.org/documentation/abi.pdf , page 16
            self.state.regs.rsp = (self.state.regs.rsp & 0xfffffffffffffff0) - 8
        self.call(self.main, (self.argc, self.argv, self.envp), 'after_main')

    def after_main(self, main, argc, argv, init, fini, exit_addr=0):
        self.exit(0)

    @classmethod
    def static_exits(cls, arch, blocks):
        # Execute those blocks with a blank state, and then dump the arguments
        blank_state = simuvex.SimState(arch=arch, mode="fastpath")

        # Execute each block
        state = blank_state
        for b in blocks:
            # state.regs.ip = next(iter(stmt for stmt in b.statements if isinstance(stmt, pyvex.IRStmt.IMark))).addr
            irsb = simuvex.SimIRSB(state, b,
                        addr=next(iter(stmt for stmt in b.statements if isinstance(stmt, pyvex.IRStmt.IMark))).addr)
            if irsb.successors:
                state = irsb.successors[0]
            else:
                break

        cc = simuvex.DefaultCC[arch.name](arch)
        args = [ cc.arg(state, _) for _ in xrange(5) ]
        main, _, _, init, fini = cls._extract_args(blank_state, *args)

        all_exits = [
            (init, 'Ijk_Call'),
            (main, 'Ijk_Call'),
            (fini, 'Ijk_Call'),
        ]

        return all_exits

    @staticmethod
    def _extract_args(state, main, argc, argv, init, fini):
        """
        Extract arguments and set them to

        :param simuvex.s_state.SimState state: The program state.
        :param main: An argument to __libc_start_main.
        :param argc: An argument to __libc_start_main.
        :param argv: An argument to __libc_start_main.
        :param init: An argument to __libc_start_main.
        :param fini: An argument to __libc_start_main.
        :return: A tuple of five elements: (main, argc, argv, init, fini)
        :rtype: tuple
        """

        main_ = main
        argc_ = argc
        argv_ = argv
        init_ = init
        fini_ = fini

        if state.arch.name == "PPC32":
            # for some dumb reason, PPC passes arguments to libc_start_main in some completely absurd way
            argv_ = argc_
            argc_ = main_
            main_ = state.mem[state.regs.r8 + 4:].int.resolved
            init_ = state.mem[state.regs.r8 + 8:].int.resolved
            fini_ = state.mem[state.regs.r8 + 12:].int.resolved

        elif state.arch.name == "PPC64":
            main_ = state.mem[state.regs.r8 + 8:].long.resolved
            init_ = state.mem[state.regs.r8 + 16:].long.resolved
            fini_ = state.mem[state.regs.r8 + 24:].long.resolved

        return main_, argc_, argv_, init_, fini_

from archinfo import ArchAMD64
