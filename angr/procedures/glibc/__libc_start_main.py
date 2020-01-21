
import logging

import pyvex
import angr

l = logging.getLogger(name=__name__)

######################################
# __libc_start_main
######################################
class __libc_start_main(angr.SimProcedure):
    #pylint:disable=arguments-differ,unused-argument,attribute-defined-outside-init

    ADDS_EXITS = True
    NO_RET = True
    local_vars = ('main', 'argc', 'argv', 'init', 'fini')

    def _initialize_b_loc_table(self):
        """
        Initialize ptable for ctype

        See __ctype_b_loc.c in libc implementation
        """
        malloc = angr.SIM_PROCEDURES['libc']['malloc']
        table = self.inline_call(malloc, 768).ret_expr
        table_ptr = self.inline_call(malloc, self.state.arch.bytes).ret_expr

        for pos, c in enumerate(self.state.libc.LOCALE_ARRAY):
            # Each entry is 2 bytes
            self.state.memory.store(table + (pos*2),
                                    self.state.solver.BVV(c, 16),
                                    inspect=False,
                                    disable_actions=True,
                                    )
        # Offset for negative chars
        # 256 because 2 bytes each, -128 * 2
        table += 256
        self.state.memory.store(table_ptr,
                                table,
                                size=self.state.arch.bytes,
                                endness=self.state.arch.memory_endness,
                                inspect=False,
                                disable_actions=True,
                                )

        self.state.libc.ctype_b_loc_table_ptr = table_ptr

    def _initialize_tolower_loc_table(self):
        """
        Initialize ptable for ctype

        See __ctype_tolower_loc.c in libc implementation
        """
        malloc = angr.SIM_PROCEDURES['libc']['malloc']
        # 384 entries, 4 bytes each
        table = self.inline_call(malloc, 384*4).ret_expr
        table_ptr = self.inline_call(malloc, self.state.arch.bytes).ret_expr

        for pos, c in enumerate(self.state.libc.TOLOWER_LOC_ARRAY):
            self.state.memory.store(table + (pos * 4),
                                    self.state.solver.BVV(c, 32),
                                    endness=self.state.arch.memory_endness,
                                    inspect=False,
                                    disable_actions=True,
                                    )

        # Offset for negative chars: -128 index (4 bytes per index)
        table += (128 * 4)
        self.state.memory.store(table_ptr,
                                table,
                                size=self.state.arch.bytes,
                                endness=self.state.arch.memory_endness,
                                inspect=False,
                                disable_actions=True,
                                )

        self.state.libc.ctype_tolower_loc_table_ptr = table_ptr

    def _initialize_toupper_loc_table(self):
        """
        Initialize ptable for ctype

        See __ctype_toupper_loc.c in libc implementation
        """
        malloc = angr.SIM_PROCEDURES['libc']['malloc']
        # 384 entries, 4 bytes each
        table = self.inline_call(malloc, 384*4).ret_expr
        table_ptr = self.inline_call(malloc, self.state.arch.bytes).ret_expr

        for pos, c in enumerate(self.state.libc.TOUPPER_LOC_ARRAY):
            self.state.memory.store(table + (pos * 4),
                                    self.state.solver.BVV(c, 32),
                                    endness=self.state.arch.memory_endness,
                                    inspect=False,
                                    disable_actions=True,
                                    )

        # Offset for negative chars: -128 index (4 bytes per index)
        table += (128 * 4)
        self.state.memory.store(table_ptr,
                                table,
                                size=self.state.arch.bytes,
                                endness=self.state.arch.memory_endness,
                                inspect=False,
                                disable_actions=True,
                                )

        self.state.libc.ctype_toupper_loc_table_ptr = table_ptr

    def _initialize_ctype_table(self):
        self._initialize_b_loc_table()
        self._initialize_tolower_loc_table()
        self._initialize_toupper_loc_table()

    def _initialize_errno(self):
        malloc = angr.SIM_PROCEDURES['libc']['malloc']
        errno_loc = self.inline_call(malloc, self.state.arch.bytes).ret_expr

        self.state.libc.errno_location = errno_loc
        self.state.memory.store(errno_loc, self.state.solver.BVV(0, self.state.arch.bits))

    @property
    def envp(self):
        return self.argv + (self.argc+1)*self.state.arch.bytes

    def run(self, main, argc, argv, init, fini):
        # TODO: handle symbolic and static modes
        # TODO: add argument types

        self._initialize_ctype_table()
        self._initialize_errno()

        self.main, self.argc, self.argv, self.init, self.fini = self._extract_args(self.state, main, argc, argv, init,
                                                                                   fini)

        # TODO: __cxa_atexit calls for various at-exit needs

        self.call(self.init, (self.argc, self.argv, self.envp), 'after_init')

    def after_init(self, main, argc, argv, init, fini, exit_addr=0):
        self.call(self.main, (self.argc, self.argv, self.envp), 'after_main')

    def after_main(self, main, argc, argv, init, fini, exit_addr=0):
        self.exit(0)

    def static_exits(self, blocks):
        # Execute those blocks with a blank state, and then dump the arguments
        blank_state = angr.SimState(project=self.project, mode="fastpath", memory_backer=self.project.loader.memory,
                                    add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY})
        # set up the stack pointer
        blank_state.regs.sp = 0x7ffffff0

        # Execute each block
        state = blank_state
        for b in blocks:
            # state.regs.ip = next(iter(stmt for stmt in b.statements if isinstance(stmt, pyvex.IRStmt.IMark))).addr
            irsb = self.project.factory.default_engine.process(state, b,
                    force_addr=next(iter(stmt for stmt in b.statements if isinstance(stmt, pyvex.IRStmt.IMark))).addr)
            if irsb.successors:
                state = irsb.successors[0]
            else:
                break

        cc = angr.DEFAULT_CC[self.arch.name](self.arch)
        args = [ cc.arg(state, _) for _ in range(5) ]
        main, _, _, init, fini = self._extract_args(blank_state, *args)

        all_exits = [
            {'address': init, 'jumpkind': 'Ijk_Call', 'namehint': 'init'},
            {'address': main, 'jumpkind': 'Ijk_Call', 'namehint': 'main'},
            {'address': fini, 'jumpkind': 'Ijk_Call', 'namehint': 'fini'},
        ]

        return all_exits

    @staticmethod
    def _extract_args(state, main, argc, argv, init, fini):
        """
        Extract arguments and set them to

        :param angr.sim_state.SimState state: The program state.
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
