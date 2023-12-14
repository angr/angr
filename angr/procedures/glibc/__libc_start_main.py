import logging

from cle import AT

import angr

l = logging.getLogger(name=__name__)


class __libc_start_main(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument,attribute-defined-outside-init,missing-class-docstring

    ADDS_EXITS = True
    NO_RET = True
    local_vars = ("main", "argc", "argv", "init", "fini", "initializers")

    def _initialize_b_loc_table(self):
        """
        Initialize ptable for ctype

        See __ctype_b_loc.c in libc implementation
        """
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        table = self.inline_call(malloc, 768).ret_expr
        table_ptr = self.inline_call(malloc, self.state.arch.bytes).ret_expr

        for pos, c in enumerate(self.state.libc.LOCALE_ARRAY):
            # Each entry is 2 bytes
            self.state.memory.store(
                table + (pos * 2),
                self.state.solver.BVV(c, 16),
                inspect=False,
                disable_actions=True,
            )
        # Offset for negative chars
        # 256 because 2 bytes each, -128 * 2
        table += 256
        self.state.memory.store(
            table_ptr,
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
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        # 384 entries, 4 bytes each
        table = self.inline_call(malloc, 384 * 4).ret_expr
        table_ptr = self.inline_call(malloc, self.state.arch.bytes).ret_expr

        for pos, c in enumerate(self.state.libc.TOLOWER_LOC_ARRAY):
            self.state.memory.store(
                table + (pos * 4),
                self.state.solver.BVV(c, 32),
                endness=self.state.arch.memory_endness,
                inspect=False,
                disable_actions=True,
            )

        # Offset for negative chars: -128 index (4 bytes per index)
        table += 128 * 4
        self.state.memory.store(
            table_ptr,
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
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        # 384 entries, 4 bytes each
        table = self.inline_call(malloc, 384 * 4).ret_expr
        table_ptr = self.inline_call(malloc, self.state.arch.bytes).ret_expr

        for pos, c in enumerate(self.state.libc.TOUPPER_LOC_ARRAY):
            self.state.memory.store(
                table + (pos * 4),
                self.state.solver.BVV(c, 32),
                endness=self.state.arch.memory_endness,
                inspect=False,
                disable_actions=True,
            )

        # Offset for negative chars: -128 index (4 bytes per index)
        table += 128 * 4
        self.state.memory.store(
            table_ptr,
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
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        errno_loc = self.inline_call(malloc, self.state.arch.bytes).ret_expr

        self.state.libc.errno_location = errno_loc
        self.state.memory.store(errno_loc, self.state.solver.BVV(0, self.state.arch.bits))

    @property
    def envp(self):
        return self.argv + (self.argc + 1) * self.state.arch.bytes

    def run(self, main, argc, argv, init, fini):
        # TODO: handle symbolic and static modes

        self._initialize_ctype_table()
        self._initialize_errno()

        self.main, self.argc, self.argv, self.init, self.fini = self._extract_args(
            self.state, main, argc, argv, init, fini
        )

        # TODO: __cxa_atexit calls for various at-exit needs

        if not self.state.solver.is_true(self.init == 0):
            self.initializers = None
            self.call(
                self.init,
                (self.argc[31:0], self.argv, self.envp),
                "after_init",
                prototype="int main(int argc, char **argv, char **envp)",
            )
        else:
            obj = self.project.loader.main_object
            init_func = getattr(obj, "_init_func", None)
            init_arr = getattr(obj, "_init_arr", None)
            init_func = [init_func] if init_func else []
            self.initializers = init_func + list(init_arr)
            for i, x in enumerate(self.initializers):
                self.initializers[i] = AT.from_lva(x, obj).to_mva()
            self.inside_init(main, argc, argv, init, fini)

    def inside_init(self, main, argc, argv, init, fini):
        if len(self.initializers) == 0:
            self.after_init(main, argc, argv, init, fini)
        else:
            addr = self.initializers.pop(0)
            self.call(
                addr,
                (self.argc[31:0], self.argv, self.envp),
                "inside_init",
                prototype="int main(int argc, char **argv, char **envp)",
            )

    def after_init(self, main, argc, argv, init, fini, exit_addr=0):
        self.call(
            self.main,
            (self.argc[31:0], self.argv, self.envp),
            "after_main",
            prototype="int main(int argc, char **argv, char **envp)",
        )

    def after_main(self, main, argc, argv, init, fini, exit_addr=0):
        self.exit(0)

    def static_exits(self, blocks, cfg=None, **kwargs):
        # Execute those blocks with a blank state, and then dump the arguments
        blank_state = angr.SimState(
            project=self.project,
            mode="fastpath",
            cle_memory_backer=self.project.loader.memory,
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        # set up the stack pointer
        blank_state.regs.sp = 0x7FFFFFF0

        # special handling for x86 PIE GCC binaries
        #
        # 08049C70 xor     ebp, ebp
        # 08049C72 pop     esi
        # 08049C73 mov     ecx, esp
        # 08049C75 and     esp, 0FFFFFFF0h
        # 08049C78 push    eax
        # 08049C79 push    esp             ; stack_end
        # 08049C7A push    edx             ; rtld_fini
        # 08049C7B call    sub_8049CA3      // this is the get_pc function
        #  // first block starts here
        # 08049C80 add     ebx, (offset off_806B000 - $)
        # 08049C86 lea     eax, (nullsub_2 - 806B000h)[ebx]
        # 08049C8C push    eax             ; fini
        # 08049C8D lea     eax, (sub_805F530 - 806B000h)[ebx]
        # 08049C93 push    eax             ; init
        # 08049C94 push    ecx             ; ubp_av
        # 08049C95 push    esi             ; argc
        # 08049C96 mov     eax, offset main
        # 08049C9C push    eax             ; main
        # 08049C9D call    ___libc_start_main
        if cfg is not None and self.arch.name == "X86":
            first_block = blocks[0]
            first_node = cfg.model.get_any_node(first_block.addr)
            if first_node is not None:
                caller_nodes = cfg.model.get_predecessors(first_node, excluding_fakeret=False)
                if len(caller_nodes) == 1:
                    caller_node = caller_nodes[0]
                    succ_and_jks = caller_node.successors_and_jumpkinds()
                    if len(succ_and_jks) == 1 and succ_and_jks[0][1] == "Ijk_Call":
                        # get_pc
                        getpc_func = cfg.functions.get_by_addr(succ_and_jks[0][0].addr)
                        if getpc_func is not None and "get_pc" in getpc_func.info:
                            # GCC-generated x86-pie binary confirmed.
                            # initialize the specified register with the block address
                            get_pc_reg = getpc_func.info["get_pc"]
                            setattr(blank_state.regs, "_" + get_pc_reg, first_block.addr)

        # Execute each block
        state = blank_state
        for b in blocks:
            irsb = self.project.factory.default_engine.process(state, irsb=b, force_addr=b.addr)
            if irsb.successors:
                state = irsb.successors[0]
            else:
                break

        cc = angr.default_cc(
            self.arch.name, platform=self.project.simos.name if self.project.simos is not None else None
        )(self.arch)
        ty = angr.sim_type.parse_signature("void x(void*, void*, void*, void*, void*)").with_arch(self.arch)
        args = cc.get_args(state, ty)
        main, _, _, init, fini = self._extract_args(blank_state, *args)

        all_exits = [
            {"address": init, "jumpkind": "Ijk_Call", "namehint": "init"},
            {"address": main, "jumpkind": "Ijk_Call", "namehint": "main"},
            {"address": fini, "jumpkind": "Ijk_Call", "namehint": "fini"},
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
            main_ = state.mem[state.regs.r8 + 4 :].int.resolved
            init_ = state.mem[state.regs.r8 + 8 :].int.resolved
            fini_ = state.mem[state.regs.r8 + 12 :].int.resolved

        elif state.arch.name == "PPC64":
            main_ = state.mem[state.regs.r8 + 8 :].long.resolved
            init_ = state.mem[state.regs.r8 + 16 :].long.resolved
            fini_ = state.mem[state.regs.r8 + 24 :].long.resolved

        return main_, argc_, argv_, init_, fini_
