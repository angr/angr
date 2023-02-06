import angr


######################################
# __libc_init
#
# Refer to http://androidxref.com/5.1.1_r6/xref/bionic/libc/bionic/libc_init_dynamic.cpp
# and http://androidxref.com/5.1.1_r6/xref/bionic/libc/private/KernelArgumentBlock.h
# raw_args points to argc, *argv, and *envp located on the stack
# unused is always zero
# slingshot points to main()
# structors points to PRE_INIT_ARRAY, INIT_ARRAY, and FINI_ARRAY
######################################
class __libc_init(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument,attribute-defined-outside-init

    ADDS_EXITS = True
    NO_RET = True
    local_vars = ("main", "argc", "argv", "envp")

    def run(self, raw_args, unused, slingshot, structors):
        offset = self.state.arch.bytes
        readlen = self.state.arch.bytes
        endness = self.state.arch.memory_endness
        self.main = slingshot
        self.argc = self.state.memory.load(raw_args + 0 * offset, readlen, endness=endness)
        argc_val = self.state.solver.eval(self.argc)
        self.argv = self.state.memory.load(raw_args + 1 * offset, readlen, endness=endness)
        self.envp = self.state.memory.load(raw_args + (1 + argc_val + 1) * offset, readlen, endness=endness)
        # TODO: __cxa_atexit calls for various at-exit needs
        self.call(
            self.main,
            (self.argc, self.argv, self.envp),
            "after_slingshot",
            prototype="int main(int arch, char **argv, char **envp)",
        )

    def after_slingshot(self, raw_args, unused, slingshot, structors, exit_addr=0):
        self.exit(0)
