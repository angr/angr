import angr
from angr.errors import SimValueError


class __tls_get_addr(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, ptr):
        module_id, offset = self.state.mem[ptr].uintptr_t.array(2).resolved
        if module_id.symbolic:
            raise SimValueError("__tls_get_addr called with symbolic module ID")
        module_id = self.state.solver.eval(module_id)

        # TODO: this should manually load values from the dtv
        return self.project.loader.tls.threads[0].get_addr(module_id, offset)


# this is a rare and highly valuable TRIPLE-UNDERSCORE tls_get_addr. weird calling convention.
class ___tls_get_addr(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        if self.state.arch.name == 'X86':
            ptr = self.state.regs.eax
            # use SIM_PROCEDURES so name-mangling doesn't fuck us :|
            return self.inline_call(angr.SIM_PROCEDURES['linux_loader']['__tls_get_addr'], ptr).ret_expr
        else:
            raise angr.errors.SimUnsupportedError("___tls_get_addr only implemented for x86. Talk to @rhelmot.")
