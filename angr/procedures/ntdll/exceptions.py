from __future__ import annotations
import claripy

import angr


class KiUserExceptionDispatcher(angr.SimProcedure):
    local_vars = ("tib_ptr", "top_record", "cur_ptr")
    IS_FUNCTION = False

    tib_ptr = None
    top_record = None
    cur_ptr = None

    def run(self, record, context):
        if self.state.arch.name != "X86":
            raise angr.errors.SimUnsupportedError("KiUserDispatchException is only implemented for X86")

        self.tib_ptr = self.state.regs._fs.concat(claripy.BVV(0, 16))
        self.top_record = self.state.mem[self.tib_ptr].uint32_t.resolved
        self.cur_ptr = self.top_record

        # set magic value to detect nested exceptions
        self.state.mem[self.tib_ptr].long = 0xBADFACE

        self.dispatch(record, context)

    def dispatch(self, record, context):
        if self.call_ret_expr is not None:
            try:
                disposition = self.state.solver.eval_one(self.call_ret_expr)
            except angr.errors.SimSolverError as err:
                raise angr.errors.SimError(f"Exception handler returned symbolic value {self.call_ret_expr}") from err
            if disposition == 0:  # Handled!!!
                self.project.simos._load_regs(self.state, context)
                # TODO: re-set the exception handler somehow?
                # self.state.mem[self.tib_ptr].uint32_t
                self.jump(self.state.regs._ip)
                return
            if disposition == 1:  # unhandled, continue search
                pass
            elif disposition == 2:
                raise angr.errors.SimUnsupportedError("Exception disposition ExceptionNestedException is unsupported")
            elif disposition == 3:
                raise angr.errors.SimUnsupportedError("Exception disposition ExceptionCollidedUnwind is unsupported")
            else:
                raise angr.errors.SimError("Bad exception disposition %d" % disposition)

        # todo: check cur_ptr against stack bounds
        cur_ptr = self.cur_ptr
        if self.state.solver.is_true(cur_ptr == -1):
            raise angr.errors.SimError("Unhandled exception - exhausted all exception handlers")
        next_ptr = self.state.mem[self.cur_ptr].uint32_t.resolved
        func_ptr = self.state.mem[self.cur_ptr + 4].uint32_t.resolved

        self.cur_ptr = next_ptr
        # as far as I can tell it doesn't actually matter whether the callback is stdcall or cdecl
        self.call(func_ptr, (record, cur_ptr, context, 0xBADF00D), "dispatch", prototype="void x(int, int, int, int)")
        # bonus! after we've done the call, mutate the state even harder so ebp is pointing to some fake args
        self.successors.successors[0].regs.ebp = self.successors.successors[0].regs.esp - 4
