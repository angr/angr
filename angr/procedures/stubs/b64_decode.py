import angr

class b64_decode(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, src, dst, length):
        strncpy = angr.SIM_PROCEDURES['libc']['strncpy']

        cpy = self.inline_call(strncpy, dst, src, length)
        self.state.memory.store(dst+16, self.state.solver.BVV(0, 8))
        return cpy.ret_expr
#
#         if length.is_symbolic():
#             raise Exception("SYMBOLIC LENGTH WTF")
#
#         ln = length.solver.any()
#         full_str = self.state.memory.load(src, ln)
#
#         for i in range(ln//4):
#             part = se.Extract(ln*8 - i*4*8 - 1, ln*8 - (i+1)*4*8, full_str)
#
#
#
#
#
#         memcpy = angr.SIM_PROCEDURES['libc']['memcpy']
#
#         fmt = self.get_arg_expr(1) #pylint:disable=unused-variable
#         one = self.get_arg_expr(2)
#         two = self.get_arg_expr(3)
#         three = self.get_arg_expr(4)
#
#         self.inline_call(memcpy, one, src, 5)
#         self.state.memory.store(one+4, self.state.solver.BVV(0, 8))
#         self.inline_call(memcpy, two, src+6, 8192)
#         self.state.memory.store(two+8191, self.state.solver.BVV(0, 8))
#         self.inline_call(memcpy, three, src+6+8193, 12)
#         self.state.memory.store(three+11, self.state.solver.BVV(0, 8))
#
#         if angr.o.SYMBOLIC in self.state.options:
#             crazy_str = "index.asp?authorization=M3NhZG1pbjoyNzk4ODMwMw==&yan=yes\x00"
#             self.state.add_constraints(self.state.memory.load(two, len(crazy_str)) == self.state.solver.BVV(crazy_str))
#
#         self.exit_return(self.state.solver.BVV(3))
