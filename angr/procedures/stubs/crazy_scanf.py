import simuvex

class crazy_scanf(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, src, fmt, one, two, three): #pylint:disable=unused-argument
        memcpy = simuvex.SimProcedures['libc.so.6']['memcpy']

        self.inline_call(memcpy, one, src, 5)
        self.state.memory.store(one+4, self.state.se.BVV(0, 8))
        self.inline_call(memcpy, two, src+6, 8192)
        self.state.memory.store(two+8191, self.state.se.BVV(0, 8))
        self.inline_call(memcpy, three, src+6+8193, 12)
        self.state.memory.store(three+11, self.state.se.BVV(0, 8))

        #if simuvex.o.SYMBOLIC in self.state.options:
        #     #crazy_str = "index.asp?authorization=M3NhZG1pbjoyNzk4ODMwMw==&yan=yes\x00"
        #     #crazy_str = "index.asp?authorization=3sadmin:27988303&yan=yes\x00"
        #     crazy_str = "authorization=3sadmin:27988303\x00"
        #     self.state.add_constraints(self.state.memory.load(two, len(crazy_str)) == self.state.se.BVV(crazy_str))

        return self.state.se.BVV(3)
