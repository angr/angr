import angr
from ..posix.read import read
from ..posix.write import write
from ...sim_type import register_types, parse_types

register_types(
    parse_types(
        """
struct iovec {
    void  *iov_base;    /* Starting address */
    size_t iov_len;     /* Number of bytes to transfer */
};
"""
    )
)


class readv(angr.SimProcedure):
    def run(self, fd, iovec, iovcnt):
        if iovec.symbolic or iovcnt.symbolic:
            raise angr.errors.SimPosixError("Can't handle symbolic arguments to readv")
        iovcnt = self.state.solver.eval(iovcnt)
        res = 0
        for element in self.state.mem[iovec].struct.iovec.array(iovcnt).resolved:
            tmpres = self.inline_call(read, fd, element.iov_base, element.iov_len).ret_expr
            if self.state.solver.is_true(self.state.solver.SLT(tmpres, 0)):
                return tmpres

        return res


class writev(angr.SimProcedure):
    def run(self, fd, iovec, iovcnt):
        if iovec.symbolic or iovcnt.symbolic:
            raise angr.errors.SimPosixError("Can't handle symbolic arguments to writev")
        iovcnt = self.state.solver.eval(iovcnt)
        res = 0
        for element in self.state.mem[iovec].struct.iovec.array(iovcnt).resolved:
            tmpres = self.inline_call(write, fd, element.iov_base, element.iov_len).ret_expr
            if self.state.solver.is_true(self.state.solver.SLT(tmpres, 0)):
                return tmpres

        return res
