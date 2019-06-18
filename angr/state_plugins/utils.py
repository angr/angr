import angr
import claripy


def get_unconstrained_bytes(state, name, bits, source=None, memory=None):

    if (memory is not None and memory.category == 'mem' and
                angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY in state.options):
        # CGC binaries zero-fill the memory for any allocated region
        # Reference: (https://github.com/CyberGrandChallenge/libcgc/blob/master/allocate.md)
        return state.se.BVV(0x0, bits)

    return state.se.Unconstrained(name, bits)

def get_obj_byte(obj, offset):

    # BVV slicing is extremely slow...
    if obj.op == 'BVV':
        assert type(obj.args[0]) == int
        value = obj.args[0]
        return claripy.BVV(value >> 8 * (len(obj) // 8 - 1 - offset) & 0xFF, 8)

    # slice the object using angr
    left = len(obj) - (offset * 8) - 1
    right = left - 8 + 1
    return obj[left:right]

def resolve_size_range(memory, size):
    if not memory.state.solver.symbolic(size):
        i = memory.state.solver.eval(size)
        if i > memory._maximum_concrete_size:
            raise SimMemoryLimitError("Concrete size %d outside of allowable limits" % i)
        return i, i

    if options.APPROXIMATE_MEMORY_SIZES in memory.state.options:
        max_size_approx = memory.state.solver.max_int(size, exact=True)
        min_size_approx = memory.state.solver.min_int(size, exact=True)

        if max_size_approx < memory._maximum_symbolic_size_approx:
            return min_size_approx, max_size_approx

    max_size = memory.state.solver.max_int(size)
    min_size = memory.state.solver.min_int(size)

    if min_size > memory._maximum_symbolic_size:
        memory.state.history.add_event('memory_limit', message="Symbolic size %d outside of allowable limits" % min_size, size=size)
        if options.BEST_EFFORT_MEMORY_STORING not in memory.state.options:
            raise SimMemoryLimitError("Symbolic size %d outside of allowable limits" % min_size)
        else:
            min_size = memory._maximum_symbolic_size

    return min_size, min(max_size, memory._maximum_symbolic_size)

from .. import sim_options as options
from ..errors import SimMemoryLimitError