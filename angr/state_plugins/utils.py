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

def convert_to_ast(state, data_e, size_e=None):
    """
    Make an AST out of concrete @data_e
    """
    if type(data_e) is str:
        # Convert the string into a BVV, *regardless of endness*
        bits = len(data_e) * 8
        data_e = state.se.BVV(data_e, bits)
    elif type(data_e) == int:
        data_e = state.se.BVV(data_e, size_e*8 if size_e is not None else state.arch.bits)
    else:
        data_e = data_e.to_bv()

    return data_e
