import os
from enum import Enum

from cffi import FFI


header_path = os.path.join(os.path.dirname(__file__), 'llvm-c-all.h')
ffi = FFI()
ffi.cdef(open(header_path, 'rb').read())

lib = ffi.dlopen("/usr/lib/llvm-3.8/lib/libLLVM-3.8.so")

class cachedproperty(object):
    def __init__(self, f):
        self.f = f

    def __get__(self, obj, type_=None):
        setattr(obj, self.f.__name__, self.f(obj))
        return getattr(obj, self.f.__name__)


class LLVMType(object):
    # we need a strong ref to the context since there's a reference inside the actual Module class
    def __init__(self, mod, ty):
        self._mod = mod
        self._ty = ty
        self._str = None

    def __repr__(self):
        if self._str is None:
            raw_s = lib.LLVMPrintTypeToString(self._ty)
            self._str = ffi.string(raw_s)
            lib.LLVMDisposeMessage(raw_s)

        return self._str


class LLVMValue(object):
    def __init__(self, mod, val):
        self._mod = mod
        self._val = val


class LLVMOpcode(Enum):
    ret             = 1
    br              = 2
    switch          = 3
    indirect_br     = 4
    invoke          = 5
    unreachable     = 7

    add             = 8
    f_add           = 9
    sub             = 10
    f_sub           = 11
    mul             = 12
    f_mul           = 13
    u_div           = 14
    s_div           = 15
    f_div           = 16
    u_rem           = 17
    s_rem           = 18
    f_rem           = 19

    shl             = 20
    l_shr           = 21
    a_shr           = 22
    and_            = 23
    or_             = 24
    xor             = 25

    alloca          = 26
    load            = 27
    store           = 28
    get_element_ptr = 29

    trunc           = 30
    z_ext           = 31
    s_xt            = 32
    fp_to_ui        = 33
    fp_to_si        = 34
    ui_to_fp        = 35
    si_to_fp        = 36
    fp_trunc        = 37
    fp_ext          = 38
    ptr_to_int      = 39
    int_to_ptr      = 40
    bit_cast        = 41
    addr_space_cast = 60

    i_cmp           = 42
    f_cmp           = 43
    phi             = 44
    call            = 45
    select          = 46
    user_op_1       = 47
    user_op_2       = 48
    va_arg          = 49
    extract_element = 50
    insert_element  = 51
    shuffle_vector  = 52
    extract_value   = 53
    insert_value    = 54

    fence           = 55
    atomic_cmpxchg  = 56
    atomic_rmw      = 57

    resume          = 58
    landing_pad     = 59
    cleanup_ret     = 61
    catch_ret       = 62
    catch_pad       = 63
    cleanup_pad     = 64
    catch_switch    = 65


class LLVMInstruction(object):
    def __init__(self, mod, insn):
        self._mod = mod
        self._insn = insn

    @cachedproperty
    def opcode(self):
        return LLVMOpcode(lib.LLVMGetInstructionOpcode(self._insn))


class LLVMBasicBlock(object):
    def __init__(self, mod, bb):
        self._mod = mod
        self._bb = bb

    def __repr__(self):
        return "<LLVMBasicBlock foo>"

    @cachedproperty
    def instructions(self):
        insns = []
        insn = lib.LLVMGetFirstInstruction(self._bb)
        while insn != ffi.NULL:
            insns.append(LLVMInstruction(self._mod, insn))
            insn = lib.LLVMGetNextInstruction(insn)
        return insns


class LLVMFunction(object):
    # we need a strong ref to the module since there might be a reference inside the actual Value class
    def __init__(self, mod, val):
        self._mod = mod
        self._val = val

    @cachedproperty
    def type(self):
        return LLVMType(self._mod, lib.LLVMTypeOf(self._val))

    @cachedproperty
    def nparams(self):
        return lib.LLVMCountParams(self._val)

    @cachedproperty
    def params(self):
        params_r = ffi.new("LLVMValueRef[%d]" % self.nparams)
        lib.LLVMGetParams(self._val, params_r)
        return [params_r[i] for i in xrange(self.nparams)]

    @cachedproperty
    def nbasic_blocks(self):
        return lib.LLVMCountBasicBlocks(self._val)

    @cachedproperty
    def basic_blocks(self):
        bbs_r = ffi.new("LLVMBasicBlockRef[%d]" % self.nbasic_blocks)
        lib.LLVMGetBasicBlocks(self._val, bbs_r)
        return [LLVMBasicBlock(self._mod,  bbs_r[i]) for i in xrange(self.nbasic_blocks)]


class LLVMModule(object):
    # we need a strong ref to the context since there's a reference inside the actual Module class
    def __init__(self, ctx, mod):
        self._ctx = ctx
        self._mod = mod

        # we'll pretty much always want the functions
        self.functions = []
        cur_func = lib.LLVMGetFirstFunction(self._mod)
        while cur_func != ffi.NULL:
            self.functions.append(LLVMFunction(self, cur_func))
            cur_func = lib.LLVMGetNextFunction(cur_func)

    def __del__(self):
        lib.LLVMDisposeModule(self._mod)

    @property
    def triple(self):
        return ffi.string(lib.LLVMGetTarget(self._mod))

    def dump(self):
        lib.LLVMDumpModule(self._mod)


class LLVMContext(object):
    def __init__(self):
        self._ctx = lib.LLVMContextCreate()

    def __del__(self):
        lib.LLVMContextDispose(self._ctx)

    def parse_ir(self, ir):
        membuf = lib.LLVMCreateMemoryBufferWithMemoryRangeCopy(
            ir,
            len(ir),
            b"ir"
        )
        module = ffi.new("LLVMModuleRef*")
        out_msg = ffi.new("char**")
        failure = lib.LLVMParseIRInContext(self._ctx, membuf, module, out_msg)

        # lib.LLVMDisposeMemoryBuffer(membuf)
        # ^ this segfaults!!! need to look into it

        if failure:
            err = ValueError("invalid IR: " + ffi.string(out_msg[0]))
            lib.LLVMDisposeMessage(out_msg[0])
            raise err

        return LLVMModule(self, module[0])
