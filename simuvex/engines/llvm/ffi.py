import os
from enum import Enum, IntEnum

from cffi import FFI


header_path = os.path.join(os.path.dirname(__file__), 'llvm-c-all.h')
ffi = FFI()
ffi.cdef(open(header_path, 'rb').read())

lib = ffi.dlopen("/usr/lib/llvm-3.8/lib/libLLVM-3.8.so")

class _object2(object):
    pass

class cachedproperty(object):
    def __init__(self, f):
        self.f = f

    def __get__(self, obj, type_=None):
        val = self.f(obj)
        setattr(obj, self.f.__name__, val)
        return val

    def __set__(self, obj, value):
        setattr(obj, self.f.__name__, value)


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

class AutoNumberIntEnum(IntEnum):
    def __new__(cls):
        value = len(cls.__members__) + 1
        obj = int.__new__(cls)
        obj._value_ = value
        return obj


class LLVMValueKind(AutoNumberIntEnum):
    Argument = ()
    BasicBlock = ()
    MemoryUse = ()
    MemoryDef = ()
    MemoryPhi = ()

    Function = ()
    GlobalAlias = ()
    GlobalIFunc = ()
    GlobalVariable = ()
    BlockAddress = ()
    ConstantExpr = ()
    ConstantArray = ()
    ConstantStruct = ()
    ConstantVector = ()

    UndefValue = ()
    ConstantAggregateZero = ()
    ConstantDataArray = ()
    ConstantDataVector = ()
    ConstantInt = ()
    ConstantFP = ()
    ConstantPointerNull = ()
    ConstantTokenNone = ()

    MetadataAsValue = ()
    InlineAsm = ()

    Instruction = ()


# TODO: investigate using a cache for all LLVMValue's, a la claripy ASTs
class LLVMValue(object):
    def __init__(self, mod, val):
        self._mod = mod
        self._val = val

    # for __hash__ and __eq__, purposefully ignore the class and other
    # attributes -- if mod and val are the same, they must be the same objects,
    # at least in LLVM land
    def __hash__(self):
        return hash((self._mod, self._val))

    def __eq__(self, other):
        return self._mod == other._mod and self._val == other._val

    @cachedproperty
    def type(self):
        return LLVMType(self._mod, lib.LLVMTypeOf(self._val))

    @cachedproperty
    def name(self):
        name_r = lib.LLVMGetValueName(self._val)
        if name_r == ffi.NULL:
            return None
        else:
            return ffi.string(name_r)

    def __repr__(self):
        return '<LLVMValue %s%s>' % (self.type, " " + self.name if self.name else "")


class LLVMConstantInt(LLVMValue):
    def __init__(self, mod, val):
        super(LLVMConstantInt, self).__init__(mod, val)

    @cachedproperty
    def value(self):
        return lib.LLVMConstIntGetZExtValue(self._val)

    def __repr__(self):
        return '<LLVMConstantInt %s %d>' % (self.type, self.value)

def _create_value(mod, val):
    if lib.LLVMIsAConstantInt(val) != ffi.NULL:
        return LLVMConstantInt(mod, val)
    elif lib.LLVMIsAInstruction(val) != ffi.NULL:
        return LLVMInstruction(mod, val)
    else:
        return LLVMValue(mod, val)


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


class LLVMInstruction(LLVMValue):
    def __init__(self, mod, bb, insn):
        super(LLVMInstruction, self).__init__(mod, insn)
        if bb is not None:
            self._bb = bb

    @cachedproperty
    def _bb(self):
        return LLVMBasicBlock(self._mod, lib.LLVMGetInstructionParent(self._val))

    @cachedproperty
    def opcode(self):
        return LLVMOpcode(lib.LLVMGetInstructionOpcode(self._val))

    @cachedproperty
    def operands(self):
        return [_create_value(self._mod, lib.LLVMGetOperand(self._val, i)) for i in xrange(lib.LLVMGetNumOperands(self._val))]

    def __repr__(self):
        return '<LLVMInstruction %s(%s)>' % (self.opcode._name_,
                                             ', '.join(str(op) for op in self.operands))

    def _operand_to_str(self, op):
        id_ = self._mod.tracker.lookup_local(self._bb._func, op)
        if id_ is not None:
            return str(id_)
        else:
            return str(op)

    def ir_str(self):
        # somewhat close to the string you'd see in the IR
        out = ""

        id_ = self._mod.tracker.lookup_local(self._bb._func, self)
        if id_ is not None:
            out += "%s = " % id_

        out += self.opcode._name_

        out += '('
        out += ', '.join(self._operand_to_str(op) for op in self.operands)
        out += ')'

        return out


class LLVMBasicBlock(LLVMValue):
    def __init__(self, mod, func, bb):
        super(LLVMBasicBlock, self).__init__(mod, lib.LLVMBasicBlockAsValue(bb))
        self._bb = bb
        self._func = func

    def __repr__(self):
        return "<LLVMBasicBlock foo>"

    @cachedproperty
    def instructions(self):
        insns = []
        insn = lib.LLVMGetFirstInstruction(self._bb)
        while insn != ffi.NULL:
            insns.append(LLVMInstruction(self._mod, self, insn))
            insn = lib.LLVMGetNextInstruction(insn)
        return insns


class LLVMFunction(LLVMValue):
    # we need a strong ref to the module since there might be a reference inside the actual Value class
    def __init__(self, mod, val):
        super(LLVMFunction, self).__init__(mod, val)

    @cachedproperty
    def nparams(self):
        return lib.LLVMCountParams(self._val)

    @cachedproperty
    def params(self):
        params_r = ffi.new("LLVMValueRef[%d]" % self.nparams)
        lib.LLVMGetParams(self._val, params_r)
        return [LLVMValue(self, params_r[i]) for i in xrange(self.nparams)]

    @cachedproperty
    def nbasic_blocks(self):
        return lib.LLVMCountBasicBlocks(self._val)

    @cachedproperty
    def basic_blocks(self):
        bbs_r = ffi.new("LLVMBasicBlockRef[%d]" % self.nbasic_blocks)
        lib.LLVMGetBasicBlocks(self._val, bbs_r)
        return [LLVMBasicBlock(self._mod, self, bbs_r[i]) for i in xrange(self.nbasic_blocks)]


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

    @cachedproperty
    def tracker(self):
        return ValueIDTracker(self)


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

# from .slots import ValueIDTracker
from slots import ValueIDTracker
