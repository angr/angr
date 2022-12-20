# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("faultrep.dll")
prototypes = \
    {
        #
        'ReportFault': SimTypeFunction([SimTypePointer(SimStruct({"ExceptionRecord": SimTypePointer(SimStruct({"ExceptionCode": SimTypeInt(signed=True, label="Int32"), "ExceptionFlags": SimTypeInt(signed=False, label="UInt32"), "ExceptionRecord": SimTypePointer(SimTypeBottom(label="EXCEPTION_RECORD"), offset=0), "ExceptionAddress": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "NumberParameters": SimTypeInt(signed=False, label="UInt32"), "ExceptionInformation": SimTypeFixedSizeArray(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), 15)}, name="EXCEPTION_RECORD", pack=False, align=None), offset=0), "ContextRecord": SimTypePointer(SimStruct({"P1Home": SimTypeLongLong(signed=False, label="UInt64"), "P2Home": SimTypeLongLong(signed=False, label="UInt64"), "P3Home": SimTypeLongLong(signed=False, label="UInt64"), "P4Home": SimTypeLongLong(signed=False, label="UInt64"), "P5Home": SimTypeLongLong(signed=False, label="UInt64"), "P6Home": SimTypeLongLong(signed=False, label="UInt64"), "ContextFlags": SimTypeInt(signed=False, label="UInt32"), "MxCsr": SimTypeInt(signed=False, label="UInt32"), "SegCs": SimTypeShort(signed=False, label="UInt16"), "SegDs": SimTypeShort(signed=False, label="UInt16"), "SegEs": SimTypeShort(signed=False, label="UInt16"), "SegFs": SimTypeShort(signed=False, label="UInt16"), "SegGs": SimTypeShort(signed=False, label="UInt16"), "SegSs": SimTypeShort(signed=False, label="UInt16"), "EFlags": SimTypeInt(signed=False, label="UInt32"), "Dr0": SimTypeLongLong(signed=False, label="UInt64"), "Dr1": SimTypeLongLong(signed=False, label="UInt64"), "Dr2": SimTypeLongLong(signed=False, label="UInt64"), "Dr3": SimTypeLongLong(signed=False, label="UInt64"), "Dr6": SimTypeLongLong(signed=False, label="UInt64"), "Dr7": SimTypeLongLong(signed=False, label="UInt64"), "Rax": SimTypeLongLong(signed=False, label="UInt64"), "Rcx": SimTypeLongLong(signed=False, label="UInt64"), "Rdx": SimTypeLongLong(signed=False, label="UInt64"), "Rbx": SimTypeLongLong(signed=False, label="UInt64"), "Rsp": SimTypeLongLong(signed=False, label="UInt64"), "Rbp": SimTypeLongLong(signed=False, label="UInt64"), "Rsi": SimTypeLongLong(signed=False, label="UInt64"), "Rdi": SimTypeLongLong(signed=False, label="UInt64"), "R8": SimTypeLongLong(signed=False, label="UInt64"), "R9": SimTypeLongLong(signed=False, label="UInt64"), "R10": SimTypeLongLong(signed=False, label="UInt64"), "R11": SimTypeLongLong(signed=False, label="UInt64"), "R12": SimTypeLongLong(signed=False, label="UInt64"), "R13": SimTypeLongLong(signed=False, label="UInt64"), "R14": SimTypeLongLong(signed=False, label="UInt64"), "R15": SimTypeLongLong(signed=False, label="UInt64"), "Rip": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimUnion({"FltSave": SimTypeBottom(label="XSAVE_FORMAT"), "Anonymous": SimStruct({"Header": SimTypeFixedSizeArray(SimTypeBottom(label="M128A"), 2), "Legacy": SimTypeFixedSizeArray(SimTypeBottom(label="M128A"), 8), "Xmm0": SimTypeBottom(label="M128A"), "Xmm1": SimTypeBottom(label="M128A"), "Xmm2": SimTypeBottom(label="M128A"), "Xmm3": SimTypeBottom(label="M128A"), "Xmm4": SimTypeBottom(label="M128A"), "Xmm5": SimTypeBottom(label="M128A"), "Xmm6": SimTypeBottom(label="M128A"), "Xmm7": SimTypeBottom(label="M128A"), "Xmm8": SimTypeBottom(label="M128A"), "Xmm9": SimTypeBottom(label="M128A"), "Xmm10": SimTypeBottom(label="M128A"), "Xmm11": SimTypeBottom(label="M128A"), "Xmm12": SimTypeBottom(label="M128A"), "Xmm13": SimTypeBottom(label="M128A"), "Xmm14": SimTypeBottom(label="M128A"), "Xmm15": SimTypeBottom(label="M128A")}, name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), "VectorRegister": SimTypeFixedSizeArray(SimTypeBottom(label="M128A"), 26), "VectorControl": SimTypeLongLong(signed=False, label="UInt64"), "DebugControl": SimTypeLongLong(signed=False, label="UInt64"), "LastBranchToRip": SimTypeLongLong(signed=False, label="UInt64"), "LastBranchFromRip": SimTypeLongLong(signed=False, label="UInt64"), "LastExceptionToRip": SimTypeLongLong(signed=False, label="UInt64"), "LastExceptionFromRip": SimTypeLongLong(signed=False, label="UInt64")}, name="CONTEXT", pack=False, align=None), offset=0)}, name="EXCEPTION_POINTERS", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="EFaultRepRetVal"), arg_names=["pep", "dwOpt"]),
        #
        'AddERExcludedApplicationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szApplication"]),
        #
        'AddERExcludedApplicationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wszApplication"]),
        #
        'WerReportHang': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndHungApp", "pwzHungApplicationName"]),
    }

lib.set_prototypes(prototypes)
