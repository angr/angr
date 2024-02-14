# pylint:disable=line-too-long
import logging
from collections import OrderedDict

from ...sim_type import (SimTypeFunction,
    SimTypeShort,
    SimTypeInt,
    SimTypeLong,
    SimTypeLongLong,
    SimTypeDouble,
    SimTypeFloat,
    SimTypePointer,
    SimTypeChar,
    SimStruct,
    SimTypeArray,
    SimTypeBottom,
    SimUnion,
    SimTypeBool,
    SimTypeRef,
)
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.type_collection_names = ["win32"]
lib.set_default_cc("X86", SimCCStdcall)
lib.set_default_cc("AMD64", SimCCMicrosoftAMD64)
lib.set_library_names("oleaut32.dll")
prototypes = \
    {
        #
        'SysAllocString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["psz"]),
        #
        'SysReAllocString': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbstr", "psz"]),
        #
        'SysAllocStringLen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["strIn", "ui"]),
        #
        'SysReAllocStringLen': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pbstr", "psz", "len"]),
        #
        'SysAddRefString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bstrString"]),
        #
        'SysReleaseString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["bstrString"]),
        #
        'SysFreeString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["bstrString"]),
        #
        'SysStringLen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbstr"]),
        #
        'SysStringByteLen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["bstr"]),
        #
        'SysAllocStringByteLen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["psz", "len"]),
        #
        'SetErrorInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IErrorInfo")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwReserved", "perrinfo"]),
        #
        'GetErrorInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IErrorInfo"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwReserved", "pperrinfo"]),
        #
        'BSTR_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'BSTR_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'BSTR_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'BSTR_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'BSTR_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'BSTR_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'BSTR_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'BSTR_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'LPSAFEARRAY_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'LPSAFEARRAY_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'LPSAFEARRAY_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'LPSAFEARRAY_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'LPSAFEARRAY_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'LPSAFEARRAY_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'LPSAFEARRAY_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'LPSAFEARRAY_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'SafeArrayAllocDescriptor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cDims", "ppsaOut"]),
        #
        'SafeArrayAllocDescriptorEx': SimTypeFunction([SimTypeInt(signed=False, label="VARENUM"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vt", "cDims", "ppsaOut"]),
        #
        'SafeArrayAllocData': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa"]),
        #
        'SafeArrayCreate': SimTypeFunction([SimTypeInt(signed=False, label="VARENUM"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SAFEARRAYBOUND", SimStruct), offset=0)], SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), arg_names=["vt", "cDims", "rgsabound"]),
        #
        'SafeArrayCreateEx': SimTypeFunction([SimTypeInt(signed=False, label="VARENUM"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SAFEARRAYBOUND", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), arg_names=["vt", "cDims", "rgsabound", "pvExtra"]),
        #
        'SafeArrayCopyData': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psaSource", "psaTarget"]),
        #
        'SafeArrayReleaseDescriptor': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["psa"]),
        #
        'SafeArrayDestroyDescriptor': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa"]),
        #
        'SafeArrayReleaseData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pData"]),
        #
        'SafeArrayDestroyData': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa"]),
        #
        'SafeArrayAddRef': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "ppDataToRelease"]),
        #
        'SafeArrayDestroy': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa"]),
        #
        'SafeArrayRedim': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypeRef("SAFEARRAYBOUND", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "psaboundNew"]),
        #
        'SafeArrayGetDim': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["psa"]),
        #
        'SafeArrayGetElemsize': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["psa"]),
        #
        'SafeArrayGetUBound': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "nDim", "plUbound"]),
        #
        'SafeArrayGetLBound': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "nDim", "plLbound"]),
        #
        'SafeArrayLock': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa"]),
        #
        'SafeArrayUnlock': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa"]),
        #
        'SafeArrayAccessData': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "ppvData"]),
        #
        'SafeArrayUnaccessData': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa"]),
        #
        'SafeArrayGetElement': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "rgIndices", "pv"]),
        #
        'SafeArrayPutElement': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "rgIndices", "pv"]),
        #
        'SafeArrayCopy': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "ppsaOut"]),
        #
        'SafeArrayPtrOfIndex': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "rgIndices", "ppvData"]),
        #
        'SafeArraySetRecordInfo': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypeBottom(label="IRecordInfo")], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "prinfo"]),
        #
        'SafeArrayGetRecordInfo': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IRecordInfo"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "prinfo"]),
        #
        'SafeArraySetIID': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "guid"]),
        #
        'SafeArrayGetIID': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "pguid"]),
        #
        'SafeArrayGetVartype': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="VARENUM"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "pvt"]),
        #
        'SafeArrayCreateVector': SimTypeFunction([SimTypeInt(signed=False, label="VARENUM"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), arg_names=["vt", "lLbound", "cElements"]),
        #
        'SafeArrayCreateVectorEx': SimTypeFunction([SimTypeInt(signed=False, label="VARENUM"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), arg_names=["vt", "lLbound", "cElements", "pvExtra"]),
        #
        'VectorFromBstr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bstr", "ppsa"]),
        #
        'BstrFromVector': SimTypeFunction([SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psa", "pbstr"]),
        #
        'VarUI1FromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sIn", "pbOut"]),
        #
        'VarUI1FromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "pbOut"]),
        #
        'VarUI1FromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "pbOut"]),
        #
        'VarUI1FromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "pbOut"]),
        #
        'VarUI1FromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "pbOut"]),
        #
        'VarUI1FromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pbOut"]),
        #
        'VarUI1FromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "pbOut"]),
        #
        'VarUI1FromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pbOut"]),
        #
        'VarUI1FromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pbOut"]),
        #
        'VarUI1FromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "pbOut"]),
        #
        'VarUI1FromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "pbOut"]),
        #
        'VarUI1FromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pbOut"]),
        #
        'VarUI1FromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "pbOut"]),
        #
        'VarUI1FromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "pbOut"]),
        #
        'VarUI1FromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pbOut"]),
        #
        'VarI2FromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "psOut"]),
        #
        'VarI2FromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "psOut"]),
        #
        'VarI2FromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "psOut"]),
        #
        'VarI2FromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "psOut"]),
        #
        'VarI2FromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "psOut"]),
        #
        'VarI2FromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "psOut"]),
        #
        'VarI2FromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "psOut"]),
        #
        'VarI2FromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "psOut"]),
        #
        'VarI2FromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "psOut"]),
        #
        'VarI2FromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "psOut"]),
        #
        'VarI2FromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "psOut"]),
        #
        'VarI2FromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "psOut"]),
        #
        'VarI2FromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "psOut"]),
        #
        'VarI2FromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "psOut"]),
        #
        'VarI2FromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "psOut"]),
        #
        'VarI4FromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "plOut"]),
        #
        'VarI4FromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sIn", "plOut"]),
        #
        'VarI4FromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "plOut"]),
        #
        'VarI4FromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "plOut"]),
        #
        'VarI4FromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "plOut"]),
        #
        'VarI4FromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "plOut"]),
        #
        'VarI4FromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "plOut"]),
        #
        'VarI4FromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "plOut"]),
        #
        'VarI4FromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "plOut"]),
        #
        'VarI4FromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "plOut"]),
        #
        'VarI4FromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "plOut"]),
        #
        'VarI4FromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "plOut"]),
        #
        'VarI4FromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "plOut"]),
        #
        'VarI4FromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "plOut"]),
        #
        'VarI4FromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "plOut"]),
        #
        'VarI8FromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "pi64Out"]),
        #
        'VarI8FromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sIn", "pi64Out"]),
        #
        'VarI8FromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "pi64Out"]),
        #
        'VarI8FromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "pi64Out"]),
        #
        'VarI8FromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pi64Out"]),
        #
        'VarI8FromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "pi64Out"]),
        #
        'VarI8FromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pi64Out"]),
        #
        'VarI8FromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pi64Out"]),
        #
        'VarI8FromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "pi64Out"]),
        #
        'VarI8FromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "pi64Out"]),
        #
        'VarI8FromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pi64Out"]),
        #
        'VarI8FromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "pi64Out"]),
        #
        'VarI8FromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "pi64Out"]),
        #
        'VarI8FromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pi64Out"]),
        #
        'VarR4FromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "pfltOut"]),
        #
        'VarR4FromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sIn", "pfltOut"]),
        #
        'VarR4FromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "pfltOut"]),
        #
        'VarR4FromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "pfltOut"]),
        #
        'VarR4FromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "pfltOut"]),
        #
        'VarR4FromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pfltOut"]),
        #
        'VarR4FromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "pfltOut"]),
        #
        'VarR4FromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pfltOut"]),
        #
        'VarR4FromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pfltOut"]),
        #
        'VarR4FromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "pfltOut"]),
        #
        'VarR4FromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "pfltOut"]),
        #
        'VarR4FromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pfltOut"]),
        #
        'VarR4FromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "pfltOut"]),
        #
        'VarR4FromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "pfltOut"]),
        #
        'VarR4FromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeFloat(size=32), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pfltOut"]),
        #
        'VarR8FromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "pdblOut"]),
        #
        'VarR8FromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sIn", "pdblOut"]),
        #
        'VarR8FromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "pdblOut"]),
        #
        'VarR8FromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "pdblOut"]),
        #
        'VarR8FromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "pdblOut"]),
        #
        'VarR8FromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pdblOut"]),
        #
        'VarR8FromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "pdblOut"]),
        #
        'VarR8FromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pdblOut"]),
        #
        'VarR8FromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pdblOut"]),
        #
        'VarR8FromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "pdblOut"]),
        #
        'VarR8FromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "pdblOut"]),
        #
        'VarR8FromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pdblOut"]),
        #
        'VarR8FromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "pdblOut"]),
        #
        'VarR8FromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "pdblOut"]),
        #
        'VarR8FromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pdblOut"]),
        #
        'VarDateFromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "pdateOut"]),
        #
        'VarDateFromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sIn", "pdateOut"]),
        #
        'VarDateFromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "pdateOut"]),
        #
        'VarDateFromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "pdateOut"]),
        #
        'VarDateFromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "pdateOut"]),
        #
        'VarDateFromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "pdateOut"]),
        #
        'VarDateFromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pdateOut"]),
        #
        'VarDateFromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pdateOut"]),
        #
        'VarDateFromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pdateOut"]),
        #
        'VarDateFromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "pdateOut"]),
        #
        'VarDateFromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "pdateOut"]),
        #
        'VarDateFromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pdateOut"]),
        #
        'VarDateFromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "pdateOut"]),
        #
        'VarDateFromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "pdateOut"]),
        #
        'VarDateFromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pdateOut"]),
        #
        'VarCyFromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "pcyOut"]),
        #
        'VarCyFromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sIn", "pcyOut"]),
        #
        'VarCyFromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "pcyOut"]),
        #
        'VarCyFromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "pcyOut"]),
        #
        'VarCyFromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "pcyOut"]),
        #
        'VarCyFromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "pcyOut"]),
        #
        'VarCyFromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "pcyOut"]),
        #
        'VarCyFromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pcyOut"]),
        #
        'VarCyFromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pcyOut"]),
        #
        'VarCyFromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "pcyOut"]),
        #
        'VarCyFromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "pcyOut"]),
        #
        'VarCyFromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pcyOut"]),
        #
        'VarCyFromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "pcyOut"]),
        #
        'VarCyFromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "pcyOut"]),
        #
        'VarCyFromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pcyOut"]),
        #
        'VarBstrFromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bVal", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iVal", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBstrFromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "lcid", "dwFlags", "pbstrOut"]),
        #
        'VarBoolFromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "pboolOut"]),
        #
        'VarBoolFromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sIn", "pboolOut"]),
        #
        'VarBoolFromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "pboolOut"]),
        #
        'VarBoolFromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "pboolOut"]),
        #
        'VarBoolFromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "pboolOut"]),
        #
        'VarBoolFromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "pboolOut"]),
        #
        'VarBoolFromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "pboolOut"]),
        #
        'VarBoolFromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pboolOut"]),
        #
        'VarBoolFromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pboolOut"]),
        #
        'VarBoolFromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pboolOut"]),
        #
        'VarBoolFromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "pboolOut"]),
        #
        'VarBoolFromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pboolOut"]),
        #
        'VarBoolFromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "pboolOut"]),
        #
        'VarBoolFromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "pboolOut"]),
        #
        'VarBoolFromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pboolOut"]),
        #
        'VarI1FromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "pcOut"]),
        #
        'VarI1FromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pcOut"]),
        #
        'VarI1FromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "pcOut"]),
        #
        'VarI1FromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "pcOut"]),
        #
        'VarI1FromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "pcOut"]),
        #
        'VarI1FromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "pcOut"]),
        #
        'VarI1FromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "pcOut"]),
        #
        'VarI1FromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pcOut"]),
        #
        'VarI1FromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pcOut"]),
        #
        'VarI1FromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pcOut"]),
        #
        'VarI1FromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "pcOut"]),
        #
        'VarI1FromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pcOut"]),
        #
        'VarI1FromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "pcOut"]),
        #
        'VarI1FromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "pcOut"]),
        #
        'VarI1FromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pcOut"]),
        #
        'VarUI2FromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "puiOut"]),
        #
        'VarUI2FromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "puiOut"]),
        #
        'VarUI2FromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "puiOut"]),
        #
        'VarUI2FromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "puiOut"]),
        #
        'VarUI2FromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "puiOut"]),
        #
        'VarUI2FromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "puiOut"]),
        #
        'VarUI2FromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "puiOut"]),
        #
        'VarUI2FromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "puiOut"]),
        #
        'VarUI2FromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "puiOut"]),
        #
        'VarUI2FromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "puiOut"]),
        #
        'VarUI2FromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "puiOut"]),
        #
        'VarUI2FromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "puiOut"]),
        #
        'VarUI2FromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "puiOut"]),
        #
        'VarUI2FromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "puiOut"]),
        #
        'VarUI2FromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "puiOut"]),
        #
        'VarUI4FromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "pulOut"]),
        #
        'VarUI4FromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pulOut"]),
        #
        'VarUI4FromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "pulOut"]),
        #
        'VarUI4FromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "plOut"]),
        #
        'VarUI4FromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "pulOut"]),
        #
        'VarUI4FromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "pulOut"]),
        #
        'VarUI4FromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "pulOut"]),
        #
        'VarUI4FromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pulOut"]),
        #
        'VarUI4FromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pulOut"]),
        #
        'VarUI4FromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pulOut"]),
        #
        'VarUI4FromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "pulOut"]),
        #
        'VarUI4FromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "pulOut"]),
        #
        'VarUI4FromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pulOut"]),
        #
        'VarUI4FromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "plOut"]),
        #
        'VarUI4FromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pulOut"]),
        #
        'VarUI8FromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "pi64Out"]),
        #
        'VarUI8FromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sIn", "pi64Out"]),
        #
        'VarUI8FromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "pi64Out"]),
        #
        'VarUI8FromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "pi64Out"]),
        #
        'VarUI8FromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "pi64Out"]),
        #
        'VarUI8FromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pi64Out"]),
        #
        'VarUI8FromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "pi64Out"]),
        #
        'VarUI8FromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pi64Out"]),
        #
        'VarUI8FromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pi64Out"]),
        #
        'VarUI8FromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "pi64Out"]),
        #
        'VarUI8FromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "pi64Out"]),
        #
        'VarUI8FromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pi64Out"]),
        #
        'VarUI8FromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "pi64Out"]),
        #
        'VarUI8FromDec': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pi64Out"]),
        #
        'VarDecFromUI1': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bIn", "pdecOut"]),
        #
        'VarDecFromI2': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pdecOut"]),
        #
        'VarDecFromI4': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lIn", "pdecOut"]),
        #
        'VarDecFromI8': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["i64In", "pdecOut"]),
        #
        'VarDecFromR4': SimTypeFunction([SimTypeFloat(size=32), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fltIn", "pdecOut"]),
        #
        'VarDecFromR8': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "pdecOut"]),
        #
        'VarDecFromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "pdecOut"]),
        #
        'VarDecFromCy': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pdecOut"]),
        #
        'VarDecFromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pdecOut"]),
        #
        'VarDecFromDisp': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispIn", "lcid", "pdecOut"]),
        #
        'VarDecFromBool': SimTypeFunction([SimTypeShort(signed=True, label="Int16"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["boolIn", "pdecOut"]),
        #
        'VarDecFromI1': SimTypeFunction([SimTypeChar(label="SByte"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cIn", "pdecOut"]),
        #
        'VarDecFromUI2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uiIn", "pdecOut"]),
        #
        'VarDecFromUI4': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulIn", "pdecOut"]),
        #
        'VarDecFromUI8': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ui64In", "pdecOut"]),
        #
        'VarParseNumFromStr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("NUMPARSE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["strIn", "lcid", "dwFlags", "pnumprs", "rgbDig"]),
        #
        'VarNumFromParseNum': SimTypeFunction([SimTypePointer(SimTypeRef("NUMPARSE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pnumprs", "rgbDig", "dwVtBits", "pvar"]),
        #
        'VarAdd': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarAnd': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarCat': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarDiv': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarEqv': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarIdiv': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarImp': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarMod': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarMul': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarOr': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarPow': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarSub': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarXor': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarLeft", "pvarRight", "pvarResult"]),
        #
        'VarAbs': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "pvarResult"]),
        #
        'VarFix': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "pvarResult"]),
        #
        'VarInt': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "pvarResult"]),
        #
        'VarNeg': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "pvarResult"]),
        #
        'VarNot': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "pvarResult"]),
        #
        'VarRound': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "cDecimals", "pvarResult"]),
        #
        'VarCmp': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="VARCMP"), arg_names=["pvarLeft", "pvarRight", "lcid", "dwFlags"]),
        #
        'VarDecAdd': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecLeft", "pdecRight", "pdecResult"]),
        #
        'VarDecDiv': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecLeft", "pdecRight", "pdecResult"]),
        #
        'VarDecMul': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecLeft", "pdecRight", "pdecResult"]),
        #
        'VarDecSub': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecLeft", "pdecRight", "pdecResult"]),
        #
        'VarDecAbs': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pdecResult"]),
        #
        'VarDecFix': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pdecResult"]),
        #
        'VarDecInt': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pdecResult"]),
        #
        'VarDecNeg': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "pdecResult"]),
        #
        'VarDecRound': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdecIn", "cDecimals", "pdecResult"]),
        #
        'VarDecCmp': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0)], SimTypeInt(signed=False, label="VARCMP"), arg_names=["pdecLeft", "pdecRight"]),
        #
        'VarDecCmpR8': SimTypeFunction([SimTypePointer(SimTypeRef("DECIMAL", SimStruct), offset=0), SimTypeFloat(size=64)], SimTypeInt(signed=False, label="VARCMP"), arg_names=["pdecLeft", "dblRight"]),
        #
        'VarCyAdd': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyLeft", "cyRight", "pcyResult"]),
        #
        'VarCyMul': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyLeft", "cyRight", "pcyResult"]),
        #
        'VarCyMulI4': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyLeft", "lRight", "pcyResult"]),
        #
        'VarCyMulI8': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyLeft", "lRight", "pcyResult"]),
        #
        'VarCySub': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyLeft", "cyRight", "pcyResult"]),
        #
        'VarCyAbs': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pcyResult"]),
        #
        'VarCyFix': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pcyResult"]),
        #
        'VarCyInt': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pcyResult"]),
        #
        'VarCyNeg': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "pcyResult"]),
        #
        'VarCyRound': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cyIn", "cDecimals", "pcyResult"]),
        #
        'VarCyCmp': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None")], SimTypeInt(signed=False, label="VARCMP"), arg_names=["cyLeft", "cyRight"]),
        #
        'VarCyCmpR8': SimTypeFunction([SimUnion({"Anonymous": SimStruct(OrderedDict((("Lo", SimTypeInt(signed=False, label="UInt32")), ("Hi", SimTypeInt(signed=True, label="Int32")),)), name="_Anonymous_e__Struct", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypeFloat(size=64)], SimTypeInt(signed=False, label="VARCMP"), arg_names=["cyLeft", "dblRight"]),
        #
        'VarBstrCat': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["bstrLeft", "bstrRight", "pbstrResult"]),
        #
        'VarBstrCmp': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["bstrLeft", "bstrRight", "lcid", "dwFlags"]),
        #
        'VarR8Pow': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblLeft", "dblRight", "pdblResult"]),
        #
        'VarR4CmpR8': SimTypeFunction([SimTypeFloat(size=32), SimTypeFloat(size=64)], SimTypeInt(signed=False, label="VARCMP"), arg_names=["fltLeft", "dblRight"]),
        #
        'VarR8Round': SimTypeFunction([SimTypeFloat(size=64), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dblIn", "cDecimals", "pdblResult"]),
        #
        'VarDateFromUdate': SimTypeFunction([SimTypePointer(SimTypeRef("UDATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pudateIn", "dwFlags", "pdateOut"]),
        #
        'VarDateFromUdateEx': SimTypeFunction([SimTypePointer(SimTypeRef("UDATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pudateIn", "lcid", "dwFlags", "pdateOut"]),
        #
        'VarUdateFromDate': SimTypeFunction([SimTypeFloat(size=64), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UDATE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dateIn", "dwFlags", "pudateOut"]),
        #
        'GetAltMonthNames': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lcid", "prgp"]),
        #
        'VarFormat': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="VARFORMAT_FIRST_DAY"), SimTypeInt(signed=False, label="VARFORMAT_FIRST_WEEK"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "pstrFormat", "iFirstDay", "iFirstWeek", "dwFlags", "pbstrOut"]),
        #
        'VarFormatDateTime': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="VARFORMAT_NAMED_FORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "iNamedFormat", "dwFlags", "pbstrOut"]),
        #
        'VarFormatNumber': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="VARFORMAT_LEADING_DIGIT"), SimTypeInt(signed=False, label="VARFORMAT_PARENTHESES"), SimTypeInt(signed=False, label="VARFORMAT_GROUP"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "iNumDig", "iIncLead", "iUseParens", "iGroup", "dwFlags", "pbstrOut"]),
        #
        'VarFormatPercent': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="VARFORMAT_LEADING_DIGIT"), SimTypeInt(signed=False, label="VARFORMAT_PARENTHESES"), SimTypeInt(signed=False, label="VARFORMAT_GROUP"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "iNumDig", "iIncLead", "iUseParens", "iGroup", "dwFlags", "pbstrOut"]),
        #
        'VarFormatCurrency': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "iNumDig", "iIncLead", "iUseParens", "iGroup", "dwFlags", "pbstrOut"]),
        #
        'VarWeekdayName': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iWeekday", "fAbbrev", "iFirstDay", "dwFlags", "pbstrOut"]),
        #
        'VarMonthName': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iMonth", "fAbbrev", "dwFlags", "pbstrOut"]),
        #
        'VarFormatFromTokens': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarIn", "pstrFormat", "pbTokCur", "dwFlags", "pbstrOut", "lcid"]),
        #
        'VarTokenizeFormatString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="VARFORMAT_FIRST_DAY"), SimTypeInt(signed=False, label="VARFORMAT_FIRST_WEEK"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstrFormat", "rgbTok", "cbTok", "iFirstDay", "iFirstWeek", "lcid", "pcbActual"]),
        #
        'LHashValOfNameSysA': SimTypeFunction([SimTypeInt(signed=False, label="SYSKIND"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["syskind", "lcid", "szName"]),
        #
        'LHashValOfNameSys': SimTypeFunction([SimTypeInt(signed=False, label="SYSKIND"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["syskind", "lcid", "szName"]),
        #
        'LoadTypeLib': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="ITypeLib"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szFile", "pptlib"]),
        #
        'LoadTypeLibEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="REGKIND"), SimTypePointer(SimTypeBottom(label="ITypeLib"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szFile", "regkind", "pptlib"]),
        #
        'LoadRegTypeLib': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ITypeLib"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rguid", "wVerMajor", "wVerMinor", "lcid", "pptlib"]),
        #
        'QueryPathOfRegTypeLib': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guid", "wMaj", "wMin", "lcid", "lpbstrPathName"]),
        #
        'RegisterTypeLib': SimTypeFunction([SimTypeBottom(label="ITypeLib"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ptlib", "szFullPath", "szHelpDir"]),
        #
        'UnRegisterTypeLib': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SYSKIND")], SimTypeInt(signed=True, label="Int32"), arg_names=["libID", "wVerMajor", "wVerMinor", "lcid", "syskind"]),
        #
        'RegisterTypeLibForUser': SimTypeFunction([SimTypeBottom(label="ITypeLib"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ptlib", "szFullPath", "szHelpDir"]),
        #
        'UnRegisterTypeLibForUser': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SYSKIND")], SimTypeInt(signed=True, label="Int32"), arg_names=["libID", "wMajorVerNum", "wMinorVerNum", "lcid", "syskind"]),
        #
        'CreateTypeLib': SimTypeFunction([SimTypeInt(signed=False, label="SYSKIND"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="ICreateTypeLib"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["syskind", "szFile", "ppctlib"]),
        #
        'CreateTypeLib2': SimTypeFunction([SimTypeInt(signed=False, label="SYSKIND"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="ICreateTypeLib2"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["syskind", "szFile", "ppctlib"]),
        #
        'DispGetParam': SimTypeFunction([SimTypePointer(SimTypeRef("DISPPARAMS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="VARENUM"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdispparams", "position", "vtTarg", "pvarResult", "puArgErr"]),
        #
        'DispGetIDsOfNames': SimTypeFunction([SimTypeBottom(label="ITypeInfo"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ptinfo", "rgszNames", "cNames", "rgdispid"]),
        #
        'DispInvoke': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="ITypeInfo"), SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("DISPPARAMS", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("EXCEPINFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["_this", "ptinfo", "dispidMember", "wFlags", "pparams", "pvarResult", "pexcepinfo", "puArgErr"]),
        #
        'CreateDispTypeInfo': SimTypeFunction([SimTypePointer(SimTypeRef("INTERFACEDATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ITypeInfo"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidata", "lcid", "pptinfo"]),
        #
        'CreateStdDispatch': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="ITypeInfo"), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkOuter", "pvThis", "ptinfo", "ppunkStdDisp"]),
        #
        'DispCallFunc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="CALLCONV"), SimTypeInt(signed=False, label="VARENUM"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvInstance", "oVft", "cc", "vtReturn", "cActuals", "prgvt", "prgpvarg", "pvargResult"]),
        #
        'RegisterActiveObject': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="ACTIVEOBJECT_FLAGS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "rclsid", "dwFlags", "pdwRegister"]),
        #
        'RevokeActiveObject': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwRegister", "pvReserved"]),
        #
        'GetActiveObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "pvReserved", "ppunk"]),
        #
        'CreateErrorInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="ICreateErrorInfo"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pperrinfo"]),
        #
        'GetRecordInfoFromTypeInfo': SimTypeFunction([SimTypeBottom(label="ITypeInfo"), SimTypePointer(SimTypeBottom(label="IRecordInfo"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pTypeInfo", "ppRecInfo"]),
        #
        'GetRecordInfoFromGuids': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IRecordInfo"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rGuidTypeLib", "uVerMajor", "uVerMinor", "lcid", "rGuidTypeInfo", "ppRecInfo"]),
        #
        'OaBuildVersion': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'ClearCustData': SimTypeFunction([SimTypePointer(SimTypeRef("CUSTDATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pCustData"]),
        #
        'OaEnablePerUserTLibRegistration': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'OleCreatePropertyFrame': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndOwner", "x", "y", "lpszCaption", "cObjects", "ppUnk", "cPages", "pPageClsID", "lcid", "dwReserved", "pvReserved"]),
        #
        'OleCreatePropertyFrameIndirect': SimTypeFunction([SimTypePointer(SimTypeRef("OCPFIPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpParams"]),
        #
        'OleTranslateColor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clr", "hpal", "lpcolorref"]),
        #
        'OleCreateFontIndirect': SimTypeFunction([SimTypePointer(SimTypeRef("FONTDESC", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFontDesc", "riid", "lplpvObj"]),
        #
        'OleCreatePictureIndirect': SimTypeFunction([SimTypePointer(SimTypeRef("PICTDESC", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpPictDesc", "riid", "fOwn", "lplpvObj"]),
        #
        'OleLoadPicture': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpstream", "lSize", "fRunmode", "riid", "lplpvObj"]),
        #
        'OleLoadPictureEx': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LOAD_PICTURE_FLAGS"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpstream", "lSize", "fRunmode", "riid", "xSizeDesired", "ySizeDesired", "dwFlags", "lplpvObj"]),
        #
        'OleLoadPicturePath': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szURLorPath", "punkCaller", "dwReserved", "clrReserved", "riid", "ppvRet"]),
        #
        'OleLoadPictureFile': SimTypeFunction([SimTypeRef("VARIANT", SimStruct), SimTypePointer(SimTypeBottom(label="IDispatch"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varFileName", "lplpdispPicture"]),
        #
        'OleLoadPictureFileEx': SimTypeFunction([SimTypeRef("VARIANT", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="LOAD_PICTURE_FLAGS"), SimTypePointer(SimTypeBottom(label="IDispatch"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varFileName", "xSizeDesired", "ySizeDesired", "dwFlags", "lplpdispPicture"]),
        #
        'OleSavePictureFile': SimTypeFunction([SimTypeBottom(label="IDispatch"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdispPicture", "bstrFileName"]),
        #
        'OleIconToCursor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hinstExe", "hIcon"]),
        #
        'VARIANT_UserSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'VARIANT_UserMarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'VARIANT_UserUnmarshal': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'VARIANT_UserFree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'VARIANT_UserSize64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]),
        #
        'VARIANT_UserMarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'VARIANT_UserUnmarshal64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["param0", "param1", "param2"]),
        #
        'VARIANT_UserFree64': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["param0", "param1"]),
        #
        'DosDateTimeToVariantTime': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wDosDate", "wDosTime", "pvtime"]),
        #
        'VariantTimeToDosDateTime': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vtime", "pwDosDate", "pwDosTime"]),
        #
        'SystemTimeToVariantTime': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSystemTime", "pvtime"]),
        #
        'VariantTimeToSystemTime': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypeRef("SYSTEMTIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["vtime", "lpSystemTime"]),
        #
        'VariantInit': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pvarg"]),
        #
        'VariantClear': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarg"]),
        #
        'VariantCopy': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvargDest", "pvargSrc"]),
        #
        'VariantCopyInd': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvarDest", "pvargSrc"]),
        #
        'VariantChangeType': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="VAR_CHANGE_FLAGS"), SimTypeInt(signed=False, label="VARENUM")], SimTypeInt(signed=True, label="Int32"), arg_names=["pvargDest", "pvarSrc", "wFlags", "vt"]),
        #
        'VariantChangeTypeEx': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="VAR_CHANGE_FLAGS"), SimTypeInt(signed=False, label="VARENUM")], SimTypeInt(signed=True, label="Int32"), arg_names=["pvargDest", "pvarSrc", "lcid", "wFlags", "vt"]),
    }

lib.set_prototypes(prototypes)
