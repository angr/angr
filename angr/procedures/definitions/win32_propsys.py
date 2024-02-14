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
lib.set_library_names("propsys.dll")
prototypes = \
    {
        #
        'PropVariantToWinRTPropertyValue': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "riid", "ppv"]),
        #
        'WinRTPropertyValueToPropVariant': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkPropertyValue", "ppropvar"]),
        #
        'InitPropVariantFromResource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hinst", "id", "ppropvar"]),
        #
        'InitPropVariantFromBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pv", "cb", "ppropvar"]),
        #
        'InitPropVariantFromCLSID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "ppropvar"]),
        #
        'InitPropVariantFromGUIDAsString': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guid", "ppropvar"]),
        #
        'InitPropVariantFromFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pftIn", "ppropvar"]),
        #
        'InitPropVariantFromPropVariantVectorElem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "iElem", "ppropvar"]),
        #
        'InitPropVariantVectorFromPropVariant': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarSingle", "ppropvarVector"]),
        #
        'InitPropVariantFromBooleanVector': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgf", "cElems", "ppropvar"]),
        #
        'InitPropVariantFromInt16Vector': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "ppropvar"]),
        #
        'InitPropVariantFromUInt16Vector': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "ppropvar"]),
        #
        'InitPropVariantFromInt32Vector': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "ppropvar"]),
        #
        'InitPropVariantFromUInt32Vector': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "ppropvar"]),
        #
        'InitPropVariantFromInt64Vector': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "ppropvar"]),
        #
        'InitPropVariantFromUInt64Vector': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "ppropvar"]),
        #
        'InitPropVariantFromDoubleVector': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "ppropvar"]),
        #
        'InitPropVariantFromFileTimeVector': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgft", "cElems", "ppropvar"]),
        #
        'InitPropVariantFromStringVector': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgsz", "cElems", "ppropvar"]),
        #
        'InitPropVariantFromStringAsVector': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz", "ppropvar"]),
        #
        'PropVariantToBooleanWithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "fDefault"]),
        #
        'PropVariantToInt16WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeShort(signed=True, label="Int16")], SimTypeShort(signed=True, label="Int16"), arg_names=["propvarIn", "iDefault"]),
        #
        'PropVariantToUInt16WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["propvarIn", "uiDefault"]),
        #
        'PropVariantToInt32WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "lDefault"]),
        #
        'PropVariantToUInt32WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["propvarIn", "ulDefault"]),
        #
        'PropVariantToInt64WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeLongLong(signed=True, label="Int64"), arg_names=["propvarIn", "llDefault"]),
        #
        'PropVariantToUInt64WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["propvarIn", "ullDefault"]),
        #
        'PropVariantToDoubleWithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeFloat(size=64)], SimTypeFloat(size=64), arg_names=["propvarIn", "dblDefault"]),
        #
        'PropVariantToStringWithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["propvarIn", "pszDefault"]),
        #
        'PropVariantToBoolean': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "pfRet"]),
        #
        'PropVariantToInt16': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "piRet"]),
        #
        'PropVariantToUInt16': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "puiRet"]),
        #
        'PropVariantToInt32': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "plRet"]),
        #
        'PropVariantToUInt32': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "pulRet"]),
        #
        'PropVariantToInt64': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "pllRet"]),
        #
        'PropVariantToUInt64': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "pullRet"]),
        #
        'PropVariantToDouble': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvarIn", "pdblRet"]),
        #
        'PropVariantToBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pv", "cb"]),
        #
        'PropVariantToString': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "psz", "cch"]),
        #
        'PropVariantToGUID': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pguid"]),
        #
        'PropVariantToStringAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "ppszOut"]),
        #
        'PropVariantToBSTR': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pbstrOut"]),
        #
        'PropVariantToFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="PSTIME_FLAGS"), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pstfOut", "pftOut"]),
        #
        'PropVariantGetElementCount': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["propvar"]),
        #
        'PropVariantToBooleanVector': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "prgf", "crgf", "pcElem"]),
        #
        'PropVariantToInt16Vector': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "prgn", "crgn", "pcElem"]),
        #
        'PropVariantToUInt16Vector': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "prgn", "crgn", "pcElem"]),
        #
        'PropVariantToInt32Vector': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "prgn", "crgn", "pcElem"]),
        #
        'PropVariantToUInt32Vector': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "prgn", "crgn", "pcElem"]),
        #
        'PropVariantToInt64Vector': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "prgn", "crgn", "pcElem"]),
        #
        'PropVariantToUInt64Vector': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "prgn", "crgn", "pcElem"]),
        #
        'PropVariantToDoubleVector': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeFloat(size=64), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "prgn", "crgn", "pcElem"]),
        #
        'PropVariantToFileTimeVector': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "prgft", "crgft", "pcElem"]),
        #
        'PropVariantToStringVector': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "prgsz", "crgsz", "pcElem"]),
        #
        'PropVariantToBooleanVectorAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pprgf", "pcElem"]),
        #
        'PropVariantToInt16VectorAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pprgn", "pcElem"]),
        #
        'PropVariantToUInt16VectorAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pprgn", "pcElem"]),
        #
        'PropVariantToInt32VectorAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pprgn", "pcElem"]),
        #
        'PropVariantToUInt32VectorAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pprgn", "pcElem"]),
        #
        'PropVariantToInt64VectorAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pprgn", "pcElem"]),
        #
        'PropVariantToUInt64VectorAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pprgn", "pcElem"]),
        #
        'PropVariantToDoubleVectorAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeFloat(size=64), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pprgn", "pcElem"]),
        #
        'PropVariantToFileTimeVectorAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pprgft", "pcElem"]),
        #
        'PropVariantToStringVectorAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pprgsz", "pcElem"]),
        #
        'PropVariantGetBooleanElem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "iElem", "pfVal"]),
        #
        'PropVariantGetInt16Elem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "iElem", "pnVal"]),
        #
        'PropVariantGetUInt16Elem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "iElem", "pnVal"]),
        #
        'PropVariantGetInt32Elem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "iElem", "pnVal"]),
        #
        'PropVariantGetUInt32Elem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "iElem", "pnVal"]),
        #
        'PropVariantGetInt64Elem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "iElem", "pnVal"]),
        #
        'PropVariantGetUInt64Elem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "iElem", "pnVal"]),
        #
        'PropVariantGetDoubleElem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "iElem", "pnVal"]),
        #
        'PropVariantGetFileTimeElem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "iElem", "pftVal"]),
        #
        'PropVariantGetStringElem': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "iElem", "ppszVal"]),
        #
        'ClearPropVariantArray': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["rgPropVar", "cVars"]),
        #
        'PropVariantCompareEx': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="PROPVAR_COMPARE_UNIT"), SimTypeInt(signed=False, label="PROPVAR_COMPARE_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar1", "propvar2", "unit", "flags"]),
        #
        'PropVariantChangeType': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="PROPVAR_CHANGE_FLAGS"), SimTypeInt(signed=False, label="VARENUM")], SimTypeInt(signed=True, label="Int32"), arg_names=["ppropvarDest", "propvarSrc", "flags", "vt"]),
        #
        'PropVariantToVariant': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPropVar", "pVar"]),
        #
        'VariantToPropVariant': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pVar", "pPropVar"]),
        #
        'StgSerializePropVariant': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SERIALIZEDPROPERTYVALUE", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppropvar", "ppProp", "pcb"]),
        #
        'StgDeserializePropVariant': SimTypeFunction([SimTypePointer(SimTypeRef("SERIALIZEDPROPERTYVALUE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pprop", "cbMax", "ppropvar"]),
        #
        'InitVariantFromResource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hinst", "id", "pvar"]),
        #
        'InitVariantFromBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pv", "cb", "pvar"]),
        #
        'InitVariantFromGUIDAsString': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guid", "pvar"]),
        #
        'InitVariantFromFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pft", "pvar"]),
        #
        'InitVariantFromFileTimeArray': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgft", "cElems", "pvar"]),
        #
        'InitVariantFromVariantArrayElem': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "iElem", "pvar"]),
        #
        'InitVariantFromBooleanArray': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgf", "cElems", "pvar"]),
        #
        'InitVariantFromInt16Array': SimTypeFunction([SimTypePointer(SimTypeShort(signed=True, label="Int16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "pvar"]),
        #
        'InitVariantFromUInt16Array': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "pvar"]),
        #
        'InitVariantFromInt32Array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "pvar"]),
        #
        'InitVariantFromUInt32Array': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "pvar"]),
        #
        'InitVariantFromInt64Array': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "pvar"]),
        #
        'InitVariantFromUInt64Array': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "pvar"]),
        #
        'InitVariantFromDoubleArray': SimTypeFunction([SimTypePointer(SimTypeFloat(size=64), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgn", "cElems", "pvar"]),
        #
        'InitVariantFromStringArray': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgsz", "cElems", "pvar"]),
        #
        'VariantToBooleanWithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "fDefault"]),
        #
        'VariantToInt16WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeShort(signed=True, label="Int16")], SimTypeShort(signed=True, label="Int16"), arg_names=["varIn", "iDefault"]),
        #
        'VariantToUInt16WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["varIn", "uiDefault"]),
        #
        'VariantToInt32WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "lDefault"]),
        #
        'VariantToUInt32WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["varIn", "ulDefault"]),
        #
        'VariantToInt64WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeLongLong(signed=True, label="Int64"), arg_names=["varIn", "llDefault"]),
        #
        'VariantToUInt64WithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["varIn", "ullDefault"]),
        #
        'VariantToDoubleWithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeFloat(size=64)], SimTypeFloat(size=64), arg_names=["varIn", "dblDefault"]),
        #
        'VariantToStringWithDefault': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["varIn", "pszDefault"]),
        #
        'VariantToBoolean': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "pfRet"]),
        #
        'VariantToInt16': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "piRet"]),
        #
        'VariantToUInt16': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "puiRet"]),
        #
        'VariantToInt32': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "plRet"]),
        #
        'VariantToUInt32': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "pulRet"]),
        #
        'VariantToInt64': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "pllRet"]),
        #
        'VariantToUInt64': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "pullRet"]),
        #
        'VariantToDouble': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "pdblRet"]),
        #
        'VariantToBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "pv", "cb"]),
        #
        'VariantToGUID': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "pguid"]),
        #
        'VariantToString': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "pszBuf", "cchBuf"]),
        #
        'VariantToStringAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "ppszBuf"]),
        #
        'VariantToDosDateTime': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "pwDate", "pwTime"]),
        #
        'VariantToFileTime': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="PSTIME_FLAGS"), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "stfOut", "pftOut"]),
        #
        'VariantGetElementCount': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["varIn"]),
        #
        'VariantToBooleanArray': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "prgf", "crgn", "pcElem"]),
        #
        'VariantToInt16Array': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "prgn", "crgn", "pcElem"]),
        #
        'VariantToUInt16Array': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "prgn", "crgn", "pcElem"]),
        #
        'VariantToInt32Array': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "prgn", "crgn", "pcElem"]),
        #
        'VariantToUInt32Array': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "prgn", "crgn", "pcElem"]),
        #
        'VariantToInt64Array': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "prgn", "crgn", "pcElem"]),
        #
        'VariantToUInt64Array': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "prgn", "crgn", "pcElem"]),
        #
        'VariantToDoubleArray': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeFloat(size=64), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "prgn", "crgn", "pcElem"]),
        #
        'VariantToStringArray': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "prgsz", "crgsz", "pcElem"]),
        #
        'VariantToBooleanArrayAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "pprgf", "pcElem"]),
        #
        'VariantToInt16ArrayAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "pprgn", "pcElem"]),
        #
        'VariantToUInt16ArrayAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "pprgn", "pcElem"]),
        #
        'VariantToInt32ArrayAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "pprgn", "pcElem"]),
        #
        'VariantToUInt32ArrayAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "pprgn", "pcElem"]),
        #
        'VariantToInt64ArrayAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "pprgn", "pcElem"]),
        #
        'VariantToUInt64ArrayAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "pprgn", "pcElem"]),
        #
        'VariantToDoubleArrayAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeFloat(size=64), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "pprgn", "pcElem"]),
        #
        'VariantToStringArrayAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "pprgsz", "pcElem"]),
        #
        'VariantGetBooleanElem': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "iElem", "pfVal"]),
        #
        'VariantGetInt16Elem': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "iElem", "pnVal"]),
        #
        'VariantGetUInt16Elem': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "iElem", "pnVal"]),
        #
        'VariantGetInt32Elem': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "iElem", "pnVal"]),
        #
        'VariantGetUInt32Elem': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "iElem", "pnVal"]),
        #
        'VariantGetInt64Elem': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "iElem", "pnVal"]),
        #
        'VariantGetUInt64Elem': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "iElem", "pnVal"]),
        #
        'VariantGetDoubleElem': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "iElem", "pnVal"]),
        #
        'VariantGetStringElem': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var", "iElem", "ppszVal"]),
        #
        'ClearVariantArray': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pvars", "cvars"]),
        #
        'VariantCompare': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["var1", "var2"]),
        #
        'InitPropVariantFromStrRet': SimTypeFunction([SimTypePointer(SimTypeRef("STRRET", SimStruct), offset=0), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstrret", "pidl", "ppropvar"]),
        #
        'PropVariantToStrRet': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRRET", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propvar", "pstrret"]),
        #
        'InitVariantFromStrRet': SimTypeFunction([SimTypePointer(SimTypeRef("STRRET", SimStruct), offset=0), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstrret", "pidl", "pvar"]),
        #
        'VariantToStrRet': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRRET", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["varIn", "pstrret"]),
        #
        'PSFormatForDisplay': SimTypeFunction([SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="PROPDESC_FORMAT_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["propkey", "propvar", "pdfFlags", "pwszText", "cchText"]),
        #
        'PSFormatForDisplayAlloc': SimTypeFunction([SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="PROPDESC_FORMAT_FLAGS"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["key", "propvar", "pdff", "ppszDisplay"]),
        #
        'PSFormatPropertyValue': SimTypeFunction([SimTypeBottom(label="IPropertyStore"), SimTypeBottom(label="IPropertyDescription"), SimTypeInt(signed=False, label="PROPDESC_FORMAT_FLAGS"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pps", "ppd", "pdff", "ppszDisplay"]),
        #
        'PSGetImageReferenceForValue': SimTypeFunction([SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propkey", "propvar", "ppszImageRes"]),
        #
        'PSStringFromPropertyKey': SimTypeFunction([SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pkey", "psz", "cch"]),
        #
        'PSPropertyKeyFromString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszString", "pkey"]),
        #
        'PSCreateMemoryPropertyStore': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppv"]),
        #
        'PSCreateDelayedMultiplexPropertyStore': SimTypeFunction([SimTypeInt(signed=False, label="GETPROPERTYSTOREFLAGS"), SimTypeBottom(label="IDelayedPropertyStoreFactory"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "pdpsf", "rgStoreIds", "cStores", "riid", "ppv"]),
        #
        'PSCreateMultiplexPropertyStore': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IUnknown"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prgpunkStores", "cStores", "riid", "ppv"]),
        #
        'PSCreatePropertyChangeArray': SimTypeFunction([SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="PKA_FLAGS"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rgpropkey", "rgflags", "rgpropvar", "cChanges", "riid", "ppv"]),
        #
        'PSCreateSimplePropertyChange': SimTypeFunction([SimTypeInt(signed=False, label="PKA_FLAGS"), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["flags", "key", "propvar", "riid", "ppv"]),
        #
        'PSGetPropertyDescription': SimTypeFunction([SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propkey", "riid", "ppv"]),
        #
        'PSGetPropertyDescriptionByName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszCanonicalName", "riid", "ppv"]),
        #
        'PSLookupPropertyHandlerCLSID': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFilePath", "pclsid"]),
        #
        'PSGetItemPropertyHandler': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkItem", "fReadWrite", "riid", "ppv"]),
        #
        'PSGetItemPropertyHandlerWithCreateObject': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkItem", "fReadWrite", "punkCreateObject", "riid", "ppv"]),
        #
        'PSGetPropertyValue': SimTypeFunction([SimTypeBottom(label="IPropertyStore"), SimTypeBottom(label="IPropertyDescription"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pps", "ppd", "ppropvar"]),
        #
        'PSSetPropertyValue': SimTypeFunction([SimTypeBottom(label="IPropertyStore"), SimTypeBottom(label="IPropertyDescription"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pps", "ppd", "propvar"]),
        #
        'PSRegisterPropertySchema': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        #
        'PSUnregisterPropertySchema': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        #
        'PSRefreshPropertySchema': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'PSEnumeratePropertyDescriptions': SimTypeFunction([SimTypeInt(signed=False, label="PROPDESC_ENUMFILTER"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["filterOn", "riid", "ppv"]),
        #
        'PSGetPropertyKeyFromName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszName", "ppropkey"]),
        #
        'PSGetNameFromPropertyKey': SimTypeFunction([SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propkey", "ppszCanonicalName"]),
        #
        'PSCoerceToCanonicalValue': SimTypeFunction([SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["key", "ppropvar"]),
        #
        'PSGetPropertyDescriptionListFromString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPropList", "riid", "ppv"]),
        #
        'PSCreatePropertyStoreFromPropertySetStorage': SimTypeFunction([SimTypeBottom(label="IPropertySetStorage"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppss", "grfMode", "riid", "ppv"]),
        #
        'PSCreatePropertyStoreFromObject': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "grfMode", "riid", "ppv"]),
        #
        'PSCreateAdapterFromPropertyStore': SimTypeFunction([SimTypeBottom(label="IPropertyStore"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pps", "riid", "ppv"]),
        #
        'PSGetPropertySystem': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppv"]),
        #
        'PSGetPropertyFromPropertyStorage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psps", "cb", "rpkey", "ppropvar"]),
        #
        'PSGetNamedPropertyFromPropertyStorage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psps", "cb", "pszName", "ppropvar"]),
        #
        'PSPropertyBag_ReadType': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypeInt(signed=False, label="VARENUM")], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "var", "type"]),
        #
        'PSPropertyBag_ReadStr': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value", "characterCount"]),
        #
        'PSPropertyBag_ReadStrAlloc': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadBSTR': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteStr': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteBSTR': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadInt': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteInt': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadSHORT': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteSHORT': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=True, label="Int16")], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadLONG': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteLONG': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadDWORD': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteDWORD': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadBOOL': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteBOOL': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadPOINTL': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WritePOINTL': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("POINTL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadPOINTS': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("POINTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WritePOINTS': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("POINTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadRECTL': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteRECTL': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("RECTL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadStream': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteStream': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_Delete': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName"]),
        #
        'PSPropertyBag_ReadULONGLONG': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteULONGLONG': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadUnknown': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "riid", "ppv"]),
        #
        'PSPropertyBag_WriteUnknown': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "punk"]),
        #
        'PSPropertyBag_ReadGUID': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WriteGUID': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_ReadPropertyKey': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
        #
        'PSPropertyBag_WritePropertyKey': SimTypeFunction([SimTypeBottom(label="IPropertyBag"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["propBag", "propName", "value"]),
    }

lib.set_prototypes(prototypes)
