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
lib.set_library_names("chakra.dll")
prototypes = \
    {
        #
        'JsCreateContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="IDebugApplication64"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime", "debugApplication", "newContext"]),
        #
        'JsStartDebugging': SimTypeFunction([SimTypeBottom(label="IDebugApplication64")], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["debugApplication"]),
        #
        'JsCreateRuntime': SimTypeFunction([SimTypeInt(signed=False, label="JsRuntimeAttributes"), SimTypeInt(signed=False, label="JsRuntimeVersion"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["callbackState"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBool(), arg_names=["callback", "callbackState"]), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["attributes", "runtimeVersion", "threadService", "runtime"]),
        #
        'JsCollectGarbage': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime"]),
        #
        'JsDisposeRuntime': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime"]),
        #
        'JsGetRuntimeMemoryUsage': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime", "memoryUsage"]),
        #
        'JsGetRuntimeMemoryLimit': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime", "memoryLimit"]),
        #
        'JsSetRuntimeMemoryLimit': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime", "memoryLimit"]),
        #
        'JsSetRuntimeMemoryAllocationCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="JsMemoryEventType"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBool(), arg_names=["callbackState", "allocationEvent", "allocationSize"]), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime", "callbackState", "allocationCallback"]),
        #
        'JsSetRuntimeBeforeCollectCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["callbackState"]), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime", "callbackState", "beforeCollectCallback"]),
        #
        'JsAddRef': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["ref", "count"]),
        #
        'JsRelease': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["ref", "count"]),
        #
        'JsGetCurrentContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["currentContext"]),
        #
        'JsSetCurrentContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["context"]),
        #
        'JsGetRuntime': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["context", "runtime"]),
        #
        'JsIdle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["nextIdleTick"]),
        #
        'JsParseScript': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["script", "sourceContext", "sourceUrl", "result"]),
        #
        'JsRunScript': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["script", "sourceContext", "sourceUrl", "result"]),
        #
        'JsSerializeScript': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["script", "buffer", "bufferSize"]),
        #
        'JsParseSerializedScript': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["script", "buffer", "sourceContext", "sourceUrl", "result"]),
        #
        'JsRunSerializedScript': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["script", "buffer", "sourceContext", "sourceUrl", "result"]),
        #
        'JsGetPropertyIdFromName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["name", "propertyId"]),
        #
        'JsGetPropertyNameFromId': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["propertyId", "name"]),
        #
        'JsGetUndefinedValue': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["undefinedValue"]),
        #
        'JsGetNullValue': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["nullValue"]),
        #
        'JsGetTrueValue': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["trueValue"]),
        #
        'JsGetFalseValue': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["falseValue"]),
        #
        'JsBoolToBoolean': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["value", "booleanValue"]),
        #
        'JsBooleanToBool': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["value", "boolValue"]),
        #
        'JsConvertValueToBoolean': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["value", "booleanValue"]),
        #
        'JsGetValueType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="JsValueType"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["value", "type"]),
        #
        'JsDoubleToNumber': SimTypeFunction([SimTypeFloat(size=64), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["doubleValue", "value"]),
        #
        'JsIntToNumber': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["intValue", "value"]),
        #
        'JsNumberToDouble': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["value", "doubleValue"]),
        #
        'JsConvertValueToNumber': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["value", "numberValue"]),
        #
        'JsGetStringLength': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["stringValue", "length"]),
        #
        'JsPointerToString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["stringValue", "stringLength", "value"]),
        #
        'JsStringToPointer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["value", "stringValue", "stringLength"]),
        #
        'JsConvertValueToString': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["value", "stringValue"]),
        #
        'JsVariantToValue': SimTypeFunction([SimTypePointer(SimStruct({"Anonymous": SimUnion({"Anonymous": SimStruct({"vt": SimTypeShort(signed=False, label="UInt16"), "wReserved1": SimTypeShort(signed=False, label="UInt16"), "wReserved2": SimTypeShort(signed=False, label="UInt16"), "wReserved3": SimTypeShort(signed=False, label="UInt16"), "Anonymous": SimUnion({"llVal": SimTypeLongLong(signed=True, label="Int64"), "lVal": SimTypeInt(signed=True, label="Int32"), "bVal": SimTypeChar(label="Byte"), "iVal": SimTypeShort(signed=True, label="Int16"), "fltVal": SimTypeFloat(size=32), "dblVal": SimTypeFloat(size=64), "boolVal": SimTypeShort(signed=True, label="Int16"), "__OBSOLETE__VARIANT_BOOL": SimTypeShort(signed=True, label="Int16"), "scode": SimTypeInt(signed=True, label="Int32"), "cyVal": SimTypeBottom(label="CY"), "date": SimTypeFloat(size=64), "bstrVal": SimTypePointer(SimTypeChar(label="Char"), offset=0), "punkVal": SimTypeBottom(label="IUnknown"), "pdispVal": SimTypeBottom(label="IDispatch"), "parray": SimTypePointer(SimStruct({"cDims": SimTypeShort(signed=False, label="UInt16"), "fFeatures": SimTypeShort(signed=False, label="UInt16"), "cbElements": SimTypeInt(signed=False, label="UInt32"), "cLocks": SimTypeInt(signed=False, label="UInt32"), "pvData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "rgsabound": SimTypePointer(SimStruct({"cElements": SimTypeInt(signed=False, label="UInt32"), "lLbound": SimTypeInt(signed=True, label="Int32")}, name="SAFEARRAYBOUND", pack=False, align=None), offset=0)}, name="SAFEARRAY", pack=False, align=None), offset=0), "pbVal": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "piVal": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), "plVal": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "pllVal": SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), "pfltVal": SimTypePointer(SimTypeFloat(size=32), offset=0), "pdblVal": SimTypePointer(SimTypeFloat(size=64), offset=0), "pboolVal": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), "__OBSOLETE__VARIANT_PBOOL": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), "pscode": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "pcyVal": SimTypePointer(SimTypeBottom(label="CY"), offset=0), "pdate": SimTypePointer(SimTypeFloat(size=64), offset=0), "pbstrVal": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), "ppunkVal": SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0), "ppdispVal": SimTypePointer(SimTypeBottom(label="IDispatch"), offset=0), "pparray": SimTypePointer(SimTypePointer(SimStruct({"cDims": SimTypeShort(signed=False, label="UInt16"), "fFeatures": SimTypeShort(signed=False, label="UInt16"), "cbElements": SimTypeInt(signed=False, label="UInt32"), "cLocks": SimTypeInt(signed=False, label="UInt32"), "pvData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "rgsabound": SimTypePointer(SimStruct({"cElements": SimTypeInt(signed=False, label="UInt32"), "lLbound": SimTypeInt(signed=True, label="Int32")}, name="SAFEARRAYBOUND", pack=False, align=None), offset=0)}, name="SAFEARRAY", pack=False, align=None), offset=0), offset=0), "pvarVal": SimTypePointer(SimTypeBottom(label="VARIANT"), offset=0), "byref": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "cVal": SimTypeBottom(label="CHAR"), "uiVal": SimTypeShort(signed=False, label="UInt16"), "ulVal": SimTypeInt(signed=False, label="UInt32"), "ullVal": SimTypeLongLong(signed=False, label="UInt64"), "intVal": SimTypeInt(signed=True, label="Int32"), "uintVal": SimTypeInt(signed=False, label="UInt32"), "pdecVal": SimTypePointer(SimTypeBottom(label="DECIMAL"), offset=0), "pcVal": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "puiVal": SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), "pulVal": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "pullVal": SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), "pintVal": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "puintVal": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "Anonymous": SimStruct({"pvRecord": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "pRecInfo": SimTypeBottom(label="IRecordInfo")}, name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="_Anonymous_e__Struct", pack=False, align=None), "decVal": SimTypeBottom(label="DECIMAL")}, name="<anon>", label="None")}, name="VARIANT", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["variant", "value"]),
        #
        'JsValueToVariant': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"Anonymous": SimUnion({"Anonymous": SimStruct({"vt": SimTypeShort(signed=False, label="UInt16"), "wReserved1": SimTypeShort(signed=False, label="UInt16"), "wReserved2": SimTypeShort(signed=False, label="UInt16"), "wReserved3": SimTypeShort(signed=False, label="UInt16"), "Anonymous": SimUnion({"llVal": SimTypeLongLong(signed=True, label="Int64"), "lVal": SimTypeInt(signed=True, label="Int32"), "bVal": SimTypeChar(label="Byte"), "iVal": SimTypeShort(signed=True, label="Int16"), "fltVal": SimTypeFloat(size=32), "dblVal": SimTypeFloat(size=64), "boolVal": SimTypeShort(signed=True, label="Int16"), "__OBSOLETE__VARIANT_BOOL": SimTypeShort(signed=True, label="Int16"), "scode": SimTypeInt(signed=True, label="Int32"), "cyVal": SimTypeBottom(label="CY"), "date": SimTypeFloat(size=64), "bstrVal": SimTypePointer(SimTypeChar(label="Char"), offset=0), "punkVal": SimTypeBottom(label="IUnknown"), "pdispVal": SimTypeBottom(label="IDispatch"), "parray": SimTypePointer(SimStruct({"cDims": SimTypeShort(signed=False, label="UInt16"), "fFeatures": SimTypeShort(signed=False, label="UInt16"), "cbElements": SimTypeInt(signed=False, label="UInt32"), "cLocks": SimTypeInt(signed=False, label="UInt32"), "pvData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "rgsabound": SimTypePointer(SimStruct({"cElements": SimTypeInt(signed=False, label="UInt32"), "lLbound": SimTypeInt(signed=True, label="Int32")}, name="SAFEARRAYBOUND", pack=False, align=None), offset=0)}, name="SAFEARRAY", pack=False, align=None), offset=0), "pbVal": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "piVal": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), "plVal": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "pllVal": SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), "pfltVal": SimTypePointer(SimTypeFloat(size=32), offset=0), "pdblVal": SimTypePointer(SimTypeFloat(size=64), offset=0), "pboolVal": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), "__OBSOLETE__VARIANT_PBOOL": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), "pscode": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "pcyVal": SimTypePointer(SimTypeBottom(label="CY"), offset=0), "pdate": SimTypePointer(SimTypeFloat(size=64), offset=0), "pbstrVal": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), "ppunkVal": SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0), "ppdispVal": SimTypePointer(SimTypeBottom(label="IDispatch"), offset=0), "pparray": SimTypePointer(SimTypePointer(SimStruct({"cDims": SimTypeShort(signed=False, label="UInt16"), "fFeatures": SimTypeShort(signed=False, label="UInt16"), "cbElements": SimTypeInt(signed=False, label="UInt32"), "cLocks": SimTypeInt(signed=False, label="UInt32"), "pvData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "rgsabound": SimTypePointer(SimStruct({"cElements": SimTypeInt(signed=False, label="UInt32"), "lLbound": SimTypeInt(signed=True, label="Int32")}, name="SAFEARRAYBOUND", pack=False, align=None), offset=0)}, name="SAFEARRAY", pack=False, align=None), offset=0), offset=0), "pvarVal": SimTypePointer(SimTypeBottom(label="VARIANT"), offset=0), "byref": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "cVal": SimTypeBottom(label="CHAR"), "uiVal": SimTypeShort(signed=False, label="UInt16"), "ulVal": SimTypeInt(signed=False, label="UInt32"), "ullVal": SimTypeLongLong(signed=False, label="UInt64"), "intVal": SimTypeInt(signed=True, label="Int32"), "uintVal": SimTypeInt(signed=False, label="UInt32"), "pdecVal": SimTypePointer(SimTypeBottom(label="DECIMAL"), offset=0), "pcVal": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "puiVal": SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), "pulVal": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "pullVal": SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), "pintVal": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "puintVal": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "Anonymous": SimStruct({"pvRecord": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "pRecInfo": SimTypeBottom(label="IRecordInfo")}, name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="_Anonymous_e__Struct", pack=False, align=None), "decVal": SimTypeBottom(label="DECIMAL")}, name="<anon>", label="None")}, name="VARIANT", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "variant"]),
        #
        'JsGetGlobalObject': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["globalObject"]),
        #
        'JsCreateObject': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object"]),
        #
        'JsCreateExternalObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["data"]), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["data", "finalizeCallback", "object"]),
        #
        'JsConvertValueToObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["value", "object"]),
        #
        'JsGetPrototype': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "prototypeObject"]),
        #
        'JsSetPrototype': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "prototypeObject"]),
        #
        'JsGetExtensionAllowed': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "value"]),
        #
        'JsPreventExtension': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object"]),
        #
        'JsGetProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "propertyId", "value"]),
        #
        'JsGetOwnPropertyDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "propertyId", "propertyDescriptor"]),
        #
        'JsGetOwnPropertyNames': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "propertyNames"]),
        #
        'JsSetProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "propertyId", "value", "useStrictRules"]),
        #
        'JsHasProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "propertyId", "hasProperty"]),
        #
        'JsDeleteProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "propertyId", "useStrictRules", "result"]),
        #
        'JsDefineProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "propertyId", "propertyDescriptor", "result"]),
        #
        'JsHasIndexedProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "index", "result"]),
        #
        'JsGetIndexedProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "index", "result"]),
        #
        'JsSetIndexedProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "index", "value"]),
        #
        'JsDeleteIndexedProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "index"]),
        #
        'JsEquals': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object1", "object2", "result"]),
        #
        'JsStrictEquals': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object1", "object2", "result"]),
        #
        'JsHasExternalData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "value"]),
        #
        'JsGetExternalData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "externalData"]),
        #
        'JsSetExternalData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "externalData"]),
        #
        'JsCreateArray': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["length", "result"]),
        #
        'JsCallFunction': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["function", "arguments", "argumentCount", "result"]),
        #
        'JsConstructObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["function", "arguments", "argumentCount", "result"]),
        #
        'JsCreateFunction': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBool(), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["callee", "isConstructCall", "arguments", "argumentCount", "callbackState"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["nativeFunction", "callbackState", "function"]),
        #
        'JsCreateError': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["message", "error"]),
        #
        'JsCreateRangeError': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["message", "error"]),
        #
        'JsCreateReferenceError': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["message", "error"]),
        #
        'JsCreateSyntaxError': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["message", "error"]),
        #
        'JsCreateTypeError': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["message", "error"]),
        #
        'JsCreateURIError': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["message", "error"]),
        #
        'JsHasException': SimTypeFunction([SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["hasException"]),
        #
        'JsGetAndClearException': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["exception"]),
        #
        'JsSetException': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["exception"]),
        #
        'JsDisableRuntimeExecution': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime"]),
        #
        'JsEnableRuntimeExecution': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime"]),
        #
        'JsIsRuntimeExecutionDisabled': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime", "isDisabled"]),
        #
        'JsStartProfiling': SimTypeFunction([SimTypeBottom(label="IActiveScriptProfilerCallback"), SimTypeInt(signed=False, label="PROFILER_EVENT_MASK"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["callback", "eventMask", "context"]),
        #
        'JsStopProfiling': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["reason"]),
        #
        'JsEnumerateHeap': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IActiveScriptProfilerHeapEnum"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["enumerator"]),
        #
        'JsIsEnumeratingHeap': SimTypeFunction([SimTypePointer(SimTypeBool(), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["isEnumeratingHeap"]),
        #
        'JsCreateContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="IDebugApplication32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime", "debugApplication", "newContext"]),
        #
        'JsStartDebugging': SimTypeFunction([SimTypeBottom(label="IDebugApplication32")], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["debugApplication"]),
    }

lib.set_prototypes(prototypes)
