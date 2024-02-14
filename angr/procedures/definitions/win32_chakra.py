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
        'JsCreateContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="IDebugApplication32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["runtime", "debugApplication", "newContext"]),
        #
        'JsGetCurrentContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["currentContext"]),
        #
        'JsSetCurrentContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["context"]),
        #
        'JsGetRuntime': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["context", "runtime"]),
        #
        'JsStartDebugging': SimTypeFunction([SimTypeBottom(label="IDebugApplication32")], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["debugApplication"]),
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
        'JsVariantToValue': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["variant", "value"]),
        #
        'JsValueToVariant': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=False, label="JsErrorCode"), arg_names=["object", "variant"]),
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
    }

lib.set_prototypes(prototypes)
