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
lib.set_library_names("api-ms-win-devices-query-l1-1-0.dll")
prototypes = \
    {
        #
        'DevCreateObjectQuery': SimTypeFunction([SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROPCOMPKEY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROP_FILTER_EXPRESSION", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("DEV_QUERY_RESULT_ACTION_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevQuery", "pContext", "pActionData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectType", "QueryFlags", "cRequestedProperties", "pRequestedProperties", "cFilterExpressionCount", "pFilter", "pCallback", "pContext", "phDevQuery"]),
        #
        'DevCreateObjectQueryFromId': SimTypeFunction([SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROPCOMPKEY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROP_FILTER_EXPRESSION", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("DEV_QUERY_RESULT_ACTION_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevQuery", "pContext", "pActionData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectType", "pszObjectId", "QueryFlags", "cRequestedProperties", "pRequestedProperties", "cFilterExpressionCount", "pFilter", "pCallback", "pContext", "phDevQuery"]),
        #
        'DevCreateObjectQueryFromIds': SimTypeFunction([SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROPCOMPKEY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROP_FILTER_EXPRESSION", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("DEV_QUERY_RESULT_ACTION_DATA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevQuery", "pContext", "pActionData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectType", "pszzObjectIds", "QueryFlags", "cRequestedProperties", "pRequestedProperties", "cFilterExpressionCount", "pFilter", "pCallback", "pContext", "phDevQuery"]),
        #
        'DevCloseObjectQuery': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevQuery"]),
        #
        'DevGetObjects': SimTypeFunction([SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROPCOMPKEY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROP_FILTER_EXPRESSION", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEV_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectType", "QueryFlags", "cRequestedProperties", "pRequestedProperties", "cFilterExpressionCount", "pFilter", "pcObjectCount", "ppObjects"]),
        #
        'DevFreeObjects': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEV_OBJECT", SimStruct), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["cObjectCount", "pObjects"]),
        #
        'DevGetObjectProperties': SimTypeFunction([SimTypeInt(signed=False, label="DEV_OBJECT_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROPCOMPKEY", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVPROPERTY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectType", "pszObjectId", "QueryFlags", "cRequestedProperties", "pRequestedProperties", "pcPropertyCount", "ppProperties"]),
        #
        'DevFreeObjectProperties': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROPERTY", SimStruct), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["cPropertyCount", "pProperties"]),
        #
        'DevFindProperty': SimTypeFunction([SimTypePointer(SimTypeRef("DEVPROPKEY", SimStruct), offset=0), SimTypeInt(signed=False, label="DEVPROPSTORE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVPROPERTY", SimStruct), label="LPArray", offset=0)], SimTypePointer(SimTypeRef("DEVPROPERTY", SimStruct), offset=0), arg_names=["pKey", "Store", "pszLocaleName", "cProperties", "pProperties"]),
    }

lib.set_prototypes(prototypes)
