# pylint:disable=line-too-long
from __future__ import annotations
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
lib.set_library_names("resutils.dll")
prototypes = \
    {
        #
        'InitializeClusterHealthFault': SimTypeFunction([SimTypePointer(SimTypeRef("CLUSTER_HEALTH_FAULT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["clusterHealthFault"]),
        #
        'InitializeClusterHealthFaultArray': SimTypeFunction([SimTypePointer(SimTypeRef("CLUSTER_HEALTH_FAULT_ARRAY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["clusterHealthFaultArray"]),
        #
        'FreeClusterHealthFault': SimTypeFunction([SimTypePointer(SimTypeRef("CLUSTER_HEALTH_FAULT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["clusterHealthFault"]),
        #
        'FreeClusterHealthFaultArray': SimTypeFunction([SimTypePointer(SimTypeRef("CLUSTER_HEALTH_FAULT_ARRAY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["clusterHealthFaultArray"]),
        #
        'ClusGetClusterHealthFaults': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLUSTER_HEALTH_FAULT_ARRAY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "objects", "flags"]),
        #
        'ClusRemoveClusterHealthFault': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "id", "flags"]),
        #
        'ClusAddClusterHealthFault': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLUSTER_HEALTH_FAULT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "failure", "param2"]),
        #
        'ResUtilStartResourceService': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszServiceName", "phServiceHandle"]),
        #
        'ResUtilVerifyResourceService': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszServiceName"]),
        #
        'ResUtilStopResourceService': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszServiceName"]),
        #
        'ResUtilVerifyService': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hServiceHandle"]),
        #
        'ResUtilStopService': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hServiceHandle"]),
        #
        'ResUtilCreateDirectoryTree': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszPath"]),
        #
        'ResUtilIsPathValid': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        #
        'ResUtilEnumProperties': SimTypeFunction([SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyTable", "pszOutProperties", "cbOutPropertiesSize", "pcbBytesReturned", "pcbRequired"]),
        #
        'ResUtilEnumPrivateProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pszOutProperties", "cbOutPropertiesSize", "pcbBytesReturned", "pcbRequired"]),
        #
        'ResUtilGetProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTable", "pOutPropertyList", "cbOutPropertyListSize", "pcbBytesReturned", "pcbRequired"]),
        #
        'ResUtilGetAllProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTable", "pOutPropertyList", "cbOutPropertyListSize", "pcbBytesReturned", "pcbRequired"]),
        #
        'ResUtilGetPrivateProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pOutPropertyList", "cbOutPropertyListSize", "pcbBytesReturned", "pcbRequired"]),
        #
        'ResUtilGetPropertySize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTableItem", "pcbOutPropertyListSize", "pnPropertyCount"]),
        #
        'ResUtilGetProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTableItem", "pOutPropertyItem", "pcbOutPropertyItemSize"]),
        #
        'ResUtilVerifyPropertyTable': SimTypeFunction([SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyTable", "Reserved", "bAllowUnknownProperties", "pInPropertyList", "cbInPropertyListSize", "pOutParams"]),
        #
        'ResUtilSetPropertyTable': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTable", "Reserved", "bAllowUnknownProperties", "pInPropertyList", "cbInPropertyListSize", "pOutParams"]),
        #
        'ResUtilSetPropertyTableEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTable", "Reserved", "bAllowUnknownProperties", "pInPropertyList", "cbInPropertyListSize", "bForceWrite", "pOutParams"]),
        #
        'ResUtilSetPropertyParameterBlock': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTable", "Reserved", "pInParams", "pInPropertyList", "cbInPropertyListSize", "pOutParams"]),
        #
        'ResUtilSetPropertyParameterBlockEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTable", "Reserved", "pInParams", "pInPropertyList", "cbInPropertyListSize", "bForceWrite", "pOutParams"]),
        #
        'ResUtilSetUnknownProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTable", "pInPropertyList", "cbInPropertyListSize"]),
        #
        'ResUtilGetPropertiesToParameterBlock': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTable", "pOutParams", "bCheckForRequiredProperties", "pszNameOfPropInError"]),
        #
        'ResUtilPropertyListFromParameterBlock': SimTypeFunction([SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyTable", "pOutPropertyList", "pcbOutPropertyListSize", "pInParams", "pcbBytesReturned", "pcbRequired"]),
        #
        'ResUtilDupParameterBlock': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pOutParams", "pInParams", "pPropertyTable"]),
        #
        'ResUtilFreeParameterBlock': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pOutParams", "pInParams", "pPropertyTable"]),
        #
        'ResUtilAddUnknownProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pPropertyTable", "pOutPropertyList", "pcbOutPropertyListSize", "pcbBytesReturned", "pcbRequired"]),
        #
        'ResUtilSetPrivatePropertyList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pInPropertyList", "cbInPropertyListSize"]),
        #
        'ResUtilVerifyPrivatePropertyList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInPropertyList", "cbInPropertyListSize"]),
        #
        'ResUtilDupString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszInString"]),
        #
        'ResUtilGetBinaryValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pszValueName", "ppbOutValue", "pcbOutValueSize"]),
        #
        'ResUtilGetSzValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["hkeyClusterKey", "pszValueName"]),
        #
        'ResUtilGetDwordValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pszValueName", "pdwOutValue", "dwDefaultValue"]),
        #
        'ResUtilGetQwordValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pszValueName", "pqwOutValue", "qwDefaultValue"]),
        #
        'ResUtilSetBinaryValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pszValueName", "pbNewValue", "cbNewValueSize", "ppbOutValue", "pcbOutValueSize"]),
        #
        'ResUtilSetSzValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pszValueName", "pszNewValue", "ppszOutString"]),
        #
        'ResUtilSetExpandSzValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pszValueName", "pszNewValue", "ppszOutString"]),
        #
        'ResUtilSetMultiSzValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pszValueName", "pszNewValue", "cbNewValueSize", "ppszOutValue", "pcbOutValueSize"]),
        #
        'ResUtilSetDwordValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pszValueName", "dwNewValue", "pdwOutValue"]),
        #
        'ResUtilSetQwordValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "pszValueName", "qwNewValue", "pqwOutValue"]),
        #
        'ResUtilSetValueEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hkeyClusterKey", "valueName", "valueType", "valueData", "valueSize", "flags"]),
        #
        'ResUtilGetBinaryProperty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CLUSPROP_BINARY", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ppbOutValue", "pcbOutValueSize", "pValueStruct", "pbOldValue", "cbOldValueSize", "ppPropertyList", "pcbPropertyListSize"]),
        #
        'ResUtilGetSzProperty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeRef("CLUSPROP_SZ", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ppszOutValue", "pValueStruct", "pszOldValue", "ppPropertyList", "pcbPropertyListSize"]),
        #
        'ResUtilGetMultiSzProperty': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CLUSPROP_SZ", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ppszOutValue", "pcbOutValueSize", "pValueStruct", "pszOldValue", "cbOldValueSize", "ppPropertyList", "pcbPropertyListSize"]),
        #
        'ResUtilGetDwordProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CLUSPROP_DWORD", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pdwOutValue", "pValueStruct", "dwOldValue", "dwMinimum", "dwMaximum", "ppPropertyList", "pcbPropertyListSize"]),
        #
        'ResUtilGetLongProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("CLUSPROP_LONG", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["plOutValue", "pValueStruct", "lOldValue", "lMinimum", "lMaximum", "ppPropertyList", "pcbPropertyListSize"]),
        #
        'ResUtilGetFileTimeProperty': SimTypeFunction([SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLUSPROP_FILETIME", SimStruct), offset=0), SimTypeRef("FILETIME", SimStruct), SimTypeRef("FILETIME", SimStruct), SimTypeRef("FILETIME", SimStruct), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pftOutValue", "pValueStruct", "ftOldValue", "ftMinimum", "ftMaximum", "ppPropertyList", "pcbPropertyListSize"]),
        #
        'ResUtilGetEnvironmentWithNetName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["hResource"]),
        #
        'ResUtilFreeEnvironment': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpEnvironment"]),
        #
        'ResUtilExpandEnvironmentStrings': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["pszSrc"]),
        #
        'ResUtilSetResourceServiceEnvironment': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="LOG_LEVEL"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ResourceHandle", "LogLevel", "FormatString"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszServiceName", "hResource", "pfnLogEvent", "hResourceHandle"]),
        #
        'ResUtilRemoveResourceServiceEnvironment': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="LOG_LEVEL"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ResourceHandle", "LogLevel", "FormatString"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszServiceName", "pfnLogEvent", "hResourceHandle"]),
        #
        'ResUtilSetResourceServiceStartParameters': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="LOG_LEVEL"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ResourceHandle", "LogLevel", "FormatString"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszServiceName", "schSCMHandle", "phService", "pfnLogEvent", "hResourceHandle"]),
        #
        'ResUtilFindSzProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyList", "cbPropertyListSize", "pszPropertyName", "pszPropertyValue"]),
        #
        'ResUtilFindExpandSzProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyList", "cbPropertyListSize", "pszPropertyName", "pszPropertyValue"]),
        #
        'ResUtilFindExpandedSzProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyList", "cbPropertyListSize", "pszPropertyName", "pszPropertyValue"]),
        #
        'ResUtilFindDwordProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyList", "cbPropertyListSize", "pszPropertyName", "pdwPropertyValue"]),
        #
        'ResUtilFindBinaryProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyList", "cbPropertyListSize", "pszPropertyName", "pbPropertyValue", "pcbPropertyValueSize"]),
        #
        'ResUtilFindMultiSzProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyList", "cbPropertyListSize", "pszPropertyName", "pszPropertyValue", "pcbPropertyValueSize"]),
        #
        'ResUtilFindLongProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyList", "cbPropertyListSize", "pszPropertyName", "plPropertyValue"]),
        #
        'ResUtilFindULargeIntegerProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyList", "cbPropertyListSize", "pszPropertyName", "plPropertyValue"]),
        #
        'ResUtilFindFileTimeProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyList", "cbPropertyListSize", "pszPropertyName", "pftPropertyValue"]),
        #
        'ClusWorkerCreate': SimTypeFunction([SimTypePointer(SimTypeRef("CLUS_WORKER", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("CLUS_WORKER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pWorker", "lpThreadParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpWorker", "lpStartAddress", "lpParameter"]),
        #
        'ClusWorkerCheckTerminate': SimTypeFunction([SimTypePointer(SimTypeRef("CLUS_WORKER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpWorker"]),
        #
        'ClusWorkerTerminate': SimTypeFunction([SimTypePointer(SimTypeRef("CLUS_WORKER", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpWorker"]),
        #
        'ClusWorkerTerminateEx': SimTypeFunction([SimTypePointer(SimTypeRef("CLUS_WORKER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ClusWorker", "TimeoutInMilliseconds", "WaitOnly"]),
        #
        'ClusWorkersTerminate': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("CLUS_WORKER", SimStruct), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ClusWorkers", "ClusWorkersCount", "TimeoutInMilliseconds", "WaitOnly"]),
        #
        'ResUtilResourcesEqual': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSelf", "hResource"]),
        #
        'ResUtilResourceTypesEqual': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszResourceTypeName", "hResource"]),
        #
        'ResUtilIsResourceClassEqual': SimTypeFunction([SimTypePointer(SimTypeRef("CLUS_RESOURCE_CLASS_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["prci", "hResource"]),
        #
        'ResUtilEnumResources': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSelf", "lpszResTypeName", "pResCallBack", "pParameter"]),
        #
        'ResUtilEnumResourcesEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "hSelf", "lpszResTypeName", "pResCallBack", "pParameter"]),
        #
        'ResUtilGetResourceDependency': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hSelf", "lpszResourceType"]),
        #
        'ResUtilGetResourceDependencyByName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hCluster", "hSelf", "lpszResourceType", "bRecurse"]),
        #
        'ResUtilGetResourceDependencyByClass': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLUS_RESOURCE_CLASS_INFO", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hCluster", "hSelf", "prci", "bRecurse"]),
        #
        'ResUtilGetResourceNameDependency': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszResourceName", "lpszResourceType"]),
        #
        'ResUtilGetResourceDependentIPAddressProps': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hResource", "pszAddress", "pcchAddress", "pszSubnetMask", "pcchSubnetMask", "pszNetwork", "pcchNetwork"]),
        #
        'ResUtilFindDependentDiskResourceDriveLetter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "hResource", "pszDriveLetter", "pcchDriveLetter"]),
        #
        'ResUtilTerminateServiceProcessFromResDll': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="LOG_LEVEL"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ResourceHandle", "LogLevel", "FormatString"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwServicePid", "bOffline", "pdwResourceState", "pfnLogEvent", "hResourceHandle"]),
        #
        'ResUtilGetPropertyFormats': SimTypeFunction([SimTypePointer(SimTypeRef("RESUTIL_PROPERTY_ITEM", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPropertyTable", "pOutPropertyFormatList", "cbPropertyFormatListSize", "pcbBytesReturned", "pcbRequired"]),
        #
        'ResUtilGetCoreClusterResources': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "phClusterNameResource", "phClusterIPAddressResource", "phClusterQuorumResource"]),
        #
        'ResUtilGetResourceName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hResource", "pszResourceName", "pcchResourceNameInOut"]),
        #
        'ResUtilGetClusterRoleState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CLUSTER_ROLE")], SimTypeInt(signed=False, label="CLUSTER_ROLE_STATE"), arg_names=["hCluster", "eClusterRole"]),
        #
        'ClusterIsPathOnSharedVolume': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszPathName"]),
        #
        'ClusterGetVolumePathName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszFileName", "lpszVolumePathName", "cchBufferLength"]),
        #
        'ClusterGetVolumeNameForVolumeMountPoint': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszVolumeMountPoint", "lpszVolumeName", "cchBufferLength"]),
        #
        'ClusterPrepareSharedVolumeForBackup': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszFileName", "lpszVolumePathName", "lpcchVolumePathName", "lpszVolumeName", "lpcchVolumeName"]),
        #
        'ClusterClearBackupStateForSharedVolume': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszVolumePathName"]),
        #
        'ResUtilSetResourceServiceStartParametersEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="LOG_LEVEL"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ResourceHandle", "LogLevel", "FormatString"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszServiceName", "schSCMHandle", "phService", "dwDesiredAccess", "pfnLogEvent", "hResourceHandle"]),
        #
        'ResUtilEnumResourcesEx2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "hSelf", "lpszResTypeName", "pResCallBack", "pParameter", "dwDesiredAccess"]),
        #
        'ResUtilGetResourceDependencyEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hSelf", "lpszResourceType", "dwDesiredAccess"]),
        #
        'ResUtilGetResourceDependencyByNameEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hCluster", "hSelf", "lpszResourceType", "bRecurse", "dwDesiredAccess"]),
        #
        'ResUtilGetResourceDependencyByClassEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLUS_RESOURCE_CLASS_INFO", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hCluster", "hSelf", "prci", "bRecurse", "dwDesiredAccess"]),
        #
        'ResUtilGetResourceNameDependencyEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszResourceName", "lpszResourceType", "dwDesiredAccess"]),
        #
        'ResUtilGetCoreClusterResourcesEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hClusterIn", "phClusterNameResourceOut", "phClusterQuorumResourceOut", "dwDesiredAccess"]),
        #
        'OpenClusterCryptProvider': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszResource", "lpszProvider", "dwType", "dwFlags"]),
        #
        'OpenClusterCryptProviderEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpszResource", "lpszKeyname", "lpszProvider", "dwType", "dwFlags"]),
        #
        'CloseClusterCryptProvider': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hClusCryptProvider"]),
        #
        'ClusterEncrypt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hClusCryptProvider", "pData", "cbData", "ppData", "pcbData"]),
        #
        'ClusterDecrypt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hClusCryptProvider", "pCryptInput", "cbCryptInput", "ppCryptOutput", "pcbCryptOutput"]),
        #
        'FreeClusterCrypt': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pCryptInfo"]),
        #
        'ResUtilVerifyShutdownSafe': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["flags", "reason", "pResult"]),
        #
        'ResUtilPaxosComparer': SimTypeFunction([SimTypePointer(SimTypeRef("PaxosTagCStruct", SimStruct), offset=0), SimTypePointer(SimTypeRef("PaxosTagCStruct", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["left", "right"]),
        #
        'ResUtilLeftPaxosIsLessThanRight': SimTypeFunction([SimTypePointer(SimTypeRef("PaxosTagCStruct", SimStruct), offset=0), SimTypePointer(SimTypeRef("PaxosTagCStruct", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["left", "right"]),
        #
        'ResUtilsDeleteKeyTree': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["key", "keyName", "treatNoKeyAsError"]),
        #
        'ResUtilGroupsEqual': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSelf", "hGroup", "pEqual"]),
        #
        'ResUtilEnumGroups': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "hSelf", "pResCallBack", "pParameter"]),
        #
        'ResUtilEnumGroupsEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CLUSGROUP_TYPE"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "hSelf", "groupType", "pResCallBack", "pParameter"]),
        #
        'ResUtilDupGroup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["group", "copy"]),
        #
        'ResUtilGetClusterGroupType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="CLUSGROUP_TYPE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hGroup", "groupType"]),
        #
        'ResUtilGetCoreGroup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hCluster"]),
        #
        'ResUtilResourceDepEnum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSelf", "enumType", "pResCallBack", "pParameter"]),
        #
        'ResUtilDupResource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["group", "copy"]),
        #
        'ResUtilGetClusterId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "guid"]),
        #
        'ResUtilNodeEnum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="CLUSTER_NODE_STATE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0", "param1", "param2", "param3"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCluster", "pNodeCallBack", "pParameter"]),
    }

lib.set_prototypes(prototypes)
