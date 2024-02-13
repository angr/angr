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
lib.set_library_names("wsdapi.dll")
prototypes = \
    {
        #
        'WSDCreateUdpMessageParameters': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWSDUdpMessageParameters"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppTxParams"]),
        #
        'WSDCreateUdpAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWSDUdpAddress"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppAddress"]),
        #
        'WSDCreateHttpMessageParameters': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWSDHttpMessageParameters"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppTxParams"]),
        #
        'WSDCreateHttpAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWSDHttpAddress"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppAddress"]),
        #
        'WSDCreateOutboundAttachment': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWSDOutboundAttachment"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppAttachment"]),
        #
        'WSDXMLGetNameFromBuiltinNamespace': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("WSDXML_NAME", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszNamespace", "pszName", "ppName"]),
        #
        'WSDXMLCreateContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IWSDXMLContext"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppContext"]),
        #
        'WSDCreateDiscoveryProvider': SimTypeFunction([SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypeBottom(label="IWSDiscoveryProvider"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pContext", "ppProvider"]),
        #
        'WSDCreateDiscoveryProvider2': SimTypeFunction([SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypeRef("WSD_CONFIG_PARAM", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IWSDiscoveryProvider"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pContext", "pConfigParams", "dwConfigParamCount", "ppProvider"]),
        #
        'WSDCreateDiscoveryPublisher': SimTypeFunction([SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypeBottom(label="IWSDiscoveryPublisher"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pContext", "ppPublisher"]),
        #
        'WSDCreateDiscoveryPublisher2': SimTypeFunction([SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypeRef("WSD_CONFIG_PARAM", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IWSDiscoveryPublisher"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pContext", "pConfigParams", "dwConfigParamCount", "ppPublisher"]),
        #
        'WSDCreateDeviceProxy': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypeBottom(label="IWSDDeviceProxy"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDeviceId", "pszLocalId", "pContext", "ppDeviceProxy"]),
        #
        'WSDCreateDeviceProxyAdvanced': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IWSDAddress"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypeBottom(label="IWSDDeviceProxy"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDeviceId", "pDeviceAddress", "pszLocalId", "pContext", "ppDeviceProxy"]),
        #
        'WSDCreateDeviceProxy2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypeRef("WSD_CONFIG_PARAM", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IWSDDeviceProxy"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDeviceId", "pszLocalId", "pContext", "pConfigParams", "dwConfigParamCount", "ppDeviceProxy"]),
        #
        'WSDCreateDeviceHost': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypeBottom(label="IWSDDeviceHost"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszLocalId", "pContext", "ppDeviceHost"]),
        #
        'WSDCreateDeviceHostAdvanced': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypeBottom(label="IWSDAddress"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IWSDDeviceHost"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszLocalId", "pContext", "ppHostAddresses", "dwHostAddressCount", "ppDeviceHost"]),
        #
        'WSDCreateDeviceHost2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypeRef("WSD_CONFIG_PARAM", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IWSDDeviceHost"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszLocalId", "pContext", "pConfigParams", "dwConfigParamCount", "ppDeviceHost"]),
        #
        'WSDSetConfigurationOption': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwOption", "pVoid", "cbInBuffer"]),
        #
        'WSDGetConfigurationOption': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwOption", "pVoid", "cbOutBuffer"]),
        #
        'WSDAllocateLinkedMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pParent", "cbSize"]),
        #
        'WSDFreeLinkedMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pVoid"]),
        #
        'WSDAttachLinkedMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pParent", "pChild"]),
        #
        'WSDDetachLinkedMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pVoid"]),
        #
        'WSDXMLBuildAnyForSingleElement': SimTypeFunction([SimTypePointer(SimTypeRef("WSDXML_NAME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("WSDXML_ELEMENT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pElementName", "pszText", "ppAny"]),
        #
        'WSDXMLGetValueFromAny': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSDXML_ELEMENT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszNamespace", "pszName", "pAny", "ppszValue"]),
        #
        'WSDXMLAddSibling': SimTypeFunction([SimTypePointer(SimTypeRef("WSDXML_ELEMENT", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSDXML_ELEMENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pFirst", "pSecond"]),
        #
        'WSDXMLAddChild': SimTypeFunction([SimTypePointer(SimTypeRef("WSDXML_ELEMENT", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSDXML_ELEMENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pParent", "pChild"]),
        #
        'WSDXMLCleanupElement': SimTypeFunction([SimTypePointer(SimTypeRef("WSDXML_ELEMENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAny"]),
        #
        'WSDGenerateFault': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IWSDXMLContext"), SimTypePointer(SimTypePointer(SimTypeRef("WSD_SOAP_FAULT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszCode", "pszSubCode", "pszReason", "pszDetail", "pContext", "ppFault"]),
        #
        'WSDGenerateFaultEx': SimTypeFunction([SimTypePointer(SimTypeRef("WSDXML_NAME", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSDXML_NAME", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSD_LOCALIZED_STRING_LIST", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("WSD_SOAP_FAULT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCode", "pSubCode", "pReasons", "pszDetail", "ppFault"]),
        #
        'WSDUriEncode': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["source", "cchSource", "destOut", "cchDestOut"]),
        #
        'WSDUriDecode': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["source", "cchSource", "destOut", "cchDestOut"]),
    }

lib.set_prototypes(prototypes)
