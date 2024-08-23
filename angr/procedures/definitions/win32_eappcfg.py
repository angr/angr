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
lib.set_library_names("eappcfg.dll")
prototypes = \
    {
        #
        'EapHostPeerGetMethods': SimTypeFunction([SimTypePointer(SimTypeRef("EAP_METHOD_INFO_ARRAY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pEapMethodInfoArray", "ppEapError"]),
        #
        'EapHostPeerGetMethodProperties': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("EAP_METHOD_TYPE", SimStruct), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("EAP_METHOD_PROPERTY_ARRAY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwVersion", "dwFlags", "eapMethodType", "hUserImpersonationToken", "dwEapConnDataSize", "pbEapConnData", "dwUserDataSize", "pbUserData", "pMethodPropertyArray", "ppEapError"]),
        #
        'EapHostPeerInvokeConfigUI': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("EAP_METHOD_TYPE", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndParent", "dwFlags", "eapMethodType", "dwSizeOfConfigIn", "pConfigIn", "pdwSizeOfConfigOut", "ppConfigOut", "ppEapError"]),
        #
        'EapHostPeerQueryCredentialInputFields': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("EAP_METHOD_TYPE", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("EAP_CONFIG_INPUT_FIELD_ARRAY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hUserImpersonationToken", "eapMethodType", "dwFlags", "dwEapConnDataSize", "pbEapConnData", "pEapConfigInputFieldArray", "ppEapError"]),
        #
        'EapHostPeerQueryUserBlobFromCredentialInputFields': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("EAP_METHOD_TYPE", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("EAP_CONFIG_INPUT_FIELD_ARRAY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hUserImpersonationToken", "eapMethodType", "dwFlags", "dwEapConnDataSize", "pbEapConnData", "pEapConfigInputFieldArray", "pdwUserBlobSize", "ppbUserBlob", "ppEapError"]),
        #
        'EapHostPeerInvokeIdentityUI': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeRef("EAP_METHOD_TYPE", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwVersion", "eapMethodType", "dwFlags", "hwndParent", "dwSizeofConnectionData", "pConnectionData", "dwSizeofUserData", "pUserData", "pdwSizeOfUserDataOut", "ppUserDataOut", "ppwszIdentity", "ppEapError", "ppvReserved"]),
        #
        'EapHostPeerInvokeInteractiveUI': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndParent", "dwSizeofUIContextData", "pUIContextData", "pdwSizeOfDataFromInteractiveUI", "ppDataFromInteractiveUI", "ppEapError"]),
        #
        'EapHostPeerQueryInteractiveUIInputFields': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("EAP_INTERACTIVE_UI_DATA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwVersion", "dwFlags", "dwSizeofUIContextData", "pUIContextData", "pEapInteractiveUIData", "ppEapError", "ppvReserved"]),
        #
        'EapHostPeerQueryUIBlobFromInteractiveUIInputFields': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("EAP_INTERACTIVE_UI_DATA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwVersion", "dwFlags", "dwSizeofUIContextData", "pUIContextData", "pEapInteractiveUIData", "pdwSizeOfDataFromInteractiveUI", "ppDataFromInteractiveUI", "ppEapError", "ppvReserved"]),
        #
        'EapHostPeerConfigXml2Blob': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IXMLDOMNode"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeRef("EAP_METHOD_TYPE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "pConfigDoc", "pdwSizeOfConfigOut", "ppConfigOut", "pEapMethodType", "ppEapError"]),
        #
        'EapHostPeerCredentialsXml2Blob': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IXMLDOMNode"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeRef("EAP_METHOD_TYPE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "pCredentialsDoc", "dwSizeOfConfigIn", "pConfigIn", "pdwSizeOfCredentialsOut", "ppCredentialsOut", "pEapMethodType", "ppEapError"]),
        #
        'EapHostPeerConfigBlob2Xml': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeRef("EAP_METHOD_TYPE", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IXMLDOMDocument2"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "eapMethodType", "dwSizeOfConfigIn", "pConfigIn", "ppConfigDoc", "ppEapError"]),
        #
        'EapHostPeerFreeMemory': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pData"]),
        #
        'EapHostPeerFreeErrorMemory': SimTypeFunction([SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pEapError"]),
    }

lib.set_prototypes(prototypes)
