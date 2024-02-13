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
lib.set_library_names("eappprxy.dll")
prototypes = \
    {
        #
        'EapHostPeerInitialize': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'EapHostPeerUninitialize': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'EapHostPeerBeginSession': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeRef("EAP_METHOD_TYPE", SimStruct), SimTypePointer(SimTypeRef("EAP_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([SimTypeBottom(label="Guid"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["connectionId", "pContextData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwFlags", "eapType", "pAttributeArray", "hTokenImpersonateUser", "dwSizeofConnectionData", "pConnectionData", "dwSizeofUserData", "pUserData", "dwMaxSendPacketSize", "pConnectionId", "func", "pContextData", "pSessionId", "ppEapError"]),
        #
        'EapHostPeerProcessReceivedPacket': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="EapHostPeerResponseAction"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["sessionHandle", "cbReceivePacket", "pReceivePacket", "pEapOutput", "ppEapError"]),
        #
        'EapHostPeerGetSendPacket': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["sessionHandle", "pcbSendPacket", "ppSendPacket", "ppEapError"]),
        #
        'EapHostPeerGetResult': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="EapHostPeerMethodResultReason"), SimTypePointer(SimTypeRef("EapHostPeerMethodResult", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["sessionHandle", "reason", "ppResult", "ppEapError"]),
        #
        'EapHostPeerGetUIContext': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["sessionHandle", "pdwSizeOfUIContextData", "ppUIContextData", "ppEapError"]),
        #
        'EapHostPeerSetUIContext': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="EapHostPeerResponseAction"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["sessionHandle", "dwSizeOfUIContextData", "pUIContextData", "pEapOutput", "ppEapError"]),
        #
        'EapHostPeerGetResponseAttributes': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EAP_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["sessionHandle", "pAttribs", "ppEapError"]),
        #
        'EapHostPeerSetResponseAttributes': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EAP_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="EapHostPeerResponseAction"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["sessionHandle", "pAttribs", "pEapOutput", "ppEapError"]),
        #
        'EapHostPeerGetAuthStatus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="EapHostPeerAuthParams"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["sessionHandle", "authParam", "pcbAuthData", "ppAuthData", "ppEapError"]),
        #
        'EapHostPeerEndSession': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["sessionHandle", "ppEapError"]),
        #
        'EapHostPeerGetDataToUnplumbCredentials': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pConnectionIdThatLastSavedCreds", "phCredentialImpersonationToken", "sessionHandle", "ppEapError", "fSaveToCredMan"]),
        #
        'EapHostPeerClearConnection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pConnectionId", "ppEapError"]),
        #
        'EapHostPeerFreeEapError': SimTypeFunction([SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pEapError"]),
        #
        'EapHostPeerGetIdentity': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeRef("EAP_METHOD_TYPE", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("EAP_ERROR", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwVersion", "dwFlags", "eapMethodType", "dwSizeofConnectionData", "pConnectionData", "dwSizeofUserData", "pUserData", "hTokenImpersonateUser", "pfInvokeUI", "pdwSizeOfUserDataOut", "ppUserDataOut", "ppwszIdentity", "ppEapError", "ppvReserved"]),
        #
        'EapHostPeerGetEncryptedPassword': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwSizeofPassword", "szPassword", "ppszEncPassword"]),
        #
        'EapHostPeerFreeRuntimeMemory': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pData"]),
    }

lib.set_prototypes(prototypes)
