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
lib.set_library_names("wdstptc.dll")
prototypes = \
    {
        #
        'WdsTransportClientInitialize': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'WdsTransportClientInitializeSession': SimTypeFunction([SimTypePointer(SimStruct({"ulLength": SimTypeInt(signed=False, label="UInt32"), "ulApiVersion": SimTypeInt(signed=False, label="UInt32"), "ulAuthLevel": SimTypeInt(signed=False, label="WDS_TRANSPORTCLIENT_REQUEST_AUTH_LEVEL"), "pwszServer": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pwszNamespace": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pwszObjectName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "ulCacheSize": SimTypeInt(signed=False, label="UInt32"), "ulProtocol": SimTypeInt(signed=False, label="UInt32"), "pvProtocolData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "ulProtocolDataLength": SimTypeInt(signed=False, label="UInt32")}, name="WDS_TRANSPORTCLIENT_REQUEST", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pSessionRequest", "pCallerData", "hSessionKey"]),
        #
        'WdsTransportClientRegisterCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSPORTCLIENT_CALLBACK_ID"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSessionKey", "CallbackId", "pfnCallback"]),
        #
        'WdsTransportClientStartSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSessionKey"]),
        #
        'WdsTransportClientCompleteReceive': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=False, label="UInt32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=False, label="UInt32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=False, label="UInt64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSessionKey", "ulSize", "pullOffset"]),
        #
        'WdsTransportClientCancelSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSessionKey"]),
        #
        'WdsTransportClientCancelSessionEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSessionKey", "dwErrorCode"]),
        #
        'WdsTransportClientWaitForCompletion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSessionKey", "uTimeout"]),
        #
        'WdsTransportClientQueryStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSessionKey", "puStatus", "puErrorCode"]),
        #
        'WdsTransportClientCloseSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hSessionKey"]),
        #
        'WdsTransportClientAddRefBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pvBuffer"]),
        #
        'WdsTransportClientReleaseBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pvBuffer"]),
        #
        'WdsTransportClientShutdown': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
    }

lib.set_prototypes(prototypes)
