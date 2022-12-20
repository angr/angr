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
lib.set_library_names("davclnt.dll")
prototypes = \
    {
        #
        'DavGetTheLockOwnerOfTheFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["FileName", "LockOwnerName", "LockOwnerNameLengthInBytes"]),
        #
        'DavInvalidateCache': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["URLName"]),
        #
        'DavCancelConnectionsToServer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "fForce"]),
        #
        'DavRegisterAuthCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"AuthBlob": SimStruct({"pBuffer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "ulSize": SimTypeInt(signed=False, label="UInt32"), "ulType": SimTypeInt(signed=False, label="UInt32")}, name="DAV_CALLBACK_AUTH_BLOB", pack=False, align=None), "UNPBlob": SimStruct({"pszUserName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "ulUserNameLength": SimTypeInt(signed=False, label="UInt32"), "pszPassword": SimTypePointer(SimTypeChar(label="Char"), offset=0), "ulPasswordLength": SimTypeInt(signed=False, label="UInt32")}, name="DAV_CALLBACK_AUTH_UNP", pack=False, align=None), "bAuthBlobValid": SimTypeInt(signed=True, label="Int32"), "bSave": SimTypeInt(signed=True, label="Int32")}, name="DAV_CALLBACK_CRED", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="AUTHNEXTSTEP"), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbuffer"]), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpwzServerName", "lpwzRemoteName", "dwAuthScheme", "dwFlags", "pCallbackCred", "NextStep", "pFreeCred"]), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["CallBack", "Version"]),
        #
        'DavUnregisterAuthCallback': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["hCallback"]),
        #
        'NPAddConnection': SimTypeFunction([SimTypePointer(SimStruct({"dwScope": SimTypeInt(signed=False, label="NET_RESOURCE_SCOPE"), "dwType": SimTypeInt(signed=False, label="NET_RESOURCE_TYPE"), "dwDisplayType": SimTypeInt(signed=False, label="UInt32"), "dwUsage": SimTypeInt(signed=False, label="UInt32"), "lpLocalName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpRemoteName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpComment": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpProvider": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="NETRESOURCEW", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpNetResource", "lpPassword", "lpUserName"]),
        #
        'NPAddConnection3': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwScope": SimTypeInt(signed=False, label="NET_RESOURCE_SCOPE"), "dwType": SimTypeInt(signed=False, label="NET_RESOURCE_TYPE"), "dwDisplayType": SimTypeInt(signed=False, label="UInt32"), "dwUsage": SimTypeInt(signed=False, label="UInt32"), "lpLocalName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpRemoteName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpComment": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpProvider": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="NETRESOURCEW", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="NET_USE_CONNECT_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndOwner", "lpNetResource", "lpPassword", "lpUserName", "dwFlags"]),
        #
        'NPCancelConnection': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "fForce"]),
        #
        'NPGetConnection': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpLocalName", "lpRemoteName", "lpnBufferLen"]),
        #
        'NPGetUniversalName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UNC_INFO_LEVEL"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpLocalPath", "dwInfoLevel", "lpBuffer", "lpBufferSize"]),
        #
        'NPOpenEnum': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"dwScope": SimTypeInt(signed=False, label="NET_RESOURCE_SCOPE"), "dwType": SimTypeInt(signed=False, label="NET_RESOURCE_TYPE"), "dwDisplayType": SimTypeInt(signed=False, label="UInt32"), "dwUsage": SimTypeInt(signed=False, label="UInt32"), "lpLocalName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpRemoteName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpComment": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpProvider": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="NETRESOURCEW", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwScope", "dwType", "dwUsage", "lpNetResource", "lphEnum"]),
        #
        'NPEnumResource': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEnum", "lpcCount", "lpBuffer", "lpBufferSize"]),
        #
        'NPCloseEnum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEnum"]),
        #
        'NPGetCaps': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ndex"]),
        #
        'NPGetUser': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "lpUserName", "lpnBufferLen"]),
        #
        'NPGetResourceParent': SimTypeFunction([SimTypePointer(SimStruct({"dwScope": SimTypeInt(signed=False, label="NET_RESOURCE_SCOPE"), "dwType": SimTypeInt(signed=False, label="NET_RESOURCE_TYPE"), "dwDisplayType": SimTypeInt(signed=False, label="UInt32"), "dwUsage": SimTypeInt(signed=False, label="UInt32"), "lpLocalName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpRemoteName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpComment": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpProvider": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="NETRESOURCEW", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpNetResource", "lpBuffer", "lpBufferSize"]),
        #
        'NPGetResourceInformation': SimTypeFunction([SimTypePointer(SimStruct({"dwScope": SimTypeInt(signed=False, label="NET_RESOURCE_SCOPE"), "dwType": SimTypeInt(signed=False, label="NET_RESOURCE_TYPE"), "dwDisplayType": SimTypeInt(signed=False, label="UInt32"), "dwUsage": SimTypeInt(signed=False, label="UInt32"), "lpLocalName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpRemoteName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpComment": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpProvider": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="NETRESOURCEW", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpNetResource", "lpBuffer", "lpBufferSize", "lplpSystem"]),
        #
        'NPFormatNetworkName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="NETWORK_NAME_FORMAT_FLAGS"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpRemoteName", "lpFormattedName", "lpnLength", "dwFlags", "dwAveCharPerLine"]),
    }

lib.set_prototypes(prototypes)
