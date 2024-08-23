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
lib.set_library_names("p2p.dll")
prototypes = \
    {
        #
        'PeerFreeData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pvData"]),
        #
        'PeerGetItemCount': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEnum", "pCount"]),
        #
        'PeerGetNextItem': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEnum", "pCount", "pppvItems"]),
        #
        'PeerEndEnumeration': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEnum"]),
        #
        'PeerGroupStartup': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("PEER_VERSION_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wVersionRequested", "pVersionData"]),
        #
        'PeerGroupShutdown': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'PeerGroupCreate': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_GROUP_PROPERTIES", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProperties", "phGroup"]),
        #
        'PeerGroupOpen': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "pwzGroupPeerName", "pwzCloud", "phGroup"]),
        #
        'PeerGroupJoin': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "pwzInvitation", "pwzCloud", "phGroup"]),
        #
        'PeerGroupPasswordJoin': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "pwzInvitation", "pwzPassword", "pwzCloud", "phGroup"]),
        #
        'PeerGroupConnect': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup"]),
        #
        'PeerGroupConnectByAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PEER_ADDRESS", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "cAddresses", "pAddresses"]),
        #
        'PeerGroupClose': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup"]),
        #
        'PeerGroupDelete': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "pwzGroupPeerName"]),
        #
        'PeerGroupCreateInvitation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pwzIdentityInfo", "pftExpiration", "cRoles", "pRoles", "ppwzInvitation"]),
        #
        'PeerGroupCreatePasswordInvitation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "ppwzInvitation"]),
        #
        'PeerGroupParseInvitation': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_INVITATION_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzInvitation", "ppInvitationInfo"]),
        #
        'PeerGroupGetStatus': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pdwStatus"]),
        #
        'PeerGroupGetProperties': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_GROUP_PROPERTIES", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "ppProperties"]),
        #
        'PeerGroupSetProperties': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("PEER_GROUP_PROPERTIES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pProperties"]),
        #
        'PeerGroupEnumMembers': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "dwFlags", "pwzIdentity", "phPeerEnum"]),
        #
        'PeerGroupOpenDirectConnection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PEER_ADDRESS", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pwzIdentity", "pAddress", "pullConnectionId"]),
        #
        'PeerGroupCloseDirectConnection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "ullConnectionId"]),
        #
        'PeerGroupEnumConnections': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "dwFlags", "phPeerEnum"]),
        #
        'PeerGroupSendData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "ullConnectionId", "pType", "cbData", "pvData"]),
        #
        'PeerGroupRegisterEvent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PEER_GROUP_EVENT_REGISTRATION", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "hEvent", "cEventRegistration", "pEventRegistrations", "phPeerEvent"]),
        #
        'PeerGroupUnregisterEvent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEvent"]),
        #
        'PeerGroupGetEventData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_GROUP_EVENT_DATA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEvent", "ppEventData"]),
        #
        'PeerGroupGetRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_RECORD", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pRecordId", "ppRecord"]),
        #
        'PeerGroupAddRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("PEER_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pRecord", "pRecordId"]),
        #
        'PeerGroupUpdateRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("PEER_RECORD", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pRecord"]),
        #
        'PeerGroupDeleteRecord': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pRecordId"]),
        #
        'PeerGroupEnumRecords': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pRecordType", "phPeerEnum"]),
        #
        'PeerGroupSearchRecords': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pwzCriteria", "phPeerEnum"]),
        #
        'PeerGroupExportDatabase': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pwzFilePath"]),
        #
        'PeerGroupImportDatabase': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pwzFilePath"]),
        #
        'PeerGroupIssueCredentials': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PEER_CREDENTIAL_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pwzSubjectIdentity", "pCredentialInfo", "dwFlags", "ppwzInvitation"]),
        #
        'PeerGroupExportConfig': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pwzPassword", "ppwzXML"]),
        #
        'PeerGroupImportConfig': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzXML", "pwzPassword", "fOverwrite", "ppwzIdentity", "ppwzGroup"]),
        #
        'PeerGroupPeerTimeToUniversalTime': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pftPeerTime", "pftUniversalTime"]),
        #
        'PeerGroupUniversalTimeToPeerTime': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "pftUniversalTime", "pftPeerTime"]),
        #
        'PeerGroupResumePasswordAuthentication': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hGroup", "hPeerEventHandle"]),
        #
        'PeerIdentityCreate': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzClassifier", "pwzFriendlyName", "hCryptProv", "ppwzIdentity"]),
        #
        'PeerIdentityGetFriendlyName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "ppwzFriendlyName"]),
        #
        'PeerIdentitySetFriendlyName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "pwzFriendlyName"]),
        #
        'PeerIdentityGetCryptKey': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "phCryptProv"]),
        #
        'PeerIdentityDelete': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity"]),
        #
        'PeerEnumIdentities': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phPeerEnum"]),
        #
        'PeerEnumGroups': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "phPeerEnum"]),
        #
        'PeerCreatePeerName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "pwzClassifier", "ppwzPeerName"]),
        #
        'PeerIdentityGetXML': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "ppwzIdentityXML"]),
        #
        'PeerIdentityExport': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzIdentity", "pwzPassword", "ppwzExportXML"]),
        #
        'PeerIdentityImport': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzImportXML", "pwzPassword", "ppwzIdentity"]),
        #
        'PeerIdentityGetDefault': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppwzPeerName"]),
        #
        'PeerCollabStartup': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["wVersionRequested"]),
        #
        'PeerCollabShutdown': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'PeerCollabSignin': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "dwSigninOptions"]),
        #
        'PeerCollabSignout': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwSigninOptions"]),
        #
        'PeerCollabGetSigninOptions': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdwSigninOptions"]),
        #
        'PeerCollabAsyncInviteContact': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_CONTACT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PEER_INVITATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcContact", "pcEndpoint", "pcInvitation", "hEvent", "phInvitation"]),
        #
        'PeerCollabGetInvitationResponse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_INVITATION_RESPONSE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInvitation", "ppInvitationResponse"]),
        #
        'PeerCollabCancelInvitation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInvitation"]),
        #
        'PeerCollabCloseHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hInvitation"]),
        #
        'PeerCollabInviteContact': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_CONTACT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PEER_INVITATION", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_INVITATION_RESPONSE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcContact", "pcEndpoint", "pcInvitation", "ppResponse"]),
        #
        'PeerCollabAsyncInviteEndpoint': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PEER_INVITATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcEndpoint", "pcInvitation", "hEvent", "phInvitation"]),
        #
        'PeerCollabInviteEndpoint': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PEER_INVITATION", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_INVITATION_RESPONSE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcEndpoint", "pcInvitation", "ppResponse"]),
        #
        'PeerCollabGetAppLaunchInfo': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("PEER_APP_LAUNCH_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppLaunchInfo"]),
        #
        'PeerCollabRegisterApplication': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_APPLICATION_REGISTRATION_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="PEER_APPLICATION_REGISTRATION_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["pcApplication", "registrationType"]),
        #
        'PeerCollabUnregisterApplication': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="PEER_APPLICATION_REGISTRATION_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["pApplicationId", "registrationType"]),
        #
        'PeerCollabGetApplicationRegistrationInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="PEER_APPLICATION_REGISTRATION_TYPE"), SimTypePointer(SimTypePointer(SimTypeRef("PEER_APPLICATION_REGISTRATION_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pApplicationId", "registrationType", "ppApplication"]),
        #
        'PeerCollabEnumApplicationRegistrationInfo': SimTypeFunction([SimTypeInt(signed=False, label="PEER_APPLICATION_REGISTRATION_TYPE"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["registrationType", "phPeerEnum"]),
        #
        'PeerCollabGetPresenceInfo': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_PRESENCE_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcEndpoint", "ppPresenceInfo"]),
        #
        'PeerCollabEnumApplications': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcEndpoint", "pApplicationId", "phPeerEnum"]),
        #
        'PeerCollabEnumObjects': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcEndpoint", "pObjectId", "phPeerEnum"]),
        #
        'PeerCollabEnumEndpoints': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_CONTACT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcContact", "phPeerEnum"]),
        #
        'PeerCollabRefreshEndpointData': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcEndpoint"]),
        #
        'PeerCollabDeleteEndpointData': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcEndpoint"]),
        #
        'PeerCollabQueryContactData': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcEndpoint", "ppwzContactData"]),
        #
        'PeerCollabSubscribeEndpointData': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcEndpoint"]),
        #
        'PeerCollabUnsubscribeEndpointData': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_ENDPOINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcEndpoint"]),
        #
        'PeerCollabSetPresenceInfo': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_PRESENCE_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcPresenceInfo"]),
        #
        'PeerCollabGetEndpointName': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppwzEndpointName"]),
        #
        'PeerCollabSetEndpointName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzEndpointName"]),
        #
        'PeerCollabSetObject': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcObject"]),
        #
        'PeerCollabDeleteObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pObjectId"]),
        #
        'PeerCollabRegisterEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PEER_COLLAB_EVENT_REGISTRATION", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent", "cEventRegistration", "pEventRegistrations", "phPeerEvent"]),
        #
        'PeerCollabGetEventData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_COLLAB_EVENT_DATA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEvent", "ppEventData"]),
        #
        'PeerCollabUnregisterEvent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPeerEvent"]),
        #
        'PeerCollabEnumPeopleNearMe': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phPeerEnum"]),
        #
        'PeerCollabAddContact': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_CONTACT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzContactData", "ppContact"]),
        #
        'PeerCollabDeleteContact': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzPeerName"]),
        #
        'PeerCollabGetContact': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_CONTACT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzPeerName", "ppContact"]),
        #
        'PeerCollabUpdateContact': SimTypeFunction([SimTypePointer(SimTypeRef("PEER_CONTACT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pContact"]),
        #
        'PeerCollabEnumContacts': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phPeerEnum"]),
        #
        'PeerCollabExportContact': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzPeerName", "ppwzContactData"]),
        #
        'PeerCollabParseContact': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_CONTACT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzContactData", "ppContact"]),
        #
        'PeerNameToPeerHostName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzPeerName", "ppwzHostName"]),
        #
        'PeerHostNameToPeerName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzHostName", "ppwzPeerName"]),
        #
        'PeerPnrpStartup': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["wVersionRequested"]),
        #
        'PeerPnrpShutdown': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'PeerPnrpRegister': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PEER_PNRP_REGISTRATION_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcwzPeerName", "pRegistrationInfo", "phRegistration"]),
        #
        'PeerPnrpUpdateRegistration': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("PEER_PNRP_REGISTRATION_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRegistration", "pRegistrationInfo"]),
        #
        'PeerPnrpUnregister': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRegistration"]),
        #
        'PeerPnrpResolve': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_PNRP_ENDPOINT_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcwzPeerName", "pcwzCloudName", "pcEndpoints", "ppEndpoints"]),
        #
        'PeerPnrpStartResolve': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcwzPeerName", "pcwzCloudName", "cMaxEndpoints", "hEvent", "phResolve"]),
        #
        'PeerPnrpGetCloudInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_PNRP_CLOUD_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcNumClouds", "ppCloudInfo"]),
        #
        'PeerPnrpGetEndpoint': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PEER_PNRP_ENDPOINT_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hResolve", "ppEndpoint"]),
        #
        'PeerPnrpEndResolve': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hResolve"]),
    }

lib.set_prototypes(prototypes)
