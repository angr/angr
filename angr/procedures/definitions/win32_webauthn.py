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
lib.set_library_names("webauthn.dll")
prototypes = \
    {
        #
        'WebAuthNGetApiVersionNumber': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbIsUserVerifyingPlatformAuthenticatorAvailable"]),
        #
        'WebAuthNAuthenticatorMakeCredential': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WEBAUTHN_RP_ENTITY_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("WEBAUTHN_USER_ENTITY_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("WEBAUTHN_COSE_CREDENTIAL_PARAMETERS", SimStruct), offset=0), SimTypePointer(SimTypeRef("WEBAUTHN_CLIENT_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("WEBAUTHN_CREDENTIAL_ATTESTATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pRpInformation", "pUserInformation", "pPubKeyCredParams", "pWebAuthNClientData", "pWebAuthNMakeCredentialOptions", "ppWebAuthNCredentialAttestation"]),
        #
        'WebAuthNAuthenticatorGetAssertion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WEBAUTHN_CLIENT_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("WEBAUTHN_ASSERTION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "pwszRpId", "pWebAuthNClientData", "pWebAuthNGetAssertionOptions", "ppWebAuthNAssertion"]),
        #
        'WebAuthNFreeCredentialAttestation': SimTypeFunction([SimTypePointer(SimTypeRef("WEBAUTHN_CREDENTIAL_ATTESTATION", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pWebAuthNCredentialAttestation"]),
        #
        'WebAuthNFreeAssertion': SimTypeFunction([SimTypePointer(SimTypeRef("WEBAUTHN_ASSERTION", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pWebAuthNAssertion"]),
        #
        'WebAuthNGetCancellationId': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCancellationId"]),
        #
        'WebAuthNCancelCurrentOperation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCancellationId"]),
        #
        'WebAuthNGetPlatformCredentialList': SimTypeFunction([SimTypePointer(SimTypeRef("WEBAUTHN_GET_CREDENTIALS_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("WEBAUTHN_CREDENTIAL_DETAILS_LIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pGetCredentialsOptions", "ppCredentialDetailsList"]),
        #
        'WebAuthNFreePlatformCredentialList': SimTypeFunction([SimTypePointer(SimTypeRef("WEBAUTHN_CREDENTIAL_DETAILS_LIST", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pCredentialDetailsList"]),
        #
        'WebAuthNDeletePlatformCredential': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbCredentialId", "pbCredentialId"]),
        #
        'WebAuthNGetErrorName': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["hr"]),
        #
        'WebAuthNGetW3CExceptionDOMError': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hr"]),
    }

lib.set_prototypes(prototypes)
