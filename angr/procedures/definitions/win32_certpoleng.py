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
lib.set_library_names("certpoleng.dll")
prototypes = \
    {
        #
        'PstGetTrustAnchors': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CERT_SELECT_CRITERIA", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SecPkgContext_IssuerListInfoEx", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pTargetName", "cCriteria", "rgpCriteria", "ppTrustedIssuers"]),
        #
        'PstGetTrustAnchorsEx': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CERT_SELECT_CRITERIA", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SecPkgContext_IssuerListInfoEx", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pTargetName", "cCriteria", "rgpCriteria", "pCertContext", "ppTrustedIssuers"]),
        #
        'PstGetCertificateChain': SimTypeFunction([SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecPkgContext_IssuerListInfoEx", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CERT_CHAIN_CONTEXT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCert", "pTrustedIssuers", "ppCertChainContext"]),
        #
        'PstGetCertificates': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CERT_SELECT_CRITERIA", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("CERT_CHAIN_CONTEXT", SimStruct), offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pTargetName", "cCriteria", "rgpCriteria", "bIsClient", "pdwCertChainContextCount", "ppCertChainContexts"]),
        #
        'PstAcquirePrivateKey': SimTypeFunction([SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCert"]),
        #
        'PstValidate': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("CERT_USAGE_MATCH", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pTargetName", "bIsClient", "pRequestedIssuancePolicy", "phAdditionalCertStore", "pCert", "pProvGUID"]),
        #
        'PstMapCertificate': SimTypeFunction([SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="LSA_TOKEN_INFORMATION_TYPE"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCert", "pTokenInformationType", "ppTokenInformation"]),
        #
        'PstGetUserNameForCertificate': SimTypeFunction([SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCertContext", "UserName"]),
    }

lib.set_prototypes(prototypes)
