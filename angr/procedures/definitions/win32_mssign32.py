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
lib.set_library_names("mssign32.dll")
prototypes = \
    {
        #
        'SignError': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SignerFreeSignerContext': SimTypeFunction([SimTypePointer(SimTypeRef("SIGNER_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSignerContext"]),
        #
        'SignerSign': SimTypeFunction([SimTypePointer(SimTypeRef("SIGNER_SUBJECT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_CERT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_SIGNATURE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_PROVIDER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSubjectInfo", "pSignerCert", "pSignatureInfo", "pProviderInfo", "pwszHttpTimeStamp", "psRequest", "pSipData"]),
        #
        'SignerSignEx': SimTypeFunction([SimTypeInt(signed=False, label="SIGNER_SIGN_FLAGS"), SimTypePointer(SimTypeRef("SIGNER_SUBJECT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_CERT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_SIGNATURE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_PROVIDER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SIGNER_CONTEXT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pSubjectInfo", "pSignerCert", "pSignatureInfo", "pProviderInfo", "pwszHttpTimeStamp", "psRequest", "pSipData", "ppSignerContext"]),
        #
        'SignerSignEx2': SimTypeFunction([SimTypeInt(signed=False, label="SIGNER_SIGN_FLAGS"), SimTypePointer(SimTypeRef("SIGNER_SUBJECT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_CERT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_SIGNATURE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_PROVIDER_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="SIGNER_TIMESTAMP_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SIGNER_CONTEXT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("CERT_STRONG_SIGN_PARA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pSubjectInfo", "pSignerCert", "pSignatureInfo", "pProviderInfo", "dwTimestampFlags", "pszTimestampAlgorithmOid", "pwszHttpTimeStamp", "psRequest", "pSipData", "ppSignerContext", "pCryptoPolicy", "pReserved"]),
        #
        'SignerSignEx3': SimTypeFunction([SimTypeInt(signed=False, label="SIGNER_SIGN_FLAGS"), SimTypePointer(SimTypeRef("SIGNER_SUBJECT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_CERT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_SIGNATURE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_PROVIDER_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="SIGNER_TIMESTAMP_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SIGNER_CONTEXT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("CERT_STRONG_SIGN_PARA", SimStruct), offset=0), SimTypePointer(SimTypeRef("SIGNER_DIGEST_SIGN_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pSubjectInfo", "pSignerCert", "pSignatureInfo", "pProviderInfo", "dwTimestampFlags", "pszTimestampAlgorithmOid", "pwszHttpTimeStamp", "psRequest", "pSipData", "ppSignerContext", "pCryptoPolicy", "pDigestSignInfo", "pReserved"]),
        #
        'SignerTimeStamp': SimTypeFunction([SimTypePointer(SimTypeRef("SIGNER_SUBJECT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSubjectInfo", "pwszHttpTimeStamp", "psRequest", "pSipData"]),
        #
        'SignerTimeStampEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SIGNER_SUBJECT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SIGNER_CONTEXT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pSubjectInfo", "pwszHttpTimeStamp", "psRequest", "pSipData", "ppSignerContext"]),
        #
        'SignerTimeStampEx2': SimTypeFunction([SimTypeInt(signed=False, label="SIGNER_TIMESTAMP_FLAGS"), SimTypePointer(SimTypeRef("SIGNER_SUBJECT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="ALG_ID"), SimTypePointer(SimTypeRef("CRYPT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SIGNER_CONTEXT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pSubjectInfo", "pwszHttpTimeStamp", "dwAlgId", "psRequest", "pSipData", "ppSignerContext"]),
        #
        'SignerTimeStampEx3': SimTypeFunction([SimTypeInt(signed=False, label="SIGNER_TIMESTAMP_FLAGS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SIGNER_SUBJECT_INFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("CRYPT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SIGNER_CONTEXT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("CERT_STRONG_SIGN_PARA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "dwIndex", "pSubjectInfo", "pwszHttpTimeStamp", "pszAlgorithmOid", "psRequest", "pSipData", "ppSignerContext", "pCryptoPolicy", "pReserved"]),
    }

lib.set_prototypes(prototypes)
