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
lib.set_library_names("schannel.dll")
prototypes = \
    {
        #
        'SslEmptyCacheA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszTargetName", "dwFlags"]),
        #
        'SslEmptyCacheW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszTargetName", "dwFlags"]),
        #
        'SslGenerateRandomBits': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pRandomData", "cRandomData"]),
        #
        'SslCrackCertificate': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("X509Certificate", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbCertificate", "cbCertificate", "dwFlags", "ppCertificate"]),
        #
        'SslFreeCertificate': SimTypeFunction([SimTypePointer(SimTypeRef("X509Certificate", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pCertificate"]),
        #
        'SslGetMaximumKeySize': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Reserved"]),
        #
        'SslGetServerIdentity': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ClientHello", "ClientHelloSize", "ServerIdentity", "ServerIdentitySize", "Flags"]),
        #
        'SslGetExtensions': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SCH_EXTENSION_DATA", SimStruct), label="LPArray", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="SchGetExtensionsOptions")], SimTypeInt(signed=True, label="Int32"), arg_names=["clientHello", "clientHelloByteSize", "genericExtensions", "genericExtensionsCount", "bytesToRead", "flags"]),
        #
        'SslDeserializeCertificateStore': SimTypeFunction([SimTypeRef("CRYPT_INTEGER_BLOB", SimStruct), SimTypePointer(SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SerializedCertificateStore", "ppCertContext"]),
    }

lib.set_prototypes(prototypes)
