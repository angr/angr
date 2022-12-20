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
        'SslCrackCertificate': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimStruct({"Version": SimTypeInt(signed=False, label="UInt32"), "SerialNumber": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 4), "SignatureAlgorithm": SimTypeInt(signed=False, label="UInt32"), "ValidFrom": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "ValidUntil": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "pszIssuer": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pszSubject": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pPublicKey": SimTypePointer(SimStruct({"Type": SimTypeInt(signed=False, label="UInt32"), "cbKey": SimTypeInt(signed=False, label="UInt32"), "pKey": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="PctPublicKey", pack=False, align=None), offset=0)}, name="X509Certificate", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbCertificate", "cbCertificate", "dwFlags", "ppCertificate"]),
        #
        'SslFreeCertificate': SimTypeFunction([SimTypePointer(SimStruct({"Version": SimTypeInt(signed=False, label="UInt32"), "SerialNumber": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 4), "SignatureAlgorithm": SimTypeInt(signed=False, label="UInt32"), "ValidFrom": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "ValidUntil": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "pszIssuer": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pszSubject": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pPublicKey": SimTypePointer(SimStruct({"Type": SimTypeInt(signed=False, label="UInt32"), "cbKey": SimTypeInt(signed=False, label="UInt32"), "pKey": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="PctPublicKey", pack=False, align=None), offset=0)}, name="X509Certificate", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["pCertificate"]),
        #
        'SslGetMaximumKeySize': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Reserved"]),
        #
        'SslGetServerIdentity': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ClientHello", "ClientHelloSize", "ServerIdentity", "ServerIdentitySize", "Flags"]),
        #
        'SslGetExtensions': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"ExtensionType": SimTypeShort(signed=False, label="UInt16"), "pExtData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "cbExtData": SimTypeInt(signed=False, label="UInt32")}, name="SCH_EXTENSION_DATA", pack=False, align=None), label="LPArray", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="SchGetExtensionsOptions")], SimTypeInt(signed=True, label="Int32"), arg_names=["clientHello", "clientHelloByteSize", "genericExtensions", "genericExtensionsCount", "bytesToRead", "flags"]),
    }

lib.set_prototypes(prototypes)
