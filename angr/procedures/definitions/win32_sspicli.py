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
lib.set_library_names("sspicli.dll")
prototypes = \
    {
        #
        'QueryContextAttributesExW': SimTypeFunction([SimTypePointer(SimStruct({"dwLower": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "dwUpper": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="SecHandle", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="SECPKG_ATTR"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "ulAttribute", "pBuffer", "cbBuffer"]),
        #
        'QueryContextAttributesExA': SimTypeFunction([SimTypePointer(SimStruct({"dwLower": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "dwUpper": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="SecHandle", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="SECPKG_ATTR"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "ulAttribute", "pBuffer", "cbBuffer"]),
        #
        'QueryCredentialsAttributesExW': SimTypeFunction([SimTypePointer(SimStruct({"dwLower": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "dwUpper": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="SecHandle", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "ulAttribute", "pBuffer", "cbBuffer"]),
        #
        'QueryCredentialsAttributesExA': SimTypeFunction([SimTypePointer(SimStruct({"dwLower": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "dwUpper": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="SecHandle", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phCredential", "ulAttribute", "pBuffer", "cbBuffer"]),
        #
        'SspiEncryptAuthIdentityEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Options", "AuthData"]),
        #
        'SspiDecryptAuthIdentityEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Options", "EncryptedAuthData"]),
    }

lib.set_prototypes(prototypes)
