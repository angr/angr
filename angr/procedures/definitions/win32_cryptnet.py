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
lib.set_library_names("cryptnet.dll")
prototypes = \
    {
        #
        'CryptRetrieveObjectByUrlA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CRYPT_CREDENTIALS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CRYPT_RETRIEVE_AUX_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszObjectOid", "dwRetrievalFlags", "dwTimeout", "ppvObject", "hAsyncRetrieve", "pCredentials", "pvVerify", "pAuxInfo"]),
        #
        'CryptRetrieveObjectByUrlW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CRYPT_CREDENTIALS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("CRYPT_RETRIEVE_AUX_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrl", "pszObjectOid", "dwRetrievalFlags", "dwTimeout", "ppvObject", "hAsyncRetrieve", "pCredentials", "pvVerify", "pAuxInfo"]),
        #
        'CryptInstallCancelRetrieval': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pvArg"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfnCancel", "pvArg", "dwFlags", "pvReserved"]),
        #
        'CryptUninstallCancelRetrieval': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwFlags", "pvReserved"]),
        #
        'CryptGetObjectUrl': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="CRYPT_GET_URL_FLAGS"), SimTypePointer(SimTypeRef("CRYPT_URL_ARRAY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("CRYPT_URL_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUrlOid", "pvPara", "dwFlags", "pUrlArray", "pcbUrlArray", "pUrlInfo", "pcbUrlInfo", "pvReserved"]),
    }

lib.set_prototypes(prototypes)
