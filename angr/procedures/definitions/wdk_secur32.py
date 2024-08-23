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
lib.set_library_names("secur32.dll")
prototypes = \
    {
        #
        'CompleteAuthToken': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "pToken"]),
        #
        'QuerySecurityContextToken': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "Token"]),
        #
        'ApplyControlToken': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "pInput"]),
        #
        'SetContextAttributesW': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "ulAttribute", "pBuffer", "cbBuffer"]),
        #
        'MakeSignature': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "fQOP", "pMessage", "MessageSeqNo"]),
        #
        'VerifySignature': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypePointer(SimTypeRef("SecBufferDesc", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "pMessage", "MessageSeqNo", "pfQOP"]),
        #
        'ExportSecurityContext': SimTypeFunction([SimTypePointer(SimTypeRef("SecHandle", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SecBuffer", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phContext", "fFlags", "pPackedContext", "pToken"]),
        #
        'GetSecurityUserInfo': SimTypeFunction([SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("SECURITY_USER_DATA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogonId", "Flags", "UserInformation"]),
    }

lib.set_prototypes(prototypes)
