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
lib.set_library_names("keycredmgr.dll")
prototypes = \
    {
        #
        'KeyCredentialManagerGetOperationErrorStates': SimTypeFunction([SimTypeInt(signed=False, label="KeyCredentialManagerOperationType"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="KeyCredentialManagerOperationErrorStates"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["keyCredentialManagerOperationType", "isReady", "keyCredentialManagerOperationErrorStates"]),
        #
        'KeyCredentialManagerShowUIOperation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="KeyCredentialManagerOperationType")], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndOwner", "keyCredentialManagerOperationType"]),
        #
        'KeyCredentialManagerGetInformation': SimTypeFunction([SimTypePointer(SimTypePointer(SimStruct({"containerId": SimTypeBottom(label="Guid")}, name="KeyCredentialManagerInfo", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["keyCredentialManagerInfo"]),
        #
        'KeyCredentialManagerFreeInformation': SimTypeFunction([SimTypePointer(SimStruct({"containerId": SimTypeBottom(label="Guid")}, name="KeyCredentialManagerInfo", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["keyCredentialManagerInfo"]),
    }

lib.set_prototypes(prototypes)
