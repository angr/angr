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
lib.set_library_names("aclui.dll")
prototypes = \
    {
        # 
        'CreateSecurityPage': SimTypeFunction([SimTypeBottom(label="ISecurityInformation")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["psi"]),
        # 
        'EditSecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="ISecurityInformation")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndOwner", "psi"]),
        # 
        'EditSecurityAdvanced': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="ISecurityInformation"), SimTypeInt(signed=False, label="SI_PAGE_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndOwner", "psi", "uSIPage"]),
    }

lib.set_prototypes(prototypes)
