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
