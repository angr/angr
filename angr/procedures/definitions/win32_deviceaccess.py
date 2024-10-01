# pylint:disable=line-too-long
from __future__ import annotations
import logging
from collections import OrderedDict

from angr.sim_type import SimTypeFunction, SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat, SimTypePointer, SimTypeChar, SimStruct, SimTypeArray, SimTypeBottom, SimUnion, SimTypeBool, SimTypeRef
from angr.calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from angr.procedures import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.type_collection_names = ["win32"]
lib.set_default_cc("X86", SimCCStdcall)
lib.set_default_cc("AMD64", SimCCMicrosoftAMD64)
lib.set_library_names("deviceaccess.dll")
prototypes = \
    {
        #
        'CreateDeviceAccessInstance': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ICreateDeviceAccessAsync"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["deviceInterfacePath", "desiredAccess", "createAsync"]),
    }

lib.set_prototypes(prototypes)
