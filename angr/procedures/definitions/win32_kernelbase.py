# pylint:disable=line-too-long
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
lib.set_library_names("kernelbase.dll")
prototypes = \
    {
        #
        'TryCreatePackageDependency': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("PACKAGE_VERSION", SimStruct), SimTypeInt(signed=False, label="PackageDependencyProcessorArchitectures"), SimTypeInt(signed=False, label="PackageDependencyLifetimeKind"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="CreatePackageDependencyOptions"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["user", "packageFamilyName", "minVersion", "packageDependencyProcessorArchitectures", "lifetimeKind", "lifetimeArtifact", "options", "packageDependencyId"]),
        #
        'DeletePackageDependency': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageDependencyId"]),
        #
        'AddPackageDependency': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="AddPackageDependencyOptions"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageDependencyId", "rank", "options", "packageDependencyContext", "packageFullName"]),
        #
        'RemovePackageDependency': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageDependencyContext"]),
        #
        'GetResolvedPackageFullNameForPackageDependency': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageDependencyId", "packageFullName"]),
        #
        'GetIdForPackageDependencyContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageDependencyContext", "packageDependencyId"]),
    }

lib.set_prototypes(prototypes)
