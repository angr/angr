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
lib.set_library_names("api-ms-win-core-winrt-roparameterizediid-l1-1-0.dll")
prototypes = \
    {
        #
        'RoGetParameterizedTypeInstanceIID': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeBottom(label="IRoMetaDataLocator"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nameElementCount", "nameElements", "metaDataLocator", "iid", "pExtra"]),
        #
        'RoFreeParameterizedTypeExtra': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["extra"]),
        #
        'RoParameterizedTypeExtraGetTypeSignature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["extra"]),
    }

lib.set_prototypes(prototypes)
