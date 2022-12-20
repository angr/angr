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
lib.set_library_names("gpedit.dll")
prototypes = \
    {
        #
        'CreateGPOLink': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpGPO", "lpContainer", "fHighPriority"]),
        #
        'DeleteGPOLink': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpGPO", "lpContainer"]),
        #
        'DeleteAllGPOLinks': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpContainer"]),
        #
        'BrowseForGPO': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hwndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpTitle": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpInitialOU": SimTypePointer(SimTypeChar(label="Char"), offset=0), "lpDSPath": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwDSPathSize": SimTypeInt(signed=False, label="UInt32"), "lpName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwNameSize": SimTypeInt(signed=False, label="UInt32"), "gpoType": SimTypeInt(signed=False, label="GROUP_POLICY_OBJECT_TYPE"), "gpoHint": SimTypeInt(signed=False, label="GROUP_POLICY_HINT_TYPE")}, name="GPOBROWSEINFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpBrowseInfo"]),
        #
        'ImportRSoPData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpNameSpace", "lpFileName"]),
        #
        'ExportRSoPData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpNameSpace", "lpFileName"]),
    }

lib.set_prototypes(prototypes)
