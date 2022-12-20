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
lib.set_library_names("wofutil.dll")
prototypes = \
    {
        #
        'WofShouldCompressBinaries': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Volume", "Algorithm"]),
        #
        'WofGetDriverVersion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileOrVolumeHandle", "Provider", "WofVersion"]),
        #
        'WofSetFileDataLocation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Provider", "ExternalFileInfo", "Length"]),
        #
        'WofIsExternalFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilePath", "IsExternalFile", "Provider", "ExternalFileInfo", "BufferLength"]),
        #
        'WofEnumEntries': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EntryInfo", "UserData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeName", "Provider", "EnumProc", "UserData"]),
        #
        'WofWimAddEntry': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeName", "WimPath", "WimType", "WimIndex", "DataSourceId"]),
        #
        'WofWimEnumFiles': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilePath", "ExternalFileInfo", "UserData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeName", "DataSourceId", "EnumProc", "UserData"]),
        #
        'WofWimSuspendEntry': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None")], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeName", "DataSourceId"]),
        #
        'WofWimRemoveEntry': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None")], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeName", "DataSourceId"]),
        #
        'WofWimUpdateEntry': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=True, label="Int64")}, name="<anon>", label="None"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeName", "DataSourceId", "NewWimPath"]),
        #
        'WofFileEnumFiles': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilePath", "ExternalFileInfo", "UserData"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeName", "Algorithm", "EnumProc", "UserData"]),
    }

lib.set_prototypes(prototypes)
