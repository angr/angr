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
lib.set_library_names("newdev.dll")
prototypes = \
    {
        #
        'UpdateDriverForPlugAndPlayDevicesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "HardwareId", "FullInfPath", "InstallFlags", "bRebootRequired"]),
        #
        'UpdateDriverForPlugAndPlayDevicesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "HardwareId", "FullInfPath", "InstallFlags", "bRebootRequired"]),
        #
        'DiInstallDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "ClassGuid": SimTypeBottom(label="Guid"), "DevInst": SimTypeInt(signed=False, label="UInt32"), "Reserved": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="SP_DEVINFO_DATA", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "DriverType": SimTypeInt(signed=False, label="UInt32"), "Reserved": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "Description": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 256), "MfgName": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 256), "ProviderName": SimTypeFixedSizeArray(SimTypeBottom(label="CHAR"), 256), "DriverDate": SimTypeBottom(label="FILETIME"), "DriverVersion": SimTypeLongLong(signed=False, label="UInt64")}, name="SP_DRVINFO_DATA_V2_A", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "DeviceInfoSet", "DeviceInfoData", "DriverInfoData", "Flags", "NeedReboot"]),
        #
        'DiInstallDriverW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "InfPath", "Flags", "NeedReboot"]),
        #
        'DiInstallDriverA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "InfPath", "Flags", "NeedReboot"]),
        #
        'DiUninstallDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "ClassGuid": SimTypeBottom(label="Guid"), "DevInst": SimTypeInt(signed=False, label="UInt32"), "Reserved": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="SP_DEVINFO_DATA", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "DeviceInfoSet", "DeviceInfoData", "Flags", "NeedReboot"]),
        #
        'DiUninstallDriverW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "InfPath", "Flags", "NeedReboot"]),
        #
        'DiUninstallDriverA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "InfPath", "Flags", "NeedReboot"]),
        #
        'DiShowUpdateDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "ClassGuid": SimTypeBottom(label="Guid"), "DevInst": SimTypeInt(signed=False, label="UInt32"), "Reserved": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="SP_DEVINFO_DATA", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "DeviceInfoSet", "DeviceInfoData", "Flags", "NeedReboot"]),
        #
        'DiRollbackDriver': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "ClassGuid": SimTypeBottom(label="Guid"), "DevInst": SimTypeInt(signed=False, label="UInt32"), "Reserved": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="SP_DEVINFO_DATA", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceInfoSet", "DeviceInfoData", "hwndParent", "Flags", "NeedReboot"]),
        #
        'DiShowUpdateDriver': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "FilePath", "Flags", "NeedReboot"]),
    }

lib.set_prototypes(prototypes)
