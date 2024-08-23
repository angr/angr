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
lib.set_library_names("powrprof.dll")
prototypes = \
    {
        #
        'CallNtPowerInformation': SimTypeFunction([SimTypeInt(signed=False, label="POWER_INFORMATION_LEVEL"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["InformationLevel", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength"]),
        #
        'GetPwrCapabilities': SimTypeFunction([SimTypePointer(SimTypeRef("SYSTEM_POWER_CAPABILITIES", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["lpspc"]),
        #
        'PowerDeterminePlatformRoleEx': SimTypeFunction([SimTypeInt(signed=False, label="POWER_PLATFORM_ROLE_VERSION")], SimTypeInt(signed=False, label="POWER_PLATFORM_ROLE"), arg_names=["Version"]),
        #
        'PowerRegisterSuspendResumeNotification': SimTypeFunction([SimTypeInt(signed=False, label="REGISTER_NOTIFICATION_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Flags", "Recipient", "RegistrationHandle"]),
        #
        'PowerUnregisterSuspendResumeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RegistrationHandle"]),
        #
        'PowerReadACValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Type", "Buffer", "BufferSize"]),
        #
        'PowerReadDCValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Type", "Buffer", "BufferSize"]),
        #
        'PowerWriteACValueIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "AcValueIndex"]),
        #
        'PowerWriteDCValueIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "DcValueIndex"]),
        #
        'PowerGetActiveScheme': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["UserRootPowerKey", "ActivePolicyGuid"]),
        #
        'PowerSetActiveScheme': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["UserRootPowerKey", "SchemeGuid"]),
        #
        'PowerSettingRegisterNotification': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="REGISTER_NOTIFICATION_FLAGS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["SettingGuid", "Flags", "Recipient", "RegistrationHandle"]),
        #
        'PowerSettingUnregisterNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RegistrationHandle"]),
        #
        'PowerRegisterForEffectivePowerModeNotifications': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="EFFECTIVE_POWER_MODE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mode", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Version", "Callback", "Context", "RegistrationHandle"]),
        #
        'PowerUnregisterFromEffectivePowerModeNotifications': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RegistrationHandle"]),
        #
        'GetPwrDiskSpindownRange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["puiMax", "puiMin"]),
        #
        'EnumPwrSchemes': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("POWER_POLICY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Index", "NameSize", "Name", "DescriptionSize", "Description", "Policy", "Context"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["lpfn", "lParam"]),
        #
        'ReadGlobalPwrPolicy': SimTypeFunction([SimTypePointer(SimTypeRef("GLOBAL_POWER_POLICY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["pGlobalPowerPolicy"]),
        #
        'ReadPwrScheme': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POWER_POLICY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["uiID", "pPowerPolicy"]),
        #
        'WritePwrScheme': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("POWER_POLICY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["puiID", "lpszSchemeName", "lpszDescription", "lpScheme"]),
        #
        'WriteGlobalPwrPolicy': SimTypeFunction([SimTypePointer(SimTypeRef("GLOBAL_POWER_POLICY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["pGlobalPowerPolicy"]),
        #
        'DeletePwrScheme': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["uiID"]),
        #
        'GetActivePwrScheme': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["puiID"]),
        #
        'SetActivePwrScheme': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GLOBAL_POWER_POLICY", SimStruct), offset=0), SimTypePointer(SimTypeRef("POWER_POLICY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["uiID", "pGlobalPowerPolicy", "pPowerPolicy"]),
        #
        'IsPwrSuspendAllowed': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'IsPwrHibernateAllowed': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'IsPwrShutdownAllowed': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'IsAdminOverrideActive': SimTypeFunction([SimTypePointer(SimTypeRef("ADMINISTRATOR_POWER_POLICY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["papp"]),
        #
        'SetSuspendState': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["bHibernate", "bForce", "bWakeupEventsDisabled"]),
        #
        'GetCurrentPowerPolicies': SimTypeFunction([SimTypePointer(SimTypeRef("GLOBAL_POWER_POLICY", SimStruct), offset=0), SimTypePointer(SimTypeRef("POWER_POLICY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["pGlobalPowerPolicy", "pPowerPolicy"]),
        #
        'CanUserWritePwrScheme': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'ReadProcessorPwrScheme': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MACHINE_PROCESSOR_POWER_POLICY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["uiID", "pMachineProcessorPowerPolicy"]),
        #
        'WriteProcessorPwrScheme': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MACHINE_PROCESSOR_POWER_POLICY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["uiID", "pMachineProcessorPowerPolicy"]),
        #
        'ValidatePowerPolicies': SimTypeFunction([SimTypePointer(SimTypeRef("GLOBAL_POWER_POLICY", SimStruct), offset=0), SimTypePointer(SimTypeRef("POWER_POLICY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["pGlobalPowerPolicy", "pPowerPolicy"]),
        #
        'PowerIsSettingRangeDefined': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeChar(label="Byte"), arg_names=["SubKeyGuid", "SettingGuid"]),
        #
        'PowerSettingAccessCheckEx': SimTypeFunction([SimTypeInt(signed=False, label="POWER_DATA_ACCESSOR"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="REG_SAM_FLAGS")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["AccessFlags", "PowerGuid", "AccessType"]),
        #
        'PowerSettingAccessCheck': SimTypeFunction([SimTypeInt(signed=False, label="POWER_DATA_ACCESSOR"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["AccessFlags", "PowerGuid"]),
        #
        'PowerReadACValueIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "AcValueIndex"]),
        #
        'PowerReadDCValueIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "DcValueIndex"]),
        #
        'PowerReadFriendlyName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Buffer", "BufferSize"]),
        #
        'PowerReadDescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Buffer", "BufferSize"]),
        #
        'PowerReadPossibleValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Type", "PossibleSettingIndex", "Buffer", "BufferSize"]),
        #
        'PowerReadPossibleFriendlyName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "PossibleSettingIndex", "Buffer", "BufferSize"]),
        #
        'PowerReadPossibleDescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "PossibleSettingIndex", "Buffer", "BufferSize"]),
        #
        'PowerReadValueMin': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "ValueMinimum"]),
        #
        'PowerReadValueMax': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "ValueMaximum"]),
        #
        'PowerReadValueIncrement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "ValueIncrement"]),
        #
        'PowerReadValueUnitsSpecifier': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Buffer", "BufferSize"]),
        #
        'PowerReadACDefaultIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RootPowerKey", "SchemePersonalityGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "AcDefaultIndex"]),
        #
        'PowerReadDCDefaultIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RootPowerKey", "SchemePersonalityGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "DcDefaultIndex"]),
        #
        'PowerReadIconResourceSpecifier': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Buffer", "BufferSize"]),
        #
        'PowerReadSettingAttributes': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SubGroupGuid", "PowerSettingGuid"]),
        #
        'PowerWriteFriendlyName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Buffer", "BufferSize"]),
        #
        'PowerWriteDescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Buffer", "BufferSize"]),
        #
        'PowerWritePossibleValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Type", "PossibleSettingIndex", "Buffer", "BufferSize"]),
        #
        'PowerWritePossibleFriendlyName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "PossibleSettingIndex", "Buffer", "BufferSize"]),
        #
        'PowerWritePossibleDescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "PossibleSettingIndex", "Buffer", "BufferSize"]),
        #
        'PowerWriteValueMin': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "ValueMinimum"]),
        #
        'PowerWriteValueMax': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "ValueMaximum"]),
        #
        'PowerWriteValueIncrement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "ValueIncrement"]),
        #
        'PowerWriteValueUnitsSpecifier': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Buffer", "BufferSize"]),
        #
        'PowerWriteACDefaultIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RootSystemPowerKey", "SchemePersonalityGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "DefaultAcIndex"]),
        #
        'PowerWriteDCDefaultIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RootSystemPowerKey", "SchemePersonalityGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "DefaultDcIndex"]),
        #
        'PowerWriteIconResourceSpecifier': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "Buffer", "BufferSize"]),
        #
        'PowerWriteSettingAttributes': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["SubGroupGuid", "PowerSettingGuid", "Attributes"]),
        #
        'PowerDuplicateScheme': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SourceSchemeGuid", "DestinationSchemeGuid"]),
        #
        'PowerImportPowerScheme': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "ImportFileNamePath", "DestinationSchemeGuid"]),
        #
        'PowerDeleteScheme': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SchemeGuid"]),
        #
        'PowerRemovePowerSetting': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["PowerSettingSubKeyGuid", "PowerSettingGuid"]),
        #
        'PowerCreateSetting': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootSystemPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid"]),
        #
        'PowerCreatePossibleSetting': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootSystemPowerKey", "SubGroupOfPowerSettingsGuid", "PowerSettingGuid", "PossibleSettingIndex"]),
        #
        'PowerEnumerate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="POWER_DATA_ACCESSOR"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["RootPowerKey", "SchemeGuid", "SubGroupOfPowerSettingsGuid", "AccessFlags", "Index", "Buffer", "BufferSize"]),
        #
        'PowerOpenUserPowerKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["phUserPowerKey", "Access", "OpenExisting"]),
        #
        'PowerOpenSystemPowerKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["phSystemPowerKey", "Access", "OpenExisting"]),
        #
        'PowerCanRestoreIndividualDefaultPowerScheme': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["SchemeGuid"]),
        #
        'PowerRestoreIndividualDefaultPowerScheme': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["SchemeGuid"]),
        #
        'PowerRestoreDefaultPowerSchemes': SimTypeFunction([], SimTypeInt(signed=False, label="WIN32_ERROR")),
        #
        'PowerReplaceDefaultPowerSchemes': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'PowerDeterminePlatformRole': SimTypeFunction([], SimTypeInt(signed=False, label="POWER_PLATFORM_ROLE")),
        #
        'DevicePowerEnumDevices': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["QueryIndex", "QueryInterpretationFlags", "QueryFlags", "pReturnBuffer", "pBufferSize"]),
        #
        'DevicePowerSetDeviceState': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DeviceDescription", "SetFlags", "SetData"]),
        #
        'DevicePowerOpen': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["DebugMask"]),
        #
        'DevicePowerClose': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'PowerReportThermalEvent': SimTypeFunction([SimTypePointer(SimTypeRef("THERMAL_EVENT", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Event"]),
    }

lib.set_prototypes(prototypes)
