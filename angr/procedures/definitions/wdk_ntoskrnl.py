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
lib.add_all_from_dict(P["win32_kernel"])
lib.set_library_names("ntoskrnl.exe")
prototypes = \
    {
        #
        'NtQueryObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="OBJECT_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "ObjectInformationClass", "ObjectInformation", "ObjectInformationLength", "ReturnLength"]),
        #
        'NtClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'NtCancelIoFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoRequestToCancel", "IoStatusBlock"]),
        #
        'NtOpenThreadToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle", "DesiredAccess", "OpenAsSelf", "TokenHandle"]),
        #
        'NtOpenThreadTokenEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle", "DesiredAccess", "OpenAsSelf", "HandleAttributes", "TokenHandle"]),
        #
        'NtOpenProcessToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "DesiredAccess", "TokenHandle"]),
        #
        'NtOpenProcessTokenEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "DesiredAccess", "HandleAttributes", "TokenHandle"]),
        #
        'NtDuplicateToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="TOKEN_TYPE"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExistingTokenHandle", "DesiredAccess", "ObjectAttributes", "EffectiveOnly", "TokenType", "NewTokenHandle"]),
        #
        'NtFilterToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TOKEN_GROUPS", SimStruct), offset=0), SimTypePointer(SimTypeRef("TOKEN_PRIVILEGES", SimStruct), offset=0), SimTypePointer(SimTypeRef("TOKEN_GROUPS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExistingTokenHandle", "Flags", "SidsToDisable", "PrivilegesToDelete", "RestrictedSids", "NewTokenHandle"]),
        #
        'NtImpersonateAnonymousToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle"]),
        #
        'NtQueryInformationToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TOKEN_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "TokenInformationClass", "TokenInformation", "TokenInformationLength", "ReturnLength"]),
        #
        'NtSetInformationToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TOKEN_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "TokenInformationClass", "TokenInformation", "TokenInformationLength"]),
        #
        'NtAdjustPrivilegesToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("TOKEN_PRIVILEGES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TOKEN_PRIVILEGES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "DisableAllPrivileges", "NewState", "BufferLength", "PreviousState", "ReturnLength"]),
        #
        'NtAdjustGroupsToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("TOKEN_GROUPS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TOKEN_GROUPS", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "ResetToDefault", "NewState", "BufferLength", "PreviousState", "ReturnLength"]),
        #
        'NtPrivilegeCheck': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ClientToken", "RequiredPrivileges", "Result"]),
        #
        'NtAccessCheckAndAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "DesiredAccess", "GenericMapping", "ObjectCreation", "GrantedAccess", "AccessStatus", "GenerateOnClose"]),
        #
        'NtAccessCheckByTypeAndAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="AUDIT_EVENT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "PrincipalSelfSid", "DesiredAccess", "AuditType", "Flags", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "ObjectCreation", "GrantedAccess", "AccessStatus", "GenerateOnClose"]),
        #
        'NtAccessCheckByTypeResultListAndAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="AUDIT_EVENT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "PrincipalSelfSid", "DesiredAccess", "AuditType", "Flags", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "ObjectCreation", "GrantedAccess", "AccessStatus", "GenerateOnClose"]),
        #
        'NtAccessCheckByTypeResultListAndAuditAlarmByHandle': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="AUDIT_EVENT_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_TYPE_LIST", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ClientToken", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "PrincipalSelfSid", "DesiredAccess", "AuditType", "Flags", "ObjectTypeList", "ObjectTypeListLength", "GenericMapping", "ObjectCreation", "GrantedAccess", "AccessStatus", "GenerateOnClose"]),
        #
        'NtOpenObjectAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ObjectTypeName", "ObjectName", "SecurityDescriptor", "ClientToken", "DesiredAccess", "GrantedAccess", "Privileges", "ObjectCreation", "AccessGranted", "GenerateOnClose"]),
        #
        'NtPrivilegeObjectAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "ClientToken", "DesiredAccess", "Privileges", "AccessGranted"]),
        #
        'NtCloseObjectAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "GenerateOnClose"]),
        #
        'NtDeleteObjectAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "HandleId", "GenerateOnClose"]),
        #
        'NtPrivilegedServiceAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["SubsystemName", "ServiceName", "ClientToken", "Privileges", "AccessGranted"]),
        #
        'RtlCreateHeap': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RTL_HEAP_PARAMETERS", SimStruct), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Flags", "HeapBase", "ReserveSize", "CommitSize", "Lock", "Parameters"]),
        #
        'RtlDestroyHeap': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["HeapHandle"]),
        #
        'RtlAllocateHeap': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["HeapHandle", "Flags", "Size"]),
        #
        'RtlFreeHeap': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["HeapHandle", "Flags", "BaseAddress"]),
        #
        'RtlRandom': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Seed"]),
        #
        'RtlRandomEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Seed"]),
        #
        'RtlInitUnicodeStringEx': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlCreateUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlPrefixString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["String1", "String2", "CaseInSensitive"]),
        #
        'RtlAppendStringToString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Destination", "Source"]),
        #
        'RtlOemStringToUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlUpcaseUnicodeStringToOemString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlOemStringToCountedUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlUnicodeStringToCountedOemString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlUpcaseUnicodeStringToCountedOemString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlValidateUnicodeString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "String"]),
        #
        'RtlDuplicateUnicodeString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "StringIn", "StringOut"]),
        #
        'RtlDowncaseUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlxUnicodeStringToOemSize': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UnicodeString"]),
        #
        'RtlxOemStringToUnicodeSize': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["OemString"]),
        #
        'RtlMultiByteToUnicodeN': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["UnicodeString", "MaxBytesInUnicodeString", "BytesInUnicodeString", "MultiByteString", "BytesInMultiByteString"]),
        #
        'RtlMultiByteToUnicodeSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["BytesInUnicodeString", "MultiByteString", "BytesInMultiByteString"]),
        #
        'RtlUnicodeToMultiByteN': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["MultiByteString", "MaxBytesInMultiByteString", "BytesInMultiByteString", "UnicodeString", "BytesInUnicodeString"]),
        #
        'RtlUpcaseUnicodeToMultiByteN': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["MultiByteString", "MaxBytesInMultiByteString", "BytesInMultiByteString", "UnicodeString", "BytesInUnicodeString"]),
        #
        'RtlOemToUnicodeN': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["UnicodeString", "MaxBytesInUnicodeString", "BytesInUnicodeString", "OemString", "BytesInOemString"]),
        #
        'RtlUnicodeToOemN': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["OemString", "MaxBytesInOemString", "BytesInOemString", "UnicodeString", "BytesInUnicodeString"]),
        #
        'RtlUpcaseUnicodeToOemN': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["OemString", "MaxBytesInOemString", "BytesInOemString", "UnicodeString", "BytesInUnicodeString"]),
        #
        'RtlNormalizeString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NormForm", "SourceString", "SourceStringLength", "DestinationString", "DestinationStringLength"]),
        #
        'RtlIsNormalizedString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NormForm", "SourceString", "SourceStringLength", "Normalized"]),
        #
        'RtlIdnToAscii': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "SourceString", "SourceStringLength", "DestinationString", "DestinationStringLength"]),
        #
        'RtlIdnToUnicode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "SourceString", "SourceStringLength", "DestinationString", "DestinationStringLength"]),
        #
        'RtlIdnToNameprepUnicode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "SourceString", "SourceStringLength", "DestinationString", "DestinationStringLength"]),
        #
        'RtlGenerate8dot3Name': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("GENERATE_NAME_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Name", "AllowExtendedCharacters", "Context", "Name8dot3"]),
        #
        'RtlIsValidOemCharacter': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Char"]),
        #
        'PfxInitialize': SimTypeFunction([SimTypePointer(SimTypeRef("PREFIX_TABLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PrefixTable"]),
        #
        'PfxInsertPrefix': SimTypeFunction([SimTypePointer(SimTypeRef("PREFIX_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("PREFIX_TABLE_ENTRY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["PrefixTable", "Prefix", "PrefixTableEntry"]),
        #
        'PfxRemovePrefix': SimTypeFunction([SimTypePointer(SimTypeRef("PREFIX_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("PREFIX_TABLE_ENTRY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PrefixTable", "PrefixTableEntry"]),
        #
        'PfxFindPrefix': SimTypeFunction([SimTypePointer(SimTypeRef("PREFIX_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypePointer(SimTypeRef("PREFIX_TABLE_ENTRY", SimStruct), offset=0), arg_names=["PrefixTable", "FullName"]),
        #
        'RtlInitializeUnicodePrefix': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_PREFIX_TABLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PrefixTable"]),
        #
        'RtlInsertUnicodePrefix': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_PREFIX_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_PREFIX_TABLE_ENTRY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["PrefixTable", "Prefix", "PrefixTableEntry"]),
        #
        'RtlRemoveUnicodePrefix': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_PREFIX_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_PREFIX_TABLE_ENTRY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PrefixTable", "PrefixTableEntry"]),
        #
        'RtlFindUnicodePrefix': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_PREFIX_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("UNICODE_PREFIX_TABLE_ENTRY", SimStruct), offset=0), arg_names=["PrefixTable", "FullName", "CaseInsensitiveIndex"]),
        #
        'RtlNextUnicodePrefix': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_PREFIX_TABLE", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeRef("UNICODE_PREFIX_TABLE_ENTRY", SimStruct), offset=0), arg_names=["PrefixTable", "Restart"]),
        #
        'RtlGetCompressionWorkSpaceSize': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormatAndEngine", "CompressBufferWorkSpaceSize", "CompressFragmentWorkSpaceSize"]),
        #
        'RtlCompressBuffer': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormatAndEngine", "UncompressedBuffer", "UncompressedBufferSize", "CompressedBuffer", "CompressedBufferSize", "UncompressedChunkSize", "FinalCompressedSize", "WorkSpace"]),
        #
        'RtlDecompressBuffer': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormat", "UncompressedBuffer", "UncompressedBufferSize", "CompressedBuffer", "CompressedBufferSize", "FinalUncompressedSize"]),
        #
        'RtlDecompressBufferEx': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormat", "UncompressedBuffer", "UncompressedBufferSize", "CompressedBuffer", "CompressedBufferSize", "FinalUncompressedSize", "WorkSpace"]),
        #
        'RtlDecompressBufferEx2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormat", "UncompressedBuffer", "UncompressedBufferSize", "CompressedBuffer", "CompressedBufferSize", "UncompressedChunkSize", "FinalUncompressedSize", "WorkSpace"]),
        #
        'RtlDecompressFragment': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormat", "UncompressedFragment", "UncompressedFragmentSize", "CompressedBuffer", "CompressedBufferSize", "FragmentOffset", "FinalUncompressedSize", "WorkSpace"]),
        #
        'RtlDecompressFragmentEx': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormat", "UncompressedFragment", "UncompressedFragmentSize", "CompressedBuffer", "CompressedBufferSize", "FragmentOffset", "UncompressedChunkSize", "FinalUncompressedSize", "WorkSpace"]),
        #
        'RtlDescribeChunk': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormat", "CompressedBuffer", "EndOfCompressedBufferPlus1", "ChunkBuffer", "ChunkSize"]),
        #
        'RtlReserveChunk': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormat", "CompressedBuffer", "EndOfCompressedBufferPlus1", "ChunkBuffer", "ChunkSize"]),
        #
        'RtlDecompressChunks': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("COMPRESSED_DATA_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UncompressedBuffer", "UncompressedBufferSize", "CompressedBuffer", "CompressedBufferSize", "CompressedTail", "CompressedTailSize", "CompressedDataInfo"]),
        #
        'RtlCompressChunks': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("COMPRESSED_DATA_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["UncompressedBuffer", "UncompressedBufferSize", "CompressedBuffer", "CompressedBufferSize", "CompressedDataInfo", "CompressedDataInfoLength", "WorkSpace"]),
        #
        'RtlCompareMemoryUlong': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["Source", "Length", "Pattern"]),
        #
        'RtlTimeToSecondsSince1980': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Time", "ElapsedSeconds"]),
        #
        'RtlSecondsSince1980ToTime': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ElapsedSeconds", "Time"]),
        #
        'RtlSecondsSince1970ToTime': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ElapsedSeconds", "Time"]),
        #
        'RtlValidSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Sid"]),
        #
        'RtlEqualSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Sid1", "Sid2"]),
        #
        'RtlEqualPrefixSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Sid1", "Sid2"]),
        #
        'RtlLengthRequiredSid': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["SubAuthorityCount"]),
        #
        'RtlFreeSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Sid"]),
        #
        'RtlAllocateAndInitializeSid': SimTypeFunction([SimTypePointer(SimTypeRef("SID_IDENTIFIER_AUTHORITY", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["IdentifierAuthority", "SubAuthorityCount", "SubAuthority0", "SubAuthority1", "SubAuthority2", "SubAuthority3", "SubAuthority4", "SubAuthority5", "SubAuthority6", "SubAuthority7", "Sid"]),
        #
        'RtlAllocateAndInitializeSidEx': SimTypeFunction([SimTypePointer(SimTypeRef("SID_IDENTIFIER_AUTHORITY", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["IdentifierAuthority", "SubAuthorityCount", "SubAuthorities", "Sid"]),
        #
        'RtlInitializeSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SID_IDENTIFIER_AUTHORITY", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Sid", "IdentifierAuthority", "SubAuthorityCount"]),
        #
        'RtlInitializeSidEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SID_IDENTIFIER_AUTHORITY", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Sid", "IdentifierAuthority", "SubAuthorityCount"]),
        #
        'RtlIdentifierAuthoritySid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("SID_IDENTIFIER_AUTHORITY", SimStruct), offset=0), arg_names=["Sid"]),
        #
        'RtlSubAuthoritySid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), arg_names=["Sid", "SubAuthority"]),
        #
        'RtlSubAuthorityCountSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["Sid"]),
        #
        'RtlLengthSid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Sid"]),
        #
        'RtlCopySid': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationSidLength", "DestinationSid", "SourceSid"]),
        #
        'RtlCreateServiceSid': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ServiceName", "ServiceSid", "ServiceSidLength"]),
        #
        'RtlGetSaclSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "SaclPresent", "Sacl", "SaclDefaulted"]),
        #
        'RtlReplaceSidInSd': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "OldSid", "NewSid", "NumChanges"]),
        #
        'RtlCreateVirtualAccountSid': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Name", "BaseSubAuthority", "Sid", "SidLength"]),
        #
        'RtlCopyLuid': SimTypeFunction([SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0), SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DestinationLuid", "SourceLuid"]),
        #
        'RtlCreateAcl': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Acl", "AclLength", "AclRevision"]),
        #
        'RtlAddAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Acl", "AceRevision", "StartingAceIndex", "AceList", "AceListLength"]),
        #
        'RtlDeleteAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Acl", "AceIndex"]),
        #
        'RtlGetAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Acl", "AceIndex", "Ace"]),
        #
        'RtlAddAccessAllowedAce': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Acl", "AceRevision", "AccessMask", "Sid"]),
        #
        'RtlAddAccessAllowedAceEx': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Acl", "AceRevision", "AceFlags", "AccessMask", "Sid"]),
        #
        'RtlGetDaclSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "DaclPresent", "Dacl", "DaclDefaulted"]),
        #
        'RtlSetOwnerSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "Owner", "OwnerDefaulted"]),
        #
        'RtlSetGroupSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "Group", "GroupDefaulted"]),
        #
        'RtlGetGroupSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "Group", "GroupDefaulted"]),
        #
        'RtlAbsoluteToSelfRelativeSD': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AbsoluteSecurityDescriptor", "SelfRelativeSecurityDescriptor", "BufferLength"]),
        #
        'RtlSelfRelativeToAbsoluteSD': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SelfRelativeSecurityDescriptor", "AbsoluteSecurityDescriptor", "AbsoluteSecurityDescriptorSize", "Dacl", "DaclSize", "Sacl", "SaclSize", "Owner", "OwnerSize", "PrimaryGroup", "PrimaryGroupSize"]),
        #
        'RtlGetOwnerSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "Owner", "OwnerDefaulted"]),
        #
        'RtlNtStatusToDosErrorNoTeb': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Status"]),
        #
        'RtlCustomCPToUnicodeN': SimTypeFunction([SimTypePointer(SimTypeRef("CPTABLEINFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CustomCP", "UnicodeString", "MaxBytesInUnicodeString", "BytesInUnicodeString", "CustomCPString", "BytesInCustomCPString"]),
        #
        'RtlUnicodeToCustomCPN': SimTypeFunction([SimTypePointer(SimTypeRef("CPTABLEINFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CustomCP", "CustomCPString", "MaxBytesInCustomCPString", "BytesInCustomCPString", "UnicodeString", "BytesInUnicodeString"]),
        #
        'RtlUpcaseUnicodeToCustomCPN': SimTypeFunction([SimTypePointer(SimTypeRef("CPTABLEINFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CustomCP", "CustomCPString", "MaxBytesInCustomCPString", "BytesInCustomCPString", "UnicodeString", "BytesInUnicodeString"]),
        #
        'RtlInitCodePageTable': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeRef("CPTABLEINFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["TableBase", "CodePageTable"]),
        #
        'RtlCreateSystemVolumeInformationFolder': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeRootPath"]),
        #
        'RtlCompareAltitudes': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Altitude1", "Altitude2"]),
        #
        'RtlQueryPackageIdentity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenObject", "PackageFullName", "PackageSize", "AppId", "AppIdSize", "Packaged"]),
        #
        'RtlQueryPackageIdentityEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenObject", "PackageFullName", "PackageSize", "AppId", "AppIdSize", "DynamicId", "Flags"]),
        #
        'RtlIsNonEmptyDirectoryReparsePointAllowed': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["ReparseTag"]),
        #
        'RtlIsCloudFilesPlaceholder': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["FileAttributes", "ReparseTag"]),
        #
        'RtlIsPartialPlaceholder': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["FileAttributes", "ReparseTag"]),
        #
        'RtlIsPartialPlaceholderFileHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IsPartialPlaceholder"]),
        #
        'RtlIsPartialPlaceholderFileInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InfoBuffer", "InfoClass", "IsPartialPlaceholder"]),
        #
        'RtlQueryThreadPlaceholderCompatibilityMode': SimTypeFunction([], SimTypeChar(label="SByte")),
        #
        'RtlSetThreadPlaceholderCompatibilityMode': SimTypeFunction([SimTypeChar(label="SByte")], SimTypeChar(label="SByte"), arg_names=["Mode"]),
        #
        'RtlQueryProcessPlaceholderCompatibilityMode': SimTypeFunction([], SimTypeChar(label="SByte")),
        #
        'RtlSetProcessPlaceholderCompatibilityMode': SimTypeFunction([SimTypeChar(label="SByte")], SimTypeChar(label="SByte"), arg_names=["Mode"]),
        #
        'NtCreateFile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="FILE_ACCESS_RIGHTS"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES"), SimTypeInt(signed=False, label="FILE_SHARE_MODE"), SimTypeInt(signed=False, label="NTCREATEFILE_CREATE_DISPOSITION"), SimTypeInt(signed=False, label="NTCREATEFILE_CREATE_OPTIONS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "AllocationSize", "FileAttributes", "ShareAccess", "CreateDisposition", "CreateOptions", "EaBuffer", "EaLength"]),
        #
        'NtFsControlFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "FsControlCode", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength"]),
        #
        'NtLockFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "ByteOffset", "Length", "Key", "FailImmediately", "ExclusiveLock"]),
        #
        'NtOpenFile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "ShareAccess", "OpenOptions"]),
        #
        'NtQueryDirectoryFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass", "ReturnSingleEntry", "FileName", "RestartScan"]),
        #
        'NtQueryDirectoryFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass", "QueryFlags", "FileName"]),
        #
        'NtQueryInformationByName': SimTypeFunction([SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectAttributes", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass"]),
        #
        'NtQueryInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass"]),
        #
        'NtQueryQuotaInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "Buffer", "Length", "ReturnSingleEntry", "SidList", "SidListLength", "StartSid", "RestartScan"]),
        #
        'NtQueryVolumeInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FS_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "FsInformation", "Length", "FsInformationClass"]),
        #
        'NtReadFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "Buffer", "Length", "ByteOffset", "Key"]),
        #
        'NtSetInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass"]),
        #
        'NtSetQuotaInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "Buffer", "Length"]),
        #
        'NtSetVolumeInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FS_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "FsInformation", "Length", "FsInformationClass"]),
        #
        'NtWriteFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "Buffer", "Length", "ByteOffset", "Key"]),
        #
        'NtUnlockFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "ByteOffset", "Length", "Key"]),
        #
        'NtFlushBuffersFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Flags", "Parameters", "ParametersSize", "IoStatusBlock"]),
        #
        'NtSetSecurityObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "SecurityInformation", "SecurityDescriptor"]),
        #
        'NtQuerySecurityObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "SecurityInformation", "SecurityDescriptor", "Length", "LengthNeeded"]),
        #
        'NtCreateSection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SectionHandle", "DesiredAccess", "ObjectAttributes", "MaximumSize", "SectionPageProtection", "AllocationAttributes", "FileHandle"]),
        #
        'NtCreateSectionEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MEM_EXTENDED_PARAMETER", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SectionHandle", "DesiredAccess", "ObjectAttributes", "MaximumSize", "SectionPageProtection", "AllocationAttributes", "FileHandle", "ExtendedParameters", "ExtendedParameterCount"]),
        #
        'NtAllocateVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "BaseAddress", "ZeroBits", "RegionSize", "AllocationType", "Protect"]),
        #
        'NtFreeVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "BaseAddress", "RegionSize", "FreeType"]),
        #
        'NtQueryVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="MEMORY_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "BaseAddress", "MemoryInformationClass", "MemoryInformation", "MemoryInformationLength", "ReturnLength"]),
        #
        'NtSetInformationVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_MEMORY_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("MEMORY_RANGE_ENTRY", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "VmInformationClass", "NumberOfEntries", "VirtualAddresses", "VmInformation", "VmInformationLength"]),
        #
        'KeInitializeMutant': SimTypeFunction([SimTypePointer(SimTypeRef("KMUTANT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Mutant", "InitialOwner"]),
        #
        'KeReadStateMutant': SimTypeFunction([SimTypePointer(SimTypeRef("KMUTANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Mutant"]),
        #
        'KeReleaseMutant': SimTypeFunction([SimTypePointer(SimTypeRef("KMUTANT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Mutant", "Increment", "Abandoned", "Wait"]),
        #
        'KeInitializeQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KQUEUE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Queue", "Count"]),
        #
        'KeReadStateQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KQUEUE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Queue"]),
        #
        'KeInsertQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KQUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Queue", "Entry"]),
        #
        'KeInsertHeadQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KQUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Queue", "Entry"]),
        #
        'KeRemoveQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KQUEUE", SimStruct), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0), arg_names=["Queue", "WaitMode", "Timeout"]),
        #
        'KeRemoveQueueEx': SimTypeFunction([SimTypePointer(SimTypeRef("KQUEUE", SimStruct), offset=0), SimTypeChar(label="SByte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Queue", "WaitMode", "Alertable", "Timeout", "EntryArray", "Count"]),
        #
        'KeRundownQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KQUEUE", SimStruct), offset=0)], SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0), arg_names=["Queue"]),
        #
        'KeAttachProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Process"]),
        #
        'KeDetachProcess': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'KeStackAttachProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("KAPC_STATE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PROCESS", "ApcState"]),
        #
        'KeUnstackDetachProcess': SimTypeFunction([SimTypePointer(SimTypeRef("KAPC_STATE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ApcState"]),
        #
        'KeSetIdealProcessorThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["Thread", "Processor"]),
        #
        'KeSetKernelStackSwapEnable': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["Enable"]),
        #
        'KeAcquireQueuedSpinLock': SimTypeFunction([SimTypeInt(signed=False, label="KSPIN_LOCK_QUEUE_NUMBER")], SimTypeChar(label="Byte"), arg_names=["Number"]),
        #
        'KeReleaseQueuedSpinLock': SimTypeFunction([SimTypeInt(signed=False, label="KSPIN_LOCK_QUEUE_NUMBER"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Number", "OldIrql"]),
        #
        'KeTryToAcquireQueuedSpinLock': SimTypeFunction([SimTypeInt(signed=False, label="KSPIN_LOCK_QUEUE_NUMBER"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Number", "OldIrql"]),
        #
        'KeAcquireSpinLockRaiseToSynch': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["SpinLock"]),
        #
        'ExQueryPoolBlockSize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["PoolBlock", "QuotaCharged"]),
        #
        'ExDisableResourceBoostLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Resource"]),
        #
        'SeDeleteClientSecurity': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_CLIENT_CONTEXT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ClientContext"]),
        #
        'SeCaptureSubjectContextEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Thread", "Process", "SubjectContext"]),
        #
        'SeReportSecurityEventWithSubCategory': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SE_ADT_PARAMETER_ARRAY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "SourceName", "UserSid", "AuditParameters", "AuditSubcategoryId"]),
        #
        'SeAccessCheckFromState': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("TOKEN_ACCESS_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("TOKEN_ACCESS_INFORMATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["SecurityDescriptor", "PrimaryTokenInformation", "ClientTokenInformation", "DesiredAccess", "PreviouslyGrantedAccess", "Privileges", "GenericMapping", "AccessMode", "GrantedAccess", "AccessStatus"]),
        #
        'SeAccessCheckFromStateEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["SecurityDescriptor", "PrimaryToken", "ClientToken", "DesiredAccess", "PreviouslyGrantedAccess", "Privileges", "GenericMapping", "AccessMode", "GrantedAccess", "AccessStatus"]),
        #
        'SeTokenFromAccessInformation': SimTypeFunction([SimTypePointer(SimTypeRef("TOKEN_ACCESS_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AccessInformation", "Token", "Length", "RequiredLength"]),
        #
        'SePrivilegeCheck': SimTypeFunction([SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypeChar(label="SByte")], SimTypeChar(label="Byte"), arg_names=["RequiredPrivileges", "SubjectSecurityContext", "AccessMode"]),
        #
        'SeFreePrivileges': SimTypeFunction([SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Privileges"]),
        #
        'SeOpenObjectAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ObjectTypeName", "Object", "AbsoluteObjectName", "SecurityDescriptor", "AccessState", "ObjectCreated", "AccessGranted", "AccessMode", "GenerateOnClose"]),
        #
        'SeOpenObjectAuditAlarmWithTransaction': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ObjectTypeName", "Object", "AbsoluteObjectName", "SecurityDescriptor", "AccessState", "ObjectCreated", "AccessGranted", "AccessMode", "TransactionId", "GenerateOnClose"]),
        #
        'SeOpenObjectForDeleteAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ObjectTypeName", "Object", "AbsoluteObjectName", "SecurityDescriptor", "AccessState", "ObjectCreated", "AccessGranted", "AccessMode", "GenerateOnClose"]),
        #
        'SeOpenObjectForDeleteAuditAlarmWithTransaction': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="SByte"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ObjectTypeName", "Object", "AbsoluteObjectName", "SecurityDescriptor", "AccessState", "ObjectCreated", "AccessGranted", "AccessMode", "TransactionId", "GenerateOnClose"]),
        #
        'SeExamineSacl': SimTypeFunction([SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Sacl", "ResourceSacl", "Token", "DesiredAccess", "AccessGranted", "GenerateAudit", "GenerateAlarm"]),
        #
        'SeDeleteObjectAuditAlarm': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Object", "Handle"]),
        #
        'SeDeleteObjectAuditAlarmWithTransaction': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Object", "Handle", "TransactionId"]),
        #
        'SeTokenType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="TOKEN_TYPE"), arg_names=["Token"]),
        #
        'SeTokenIsAdmin': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Token"]),
        #
        'SeTokenIsRestricted': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Token"]),
        #
        'SeTokenIsWriteRestricted': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Token"]),
        #
        'SeFilterToken': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TOKEN_GROUPS", SimStruct), offset=0), SimTypePointer(SimTypeRef("TOKEN_PRIVILEGES", SimStruct), offset=0), SimTypePointer(SimTypeRef("TOKEN_GROUPS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExistingToken", "Flags", "SidsToDisable", "PrivilegesToDelete", "RestrictedSids", "FilteredToken"]),
        #
        'SeQueryAuthenticationIdToken': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Token", "AuthenticationId"]),
        #
        'SeQuerySessionIdToken': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Token", "SessionId"]),
        #
        'SeQuerySessionIdTokenEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Token", "SessionId", "IsServiceSession"]),
        #
        'SeQueryServerSiloToken': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Token", "pServerSilo"]),
        #
        'SeCreateClientSecurity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SECURITY_QUALITY_OF_SERVICE", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("SECURITY_CLIENT_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ClientThread", "ClientSecurityQos", "RemoteSession", "ClientContext"]),
        #
        'SeImpersonateClient': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_CLIENT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["ClientContext", "ServerThread"]),
        #
        'SeImpersonateClientEx': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_CLIENT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ClientContext", "ServerThread"]),
        #
        'SeCreateClientSecurityFromSubjectContext': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SECURITY_QUALITY_OF_SERVICE", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("SECURITY_CLIENT_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SubjectContext", "ClientSecurityQos", "ServerIsRemote", "ClientContext"]),
        #
        'SeQuerySecurityDescriptorInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityInformation", "SecurityDescriptor", "Length", "ObjectsSecurityDescriptor"]),
        #
        'SeSetSecurityDescriptorInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "SecurityInformation", "ModificationDescriptor", "ObjectsSecurityDescriptor", "PoolType", "GenericMapping"]),
        #
        'SeSetSecurityDescriptorInfoEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "SecurityInformation", "ModificationDescriptor", "ObjectsSecurityDescriptor", "AutoInheritFlags", "PoolType", "GenericMapping"]),
        #
        'SeAppendPrivileges': SimTypeFunction([SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0), SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AccessState", "Privileges"]),
        #
        'SeAuditHardLinkCreation': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["FileName", "LinkName", "bSuccess"]),
        #
        'SeAuditHardLinkCreationWithTransaction': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileName", "LinkName", "bSuccess", "TransactionId"]),
        #
        'SeAuditFipsCryptoSelftests': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["bSuccess", "SelftestCode"]),
        #
        'SeAuditTransactionStateChange': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["TransactionId", "ResourceManagerId", "NewTransactionState"]),
        #
        'SeAuditingFileEvents': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["AccessGranted", "SecurityDescriptor"]),
        #
        'SeAuditingFileEventsWithContext': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["AccessGranted", "SecurityDescriptor", "SubjectSecurityContext"]),
        #
        'SeAuditingAnyFileEventsWithContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["SecurityDescriptor", "SubjectSecurityContext"]),
        #
        'SeAuditingFileEventsWithContextEx': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["AccessGranted", "SecurityDescriptor", "SubjectSecurityContext", "StagingEnabled"]),
        #
        'SeAuditingAnyFileEventsWithContextEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["SecurityDescriptor", "SubjectSecurityContext", "StagingEnabled"]),
        #
        'SeAdjustAccessStateForTrustLabel': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ObjectType", "SecurityDescriptor", "AccessState"]),
        #
        'SeAdjustAccessStateForAccessConstraints': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ObjectType", "SecurityDescriptor", "AccessState"]),
        #
        'SeShouldCheckForAccessRightsFromParent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["ObjectType", "ChildDescriptor", "AccessState"]),
        #
        'SeAuditingHardLinkEvents': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["AccessGranted", "SecurityDescriptor"]),
        #
        'SeAuditingHardLinkEventsWithContext': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["AccessGranted", "SecurityDescriptor", "SubjectSecurityContext"]),
        #
        'SeAuditingFileOrGlobalEvents': SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["AccessGranted", "SecurityDescriptor", "SubjectSecurityContext"]),
        #
        'SeSetAccessStateGenericMapping': SimTypeFunction([SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["AccessState", "GenericMapping"]),
        #
        'SeRegisterLogonSessionTerminatedRoutine': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackRoutine"]),
        #
        'SeUnregisterLogonSessionTerminatedRoutine': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackRoutine"]),
        #
        'SeRegisterLogonSessionTerminatedRoutineEx': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackRoutine", "Context"]),
        #
        'SeUnregisterLogonSessionTerminatedRoutineEx': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackRoutine", "Context"]),
        #
        'SeMarkLogonSessionForTerminationNotification': SimTypeFunction([SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogonId"]),
        #
        'SeMarkLogonSessionForTerminationNotificationEx': SimTypeFunction([SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogonId", "pServerSilo"]),
        #
        'SeQueryInformationToken': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="TOKEN_INFORMATION_CLASS"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Token", "TokenInformationClass", "TokenInformation"]),
        #
        'SeLocateProcessImageName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Process", "pImageFileName"]),
        #
        'RtlIsSandboxedToken': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypeChar(label="SByte")], SimTypeChar(label="Byte"), arg_names=["Context", "PreviousMode"]),
        #
        'SeCheckForCriticalAceRemoval': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CurrentDescriptor", "NewDescriptor", "SubjectSecurityContext", "AceRemoved"]),
        #
        'SeAdjustObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectName", "OriginalDescriptor", "ProposedDescriptor", "SubjectSecurityContext", "AdjustedDescriptor", "ApplyAdjustedDescriptor"]),
        #
        'PsAssignImpersonationToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread", "Token"]),
        #
        'PsReferencePrimaryToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Process"]),
        #
        'PsDereferencePrimaryToken': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["PrimaryToken"]),
        #
        'PsDereferenceImpersonationToken': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ImpersonationToken"]),
        #
        'PsReferenceImpersonationToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="SECURITY_IMPERSONATION_LEVEL"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Thread", "CopyOnOpen", "EffectiveOnly", "ImpersonationLevel"]),
        #
        'PsGetProcessExitTime': SimTypeFunction([], SimTypeLongLong(signed=True, label="Int64")),
        #
        'PsIsThreadTerminating': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Thread"]),
        #
        'PsImpersonateClient': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="SECURITY_IMPERSONATION_LEVEL")], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread", "Token", "CopyOnOpen", "EffectiveOnly", "ImpersonationLevel"]),
        #
        'PsDisableImpersonation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SE_IMPERSONATION_STATE", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Thread", "ImpersonationState"]),
        #
        'PsRestoreImpersonation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("SE_IMPERSONATION_STATE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Thread", "ImpersonationState"]),
        #
        'PsRevertToSelf': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'PsLookupProcessByProcessId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessId", "Process"]),
        #
        'PsLookupThreadByThreadId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadId", "Thread"]),
        #
        'PsChargePoolQuota': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Process", "PoolType", "Amount"]),
        #
        'PsChargeProcessPoolQuota': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Process", "PoolType", "Amount"]),
        #
        'PsReturnPoolQuota': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Process", "PoolType", "Amount"]),
        #
        'PsGetThreadProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Thread"]),
        #
        'PsIsSystemThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Thread"]),
        #
        'PsUpdateDiskCounters': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Process", "BytesRead", "BytesWritten", "ReadOperationCount", "WriteOperationCount", "FlushOperationCount"]),
        #
        'PsIsDiskCountersEnabled': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'FsRtlRegisterFileSystemFilterCallbacks': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FS_FILTER_CALLBACKS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FilterDriverObject", "Callbacks"]),
        #
        'IoAcquireVpbSpinLock': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irql"]),
        #
        'IoCheckDesiredAccess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["DesiredAccess", "GrantedAccess"]),
        #
        'IoCheckEaBufferValidity': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_FULL_EA_INFORMATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EaBuffer", "EaLength", "ErrorOffset"]),
        #
        'IoCheckFunctionAccess': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["GrantedAccess", "MajorFunction", "MinorFunction", "IoControlCode", "Arg1", "Arg2"]),
        #
        'IoCheckQuerySetFileInformation': SimTypeFunction([SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileInformationClass", "Length", "SetOperation"]),
        #
        'IoCheckQuerySetVolumeInformation': SimTypeFunction([SimTypeInt(signed=False, label="FS_INFORMATION_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FsInformationClass", "Length", "SetOperation"]),
        #
        'IoCheckQuotaBufferValidity': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_QUOTA_INFORMATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["QuotaBuffer", "QuotaLength", "ErrorOffset"]),
        #
        'IoCreateStreamFileObject': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), arg_names=["FileObject", "DeviceObject"]),
        #
        'IoCreateStreamFileObjectEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), arg_names=["FileObject", "DeviceObject", "FileHandle"]),
        #
        'IoCreateStreamFileObjectLite': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), arg_names=["FileObject", "DeviceObject"]),
        #
        'IoCreateStreamFileObjectEx2': SimTypeFunction([SimTypePointer(SimTypeRef("IO_CREATE_STREAM_FILE_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CreateOptions", "FileObject", "DeviceObject", "StreamFileObject", "FileHandle"]),
        #
        'IoFastQueryNetworkAttributes': SimTypeFunction([SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_NETWORK_OPEN_INFORMATION", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["ObjectAttributes", "DesiredAccess", "OpenOptions", "IoStatus", "Buffer"]),
        #
        'IoPageRead': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "MemoryDescriptorList", "StartingOffset", "Event", "IoStatusBlock"]),
        #
        'IoGetAttachedDevice': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), arg_names=["DeviceObject"]),
        #
        'IoGetBaseFileSystemDeviceObject': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), arg_names=["FileObject"]),
        #
        'IoGetDeviceToVerify': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), arg_names=["Thread"]),
        #
        'IoGetRequestorProcessId': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Irp"]),
        #
        'IoGetRequestorProcess': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Irp"]),
        #
        'IoIsOperationSynchronous': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Irp"]),
        #
        'IoIsSystemThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Thread"]),
        #
        'IoIsValidNameGraftingBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeRef("REPARSE_DATA_BUFFER", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Irp", "ReparseBuffer"]),
        #
        'IoQueryFileDosDeviceName': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("OBJECT_NAME_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "ObjectNameInformation"]),
        #
        'IoQueryFileInformation': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "FileInformationClass", "Length", "FileInformation", "ReturnedLength"]),
        #
        'IoQueryVolumeInformation': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="FS_INFORMATION_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "FsInformationClass", "Length", "FsInformation", "ReturnedLength"]),
        #
        'IoQueueThreadIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irp"]),
        #
        'IoRegisterFileSystem': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject"]),
        #
        'IoRegisterFsRegistrationChange': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "FsActive"]), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "DriverNotificationRoutine"]),
        #
        'IoRegisterFsRegistrationChangeMountAware': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "FsActive"]), offset=0), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "DriverNotificationRoutine", "SynchronizeWithMounts"]),
        #
        'IoEnumerateRegisteredFiltersList': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObjectList", "DriverObjectListSize", "ActualNumberDriverObjects"]),
        #
        'IoReplaceFileObjectName': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "NewFileName", "FileNameLength"]),
        #
        'IoReleaseVpbSpinLock': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Irql"]),
        #
        'IoSetDeviceToVerify': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Thread", "DeviceObject"]),
        #
        'IoSetInformation': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "FileInformationClass", "Length", "FileInformation"]),
        #
        'IoSynchronousPageWrite': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "MemoryDescriptorList", "StartingOffset", "Event", "IoStatusBlock"]),
        #
        'IoThreadToProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Thread"]),
        #
        'IoUnregisterFileSystem': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject"]),
        #
        'IoUnregisterFsRegistrationChange': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "FsActive"]), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["DriverObject", "DriverNotificationRoutine"]),
        #
        'IoVerifyVolume': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "AllowRawMount"]),
        #
        'IoGetRequestorSessionId': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "pSessionId"]),
        #
        'IoEnumerateDeviceObjectList': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "DeviceObjectList", "DeviceObjectListSize", "ActualNumberDeviceObjects"]),
        #
        'IoGetLowerDeviceObject': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), arg_names=["DeviceObject"]),
        #
        'IoGetDeviceAttachmentBaseRef': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), arg_names=["DeviceObject"]),
        #
        'IoGetDiskDeviceObject': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileSystemDeviceObject", "DiskDeviceObject"]),
        #
        'IoRetrievePriorityInfo': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_PRIORITY_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "FileObject", "Thread", "PriorityInfo"]),
        #
        'IoApplyPriorityInfoThread': SimTypeFunction([SimTypePointer(SimTypeRef("IO_PRIORITY_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_PRIORITY_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InputPriorityInfo", "OutputPriorityInfo", "Thread"]),
        #
        'IoGetFsTrackOffsetState': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("IO_IRP_EXT_TRACK_OFFSET_HEADER", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "RetFsTrackOffsetBlob", "RetTrackedOffset"]),
        #
        'IoSetFsTrackOffsetState': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_IRP_EXT_TRACK_OFFSET_HEADER", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "FsTrackOffsetBlob", "TrackedOffset"]),
        #
        'IoClearFsTrackOffsetState': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp"]),
        #
        'IoIrpHasFsTrackOffsetExtensionType': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Irp"]),
        #
        'PoQueueShutdownWorkItem': SimTypeFunction([SimTypePointer(SimTypeRef("WORK_QUEUE_ITEM", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WorkItem"]),
        #
        'MmIsRecursiveIoFault': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'MmForceSectionClosed': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["SectionObjectPointer", "DelayClose"]),
        #
        'MmForceSectionClosedEx': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["SectionObjectPointer", "ForceCloseFlags"]),
        #
        'MmGetMaximumFileSectionSize': SimTypeFunction([], SimTypeLongLong(signed=False, label="UInt64")),
        #
        'MmFlushImageSection': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0), SimTypeInt(signed=False, label="MMFLUSH_TYPE")], SimTypeChar(label="Byte"), arg_names=["SectionObjectPointer", "FlushType"]),
        #
        'MmCanFileBeTruncated': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeChar(label="Byte"), arg_names=["SectionPointer", "NewFileSize"]),
        #
        'MmSetAddressRangeModified': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Address", "Length"]),
        #
        'MmIsFileSectionActive': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FsSectionPointer", "Flags", "SectionIsActive"]),
        #
        'MmPrefetchPages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("READ_LIST", SimStruct), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NumberOfLists", "ReadLists"]),
        #
        'MmDoesFileHaveUserWritableReferences': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SectionPointer"]),
        #
        'MmMdlPagesAreZero': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Mdl"]),
        #
        'ObInsertObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "PassedAccessState", "DesiredAccess", "ObjectPointerBias", "NewObject", "Handle"]),
        #
        'ObOpenObjectByPointer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "HandleAttributes", "PassedAccessState", "DesiredAccess", "ObjectType", "AccessMode", "Handle"]),
        #
        'ObOpenObjectByPointerWithTag': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ACCESS_STATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="SByte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "HandleAttributes", "PassedAccessState", "DesiredAccess", "ObjectType", "AccessMode", "Tag", "Handle"]),
        #
        'ObMakeTemporaryObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Object"]),
        #
        'ObQueryNameString': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("OBJECT_NAME_INFORMATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "ObjectNameInfo", "Length", "ReturnLength"]),
        #
        'ObIsKernelHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Handle"]),
        #
        'ObQueryObjectAuditingByHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "GenerateOnClose"]),
        #
        'IoRequestDeviceRemovalForReset': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["PhysicalDeviceObject", "Flags"]),
        #
        'FsRtlCopyRead': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Wait", "LockKey", "Buffer", "IoStatus", "DeviceObject"]),
        #
        'FsRtlCopyWrite': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Wait", "LockKey", "Buffer", "IoStatus", "DeviceObject"]),
        #
        'FsRtlMdlReadEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "FileOffset", "Length", "LockKey", "MdlChain", "IoStatus"]),
        #
        'FsRtlMdlReadDev': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "LockKey", "MdlChain", "IoStatus", "DeviceObject"]),
        #
        'FsRtlMdlReadCompleteDev': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "MdlChain", "DeviceObject"]),
        #
        'FsRtlPrepareMdlWriteEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "FileOffset", "Length", "LockKey", "MdlChain", "IoStatus"]),
        #
        'FsRtlPrepareMdlWriteDev': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "LockKey", "MdlChain", "IoStatus", "DeviceObject"]),
        #
        'FsRtlMdlWriteCompleteDev': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "MdlChain", "DeviceObject"]),
        #
        'FsRtlAcquireFileExclusive': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject"]),
        #
        'FsRtlReleaseFile': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject"]),
        #
        'FsRtlGetFileSize': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "FileSize"]),
        #
        'FsRtlAllocateFileLock': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("FILE_LOCK_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "FileLockInfo"]), offset=0)], SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), arg_names=["CompleteLockIrpRoutine", "UnlockRoutine"]),
        #
        'FsRtlFreeFileLock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileLock"]),
        #
        'FsRtlInitializeFileLock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("FILE_LOCK_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "FileLockInfo"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileLock", "CompleteLockIrpRoutine", "UnlockRoutine"]),
        #
        'FsRtlUninitializeFileLock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileLock"]),
        #
        'FsRtlProcessFileLock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileLock", "Irp", "Context"]),
        #
        'FsRtlCheckLockForReadAccess': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileLock", "Irp"]),
        #
        'FsRtlCheckLockForWriteAccess': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileLock", "Irp"]),
        #
        'FsRtlCheckLockForOplockRequest': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileLock", "AllocationSize"]),
        #
        'FsRtlFastCheckLockForRead': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileLock", "StartingByte", "Length", "Key", "FileObject", "ProcessId"]),
        #
        'FsRtlFastCheckLockForWrite': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileLock", "StartingByte", "Length", "Key", "FileObject", "ProcessId"]),
        #
        'FsRtlGetNextFileLock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeRef("FILE_LOCK_INFO", SimStruct), offset=0), arg_names=["FileLock", "Restart"]),
        #
        'FsRtlAreThereCurrentOrInProgressFileLocks': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileLock"]),
        #
        'FsRtlAreThereWaitingFileLocks': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileLock"]),
        #
        'FsRtlFastUnlockSingle': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileLock", "FileObject", "FileOffset", "Length", "ProcessId", "Key", "Context", "AlreadySynchronized"]),
        #
        'FsRtlFastUnlockAll': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileLock", "FileObject", "ProcessId", "Context"]),
        #
        'FsRtlFastUnlockAllByKey': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileLock", "FileObject", "ProcessId", "Key", "Context"]),
        #
        'FsRtlPrivateLock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["FileLock", "FileObject", "FileOffset", "Length", "ProcessId", "Key", "FailImmediately", "ExclusiveLock", "Iosb", "Irp", "Context", "AlreadySynchronized"]),
        #
        'FsRtlInitializeTunnelCache': SimTypeFunction([SimTypePointer(SimTypeRef("TUNNEL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Cache"]),
        #
        'FsRtlAddToTunnelCache': SimTypeFunction([SimTypePointer(SimTypeRef("TUNNEL", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Cache", "DirectoryKey", "ShortName", "LongName", "KeyByShortName", "DataLength", "Data"]),
        #
        'FsRtlFindInTunnelCache': SimTypeFunction([SimTypePointer(SimTypeRef("TUNNEL", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Cache", "DirectoryKey", "Name", "ShortName", "LongName", "DataLength", "Data"]),
        #
        'FsRtlAddToTunnelCacheEx': SimTypeFunction([SimTypePointer(SimTypeRef("TUNNEL", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Cache", "DirectoryKey", "ShortName", "LongName", "Flags", "DataLength", "Data"]),
        #
        'FsRtlFindInTunnelCacheEx': SimTypeFunction([SimTypePointer(SimTypeRef("TUNNEL", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Cache", "DirectoryKey", "Name", "ShortName", "LongName", "Flags", "DataLength", "Data"]),
        #
        'FsRtlDeleteKeyFromTunnelCache': SimTypeFunction([SimTypePointer(SimTypeRef("TUNNEL", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeBottom(label="Void"), arg_names=["Cache", "DirectoryKey"]),
        #
        'FsRtlDeleteTunnelCache': SimTypeFunction([SimTypePointer(SimTypeRef("TUNNEL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Cache"]),
        #
        'FsRtlDissectDbcs': SimTypeFunction([SimTypeRef("STRING", SimStruct), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Path", "FirstName", "RemainingName"]),
        #
        'FsRtlDoesDbcsContainWildCards': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Name"]),
        #
        'FsRtlIsDbcsInExpression': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Expression", "Name"]),
        #
        'FsRtlIsFatDbcsLegal': SimTypeFunction([SimTypeRef("STRING", SimStruct), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["DbcsName", "WildCardsPermissible", "PathNamePermissible", "LeadingBackslashPermissible"]),
        #
        'FsRtlIsHpfsDbcsLegal': SimTypeFunction([SimTypeRef("STRING", SimStruct), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["DbcsName", "WildCardsPermissible", "PathNamePermissible", "LeadingBackslashPermissible"]),
        #
        'FsRtlNormalizeNtstatus': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Exception", "GenericException"]),
        #
        'FsRtlIsNtstatusExpected': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="Byte"), arg_names=["Exception"]),
        #
        'FsRtlAllocateResource': SimTypeFunction([], SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)),
        #
        'FsRtlInitializeLargeMcb': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="POOL_TYPE")], SimTypeBottom(label="Void"), arg_names=["Mcb", "PoolType"]),
        #
        'FsRtlUninitializeLargeMcb': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mcb"]),
        #
        'FsRtlResetLargeMcb': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Mcb", "SelfSynchronized"]),
        #
        'FsRtlTruncateLargeMcb': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeBottom(label="Void"), arg_names=["Mcb", "Vbn"]),
        #
        'FsRtlAddLargeMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64")], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Lbn", "SectorCount"]),
        #
        'FsRtlRemoveLargeMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64")], SimTypeBottom(label="Void"), arg_names=["Mcb", "Vbn", "SectorCount"]),
        #
        'FsRtlLookupLargeMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Lbn", "SectorCountFromLbn", "StartingLbn", "SectorCountFromStartingLbn", "Index"]),
        #
        'FsRtlLookupLastLargeMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Lbn"]),
        #
        'FsRtlLookupLastLargeMcbEntryAndIndex': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["OpaqueMcb", "LargeVbn", "LargeLbn", "Index"]),
        #
        'FsRtlNumberOfRunsInLargeMcb': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Mcb"]),
        #
        'FsRtlGetNextLargeMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Mcb", "RunIndex", "Vbn", "Lbn", "SectorCount"]),
        #
        'FsRtlSplitLargeMcb': SimTypeFunction([SimTypePointer(SimTypeRef("LARGE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64")], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Amount"]),
        #
        'FsRtlInitializeBaseMcb': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="POOL_TYPE")], SimTypeBottom(label="Void"), arg_names=["Mcb", "PoolType"]),
        #
        'FsRtlInitializeBaseMcbEx': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypeShort(signed=False, label="UInt16")], SimTypeChar(label="Byte"), arg_names=["Mcb", "PoolType", "Flags"]),
        #
        'FsRtlUninitializeBaseMcb': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mcb"]),
        #
        'FsRtlResetBaseMcb': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mcb"]),
        #
        'FsRtlTruncateBaseMcb': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeBottom(label="Void"), arg_names=["Mcb", "Vbn"]),
        #
        'FsRtlAddBaseMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64")], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Lbn", "SectorCount"]),
        #
        'FsRtlAddBaseMcbEntryEx': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=True, label="Int32"), arg_names=["Mcb", "Vbn", "Lbn", "SectorCount"]),
        #
        'FsRtlRemoveBaseMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64")], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "SectorCount"]),
        #
        'FsRtlLookupBaseMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Lbn", "SectorCountFromLbn", "StartingLbn", "SectorCountFromStartingLbn", "Index"]),
        #
        'FsRtlLookupLastBaseMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Lbn"]),
        #
        'FsRtlLookupLastBaseMcbEntryAndIndex': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["OpaqueMcb", "LargeVbn", "LargeLbn", "Index"]),
        #
        'FsRtlNumberOfRunsInBaseMcb': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Mcb"]),
        #
        'FsRtlGetNextBaseMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Mcb", "RunIndex", "Vbn", "Lbn", "SectorCount"]),
        #
        'FsRtlSplitBaseMcb': SimTypeFunction([SimTypePointer(SimTypeRef("BASE_MCB", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64")], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Amount"]),
        #
        'FsRtlInitializeMcb': SimTypeFunction([SimTypePointer(SimTypeRef("MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="POOL_TYPE")], SimTypeBottom(label="Void"), arg_names=["Mcb", "PoolType"]),
        #
        'FsRtlUninitializeMcb': SimTypeFunction([SimTypePointer(SimTypeRef("MCB", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mcb"]),
        #
        'FsRtlTruncateMcb': SimTypeFunction([SimTypePointer(SimTypeRef("MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Mcb", "Vbn"]),
        #
        'FsRtlAddMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Lbn", "SectorCount"]),
        #
        'FsRtlRemoveMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Mcb", "Vbn", "SectorCount"]),
        #
        'FsRtlLookupMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Lbn", "SectorCount", "Index"]),
        #
        'FsRtlLookupLastMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MCB", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Mcb", "Vbn", "Lbn"]),
        #
        'FsRtlNumberOfRunsInMcb': SimTypeFunction([SimTypePointer(SimTypeRef("MCB", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Mcb"]),
        #
        'FsRtlGetNextMcbEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MCB", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Mcb", "RunIndex", "Vbn", "Lbn", "SectorCount"]),
        #
        'FsRtlBalanceReads': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetDevice"]),
        #
        'FsRtlInitializeOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Oplock"]),
        #
        'FsRtlUninitializeOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Oplock"]),
        #
        'FsRtlOplockFsctrl': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "Irp", "OpenCount"]),
        #
        'FsRtlCheckOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "Irp", "Context", "CompletionRoutine", "PostIrpRoutine"]),
        #
        'FsRtlCheckOplockEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "Irp", "Flags", "Context", "CompletionRoutine", "PostIrpRoutine"]),
        #
        'FsRtlCheckUpperOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "NewLowerOplockState", "CompletionRoutineContext", "CompletionRoutine", "PrePendRoutine", "Flags"]),
        #
        'FsRtlUpperOplockFsctrl': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "Irp", "OpenCount", "LowerOplockState", "Flags"]),
        #
        'FsRtlOplockIsFastIoPossible': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["Oplock"]),
        #
        'FsRtlCurrentBatchOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["Oplock"]),
        #
        'FsRtlCurrentOplock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["Oplock"]),
        #
        'FsRtlOplockBreakToNone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IO_STACK_LOCATION", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "IrpSp", "Irp", "Context", "CompletionRoutine", "PostIrpRoutine"]),
        #
        'FsRtlOplockIsSharedRequest': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Irp"]),
        #
        'FsRtlOplockBreakH': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "Irp", "Flags", "Context", "CompletionRoutine", "PostIrpRoutine"]),
        #
        'FsRtlOplockBreakH2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "Irp", "Flags", "Context", "CompletionRoutine", "PostIrpRoutine", "GrantedAccess", "ShareAccess"]),
        #
        'FsRtlCurrentOplockH': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["Oplock"]),
        #
        'FsRtlOplockBreakToNoneEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "Irp", "Flags", "Context", "CompletionRoutine", "PostIrpRoutine"]),
        #
        'FsRtlOplockFsctrlEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "Irp", "OpenCount", "Flags"]),
        #
        'FsRtlOplockKeysEqual': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Fo1", "Fo2"]),
        #
        'FsRtlNotifyVolumeEvent': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "EventCode"]),
        #
        'FsRtlNotifyVolumeEventEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("TARGET_DEVICE_CUSTOM_NOTIFICATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "EventCode", "Event"]),
        #
        'FsRtlNotifyInitializeSync': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["NotifySync"]),
        #
        'FsRtlNotifyUninitializeSync': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["NotifySync"]),
        #
        'FsRtlNotifyFullChangeDirectory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["NotifyContext", "TargetContext", "SubjectContext"]), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["NotifySync", "NotifyList", "FsContext", "FullDirectoryName", "WatchTree", "IgnoreBuffer", "CompletionFilter", "NotifyIrp", "TraverseCallback", "SubjectContext"]),
        #
        'FsRtlNotifyFilterChangeDirectory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["NotifyContext", "TargetContext", "SubjectContext"]), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["NotifyContext", "FilterContext"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["NotifySync", "NotifyList", "FsContext", "FullDirectoryName", "WatchTree", "IgnoreBuffer", "CompletionFilter", "NotifyIrp", "TraverseCallback", "SubjectContext", "FilterCallback"]),
        #
        'FsRtlNotifyFilterReportChange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NotifySync", "NotifyList", "FullTargetName", "TargetNameOffset", "StreamName", "NormalizedParentName", "FilterMatch", "Action", "TargetContext", "FilterContext"]),
        #
        'FsRtlNotifyFullReportChange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NotifySync", "NotifyList", "FullTargetName", "TargetNameOffset", "StreamName", "NormalizedParentName", "FilterMatch", "Action", "TargetContext"]),
        #
        'FsRtlNotifyCleanup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NotifySync", "NotifyList", "FsContext"]),
        #
        'FsRtlNotifyCleanupAll': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["NotifySync", "NotifyList"]),
        #
        'FsRtlDissectName': SimTypeFunction([SimTypeRef("UNICODE_STRING", SimStruct), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Path", "FirstName", "RemainingName"]),
        #
        'FsRtlDoesNameContainWildCards': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Name"]),
        #
        'FsRtlAreNamesEqual': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeChar(label="Byte"), arg_names=["ConstantNameA", "ConstantNameB", "IgnoreCase", "UpcaseTable"]),
        #
        'FsRtlIsNameInExpression': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Expression", "Name", "IgnoreCase", "UpcaseTable"]),
        #
        'FsRtlIsNameInUnUpcasedExpression': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Expression", "Name", "IgnoreCase", "UpcaseTable"]),
        #
        'FsRtlPostStackOverflow': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Event"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Event", "StackOverflowRoutine"]),
        #
        'FsRtlPostPagingFileStackOverflow': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Event"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Event", "StackOverflowRoutine"]),
        #
        'FsRtlRegisterUncProvider': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["MupHandle", "RedirectorDeviceName", "MailslotsSupported"]),
        #
        'FsRtlRegisterUncProviderEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["MupHandle", "RedirDevName", "DeviceObject", "Flags"]),
        #
        'FsRtlRegisterUncProviderEx2': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FSRTL_UNC_PROVIDER_REGISTRATION", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RedirDevName", "DeviceObject", "Registration", "MupHandle"]),
        #
        'FsRtlDeregisterUncProvider': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle"]),
        #
        'FsRtlCancellableWaitForSingleObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "Timeout", "Irp"]),
        #
        'FsRtlCancellableWaitForMultipleObjects': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="WAIT_TYPE"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("KWAIT_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Count", "ObjectArray", "WaitType", "Timeout", "WaitBlockArray", "Irp"]),
        #
        'FsRtlMupGetProviderInfoFromFileObject': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pFileObject", "Level", "pBuffer", "pBufferSize"]),
        #
        'FsRtlMupGetProviderIdFromName': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProviderName", "pProviderId"]),
        #
        'FsRtlInsertPerFileContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("FSRTL_PER_FILE_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PerFileContextPointer", "Ptr"]),
        #
        'FsRtlLookupPerFileContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("FSRTL_PER_FILE_CONTEXT", SimStruct), offset=0), arg_names=["PerFileContextPointer", "OwnerId", "InstanceId"]),
        #
        'FsRtlRemovePerFileContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("FSRTL_PER_FILE_CONTEXT", SimStruct), offset=0), arg_names=["PerFileContextPointer", "OwnerId", "InstanceId"]),
        #
        'FsRtlTeardownPerFileContexts': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["PerFileContextPointer"]),
        #
        'FsRtlInsertPerStreamContext': SimTypeFunction([SimTypePointer(SimTypeRef("FSRTL_ADVANCED_FCB_HEADER", SimStruct), offset=0), SimTypePointer(SimTypeRef("FSRTL_PER_STREAM_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PerStreamContext", "Ptr"]),
        #
        'FsRtlLookupPerStreamContextInternal': SimTypeFunction([SimTypePointer(SimTypeRef("FSRTL_ADVANCED_FCB_HEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("FSRTL_PER_STREAM_CONTEXT", SimStruct), offset=0), arg_names=["StreamContext", "OwnerId", "InstanceId"]),
        #
        'FsRtlRemovePerStreamContext': SimTypeFunction([SimTypePointer(SimTypeRef("FSRTL_ADVANCED_FCB_HEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("FSRTL_PER_STREAM_CONTEXT", SimStruct), offset=0), arg_names=["StreamContext", "OwnerId", "InstanceId"]),
        #
        'FsRtlAllocateAePushLock': SimTypeFunction([SimTypeInt(signed=False, label="POOL_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PoolType", "Tag"]),
        #
        'FsRtlFreeAePushLock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["AePushLock"]),
        #
        'FsRtlTeardownPerStreamContexts': SimTypeFunction([SimTypePointer(SimTypeRef("FSRTL_ADVANCED_FCB_HEADER", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["AdvancedHeader"]),
        #
        'FsRtlInsertPerFileObjectContext': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FSRTL_PER_FILEOBJECT_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "Ptr"]),
        #
        'FsRtlLookupPerFileObjectContext': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("FSRTL_PER_FILEOBJECT_CONTEXT", SimStruct), offset=0), arg_names=["FileObject", "OwnerId", "InstanceId"]),
        #
        'FsRtlRemovePerFileObjectContext': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("FSRTL_PER_FILEOBJECT_CONTEXT", SimStruct), offset=0), arg_names=["FileObject", "OwnerId", "InstanceId"]),
        #
        'FsRtlIncrementCcFastReadNotPossible': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'FsRtlIncrementCcFastReadWait': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'FsRtlIncrementCcFastReadNoWait': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'FsRtlIncrementCcFastReadResourceMiss': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'FsRtlIncrementCcFastMdlReadWait': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'FsRtlIsPagingFile': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["FileObject"]),
        #
        'FsRtlIsSystemPagingFile': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["FileObject"]),
        #
        'FsRtlCreateSectionForDataScan': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SectionHandle", "SectionObject", "SectionFileSize", "FileObject", "DesiredAccess", "ObjectAttributes", "MaximumSize", "SectionPageProtection", "AllocationAttributes", "Flags"]),
        #
        'FsRtlValidateReparsePointBuffer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("REPARSE_DATA_BUFFER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BufferLength", "ReparseBuffer"]),
        #
        'FsRtlRemoveDotsFromPath': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OriginalString", "PathLength", "NewLength"]),
        #
        'FsRtlIsNonEmptyDirectoryReparsePointAllowed': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["ReparseTag"]),
        #
        'FsRtlAllocateExtraCreateParameterList': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "EcpList"]),
        #
        'FsRtlFreeExtraCreateParameterList': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["EcpList"]),
        #
        'FsRtlInitializeExtraCreateParameterList': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EcpList"]),
        #
        'FsRtlAllocateExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["EcpContext", "EcpType"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EcpType", "SizeOfContext", "Flags", "CleanupCallback", "PoolTag", "EcpContext"]),
        #
        'FsRtlFreeExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["EcpContext"]),
        #
        'FsRtlInitializeExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["EcpContext", "EcpType"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Ecp", "EcpFlags", "CleanupCallback", "TotalSize", "EcpType", "ListAllocatedFrom"]),
        #
        'FsRtlInitExtraCreateParameterLookasideList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Lookaside", "Flags", "Size", "Tag"]),
        #
        'FsRtlDeleteExtraCreateParameterLookasideList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Lookaside", "Flags"]),
        #
        'FsRtlAllocateExtraCreateParameterFromLookasideList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["EcpContext", "EcpType"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EcpType", "SizeOfContext", "Flags", "CleanupCallback", "LookasideList", "EcpContext"]),
        #
        'FsRtlInsertExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EcpList", "EcpContext"]),
        #
        'FsRtlFindExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EcpList", "EcpType", "EcpContext", "EcpContextSize"]),
        #
        'FsRtlRemoveExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EcpList", "EcpType", "EcpContext", "EcpContextSize"]),
        #
        'FsRtlGetEcpListFromIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "EcpList"]),
        #
        'FsRtlSetEcpListIntoIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "EcpList"]),
        #
        'FsRtlGetNextExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EcpList", "CurrentEcpContext", "NextEcpType", "NextEcpContext", "NextEcpContextSize"]),
        #
        'FsRtlAcknowledgeEcp': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["EcpContext"]),
        #
        'FsRtlPrepareToReuseEcp': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["EcpContext"]),
        #
        'FsRtlIsEcpAcknowledged': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["EcpContext"]),
        #
        'FsRtlIsEcpFromUserMode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["EcpContext"]),
        #
        'FsRtlOplockGetAnyBreakOwnerProcess': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Oplock"]),
        #
        'FsRtlCheckOplockEx2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context", "Irp"]), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("OPLOCK_NOTIFY_PARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotifyParams"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Oplock", "Irp", "Flags", "FlagsEx2", "CompletionRoutineContext", "CompletionRoutine", "PostIrpRoutine", "Timeout", "NotifyContext", "NotifyRoutine"]),
        #
        'FsRtlGetCurrentProcessLoaderList': SimTypeFunction([], SimTypePointer(SimTypeRef("LIST_ENTRY", SimStruct), offset=0)),
        #
        'FsRtlIs32BitProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Process"]),
        #
        'FsRtlChangeBackingFileObject': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="FSRTL_CHANGE_BACKING_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CurrentFileObject", "NewFileObject", "ChangeBackingType", "Flags"]),
        #
        'FsRtlLogCcFlushError': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileName", "DeviceObject", "SectionObjectPointer", "FlushError", "Flags"]),
        #
        'FsRtlAreVolumeStartupApplicationsComplete': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'FsRtlQueryMaximumVirtualDiskNestingLevel': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'FsRtlGetVirtualDiskNestingLevel': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "NestingLevel", "NestingFlags"]),
        #
        'FsRtlVolumeDeviceToCorrelationId': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeDeviceObject", "Guid"]),
        #
        'FsRtlIssueDeviceIoControl': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "IoCtl", "Flags", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength", "IosbInformation"]),
        #
        'FsRtlGetSectorSizeInformation': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_FS_SECTOR_SIZE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "SectorSizeInfo"]),
        #
        'FsRtlGetSupportedFeatures': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "SupportedFeatures"]),
        #
        'FsRtlKernelFsControlFile': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "FsControlCode", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength", "RetOutputBufferSize"]),
        #
        'FsRtlQueryKernelEaFile': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "ReturnedEaData", "Length", "ReturnSingleEntry", "EaList", "EaListLength", "EaIndex", "RestartScan", "LengthReturned"]),
        #
        'FsRtlSetKernelEaFile': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "EaBuffer", "Length"]),
        #
        'FsRtlQueryInformationFile': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "FileInformation", "Length", "FileInformationClass", "RetFileInformationSize"]),
        #
        'FsRtlQueryCachedVdl': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "Vdl"]),
        #
        'FsRtlUpdateDiskCounters': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeBottom(label="Void"), arg_names=["BytesRead", "BytesWritten"]),
        #
        'FsRtlDismountComplete': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "DismountStatus"]),
        #
        'FsRtlSetDriverBacking': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObj", "Flags"]),
        #
        'FsRtlIsMobileOS': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'FsRtlIsExtentDangling': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["StartPage", "NumberOfPages", "Flags"]),
        #
        'FsRtlIsDaxVolume': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject"]),
        #
        'CcInitializeCacheMap': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CC_FILE_SIZES", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("CACHE_MANAGER_CALLBACKS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileSizes", "PinAccess", "Callbacks", "LazyWriteContext"]),
        #
        'CcUninitializeCacheMap': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("CACHE_UNINITIALIZE_EVENT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "TruncateSize", "UninitializeEvent"]),
        #
        'CcSetFileSizes': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CC_FILE_SIZES", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileSizes"]),
        #
        'CcSetFileSizesEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CC_FILE_SIZES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "FileSizes"]),
        #
        'CcPurgeCacheSection': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["SectionObjectPointer", "FileOffset", "Length", "Flags"]),
        #
        'CcCoherencyFlushAndPurgeCache': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["SectionObjectPointer", "FileOffset", "Length", "IoStatus", "Flags"]),
        #
        'CcSetDirtyPageThreshold': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["FileObject", "DirtyPageThreshold"]),
        #
        'CcFlushCache': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SectionObjectPointer", "FileOffset", "Length", "IoStatus"]),
        #
        'CcGetFlushedValidData': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeLongLong(signed=True, label="Int64"), arg_names=["SectionObjectPointer", "BcbListHeld"]),
        #
        'CcZeroData': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["FileObject", "StartOffset", "EndOffset", "Wait"]),
        #
        'CcRemapBcb': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Bcb"]),
        #
        'CcRepinBcb': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Bcb"]),
        #
        'CcUnpinRepinnedBcb': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Bcb", "WriteThrough", "IoStatus"]),
        #
        'CcGetFileObjectFromSectionPtrs': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0)], SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), arg_names=["SectionObjectPointer"]),
        #
        'CcGetFileObjectFromSectionPtrsRef': SimTypeFunction([SimTypePointer(SimTypeRef("SECTION_OBJECT_POINTERS", SimStruct), offset=0)], SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), arg_names=["SectionObjectPointer"]),
        #
        'CcGetFileObjectFromBcb': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), arg_names=["Bcb"]),
        #
        'CcCopyWriteWontFlush': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length"]),
        #
        'CcCanIWrite': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["FileObject", "BytesToWrite", "Wait", "Retrying"]),
        #
        'CcDeferWrite': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Context1", "Context2"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["FileObject", "PostRoutine", "Context1", "Context2", "BytesToWrite", "Retrying"]),
        #
        'CcCopyRead': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Wait", "Buffer", "IoStatus"]),
        #
        'CcFastCopyRead': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileOffset", "Length", "PageCount", "Buffer", "IoStatus"]),
        #
        'CcCopyWrite': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Wait", "Buffer"]),
        #
        'CcFastCopyWrite': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileOffset", "Length", "Buffer"]),
        #
        'CcMdlRead': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileOffset", "Length", "MdlChain", "IoStatus"]),
        #
        'CcMdlReadComplete': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "MdlChain"]),
        #
        'CcPrepareMdlWrite': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileOffset", "Length", "MdlChain", "IoStatus"]),
        #
        'CcMdlWriteComplete': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileOffset", "MdlChain"]),
        #
        'CcMdlWriteAbort': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "MdlChain"]),
        #
        'CcScheduleReadAhead': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileOffset", "Length"]),
        #
        'CcWaitForCurrentLazyWriterActivity': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'CcSetReadAheadGranularity': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["FileObject", "Granularity"]),
        #
        'CcCopyWriteEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Wait", "Buffer", "IoIssuerThread"]),
        #
        'CcCopyReadEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Wait", "Buffer", "IoStatus", "IoIssuerThread"]),
        #
        'CcAsyncCopyRead': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CC_ASYNC_READ_CONTEXT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Wait", "Buffer", "IoStatus", "IoIssuerThread", "AsyncReadContext"]),
        #
        'CcScheduleReadAheadEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileOffset", "Length", "IoIssuerThread"]),
        #
        'CcInitializeCacheMapEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CC_FILE_SIZES", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("CACHE_MANAGER_CALLBACKS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileSizes", "PinAccess", "Callbacks", "LazyWriteContext", "Flags"]),
        #
        'CcPinRead': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Flags", "Bcb", "Buffer"]),
        #
        'CcMapData': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Flags", "Bcb", "Buffer"]),
        #
        'CcPinMappedData': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Flags", "Bcb"]),
        #
        'CcPreparePinWrite': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject", "FileOffset", "Length", "Zero", "Flags", "Bcb", "Buffer"]),
        #
        'CcSetDirtyPinnedData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["BcbVoid", "Lsn"]),
        #
        'CcUnpinData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Bcb"]),
        #
        'CcSetBcbOwnerPointer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Bcb", "OwnerPointer"]),
        #
        'CcUnpinDataForThread': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Bcb", "ResourceThreadId"]),
        #
        'CcSetAdditionalCacheAttributes': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["FileObject", "DisableReadAhead", "DisableWriteBehind"]),
        #
        'CcSetAdditionalCacheAttributesEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["FileObject", "Flags"]),
        #
        'CcSetParallelFlushFile': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["FileObject", "EnableParallelFlush"]),
        #
        'CcSetLogHandleForFile': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypeBottom(label="Void"), arg_names=["LogHandle", "Lsn"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "LogHandle", "FlushToLsnRoutine"]),
        #
        'CcGetDirtyPages': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "FileOffset", "Length", "OldestLsn", "NewestLsn", "Context1", "Context2"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["LogHandle", "DirtyPageRoutine", "Context1", "Context2"]),
        #
        'CcIsThereDirtyData': SimTypeFunction([SimTypePointer(SimTypeRef("VPB", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Vpb"]),
        #
        'CcIsThereDirtyDataEx': SimTypeFunction([SimTypePointer(SimTypeRef("VPB", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Vpb", "NumberOfDirtyPages"]),
        #
        'CcIsCacheManagerCallbackNeeded': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="Byte"), arg_names=["Status"]),
        #
        'CcErrorCallbackRoutine': SimTypeFunction([SimTypePointer(SimTypeRef("CC_ERROR_CALLBACK_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Context"]),
        #
        'ZwQueryObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="OBJECT_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "ObjectInformationClass", "ObjectInformation", "ObjectInformationLength", "ReturnLength"]),
        #
        'ZwNotifyChangeKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "CompletionFilter", "WatchTree", "Buffer", "BufferSize", "Asynchronous"]),
        #
        'ZwCreateEvent': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="EVENT_TYPE"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["EventHandle", "DesiredAccess", "ObjectAttributes", "EventType", "InitialState"]),
        #
        'ZwDeleteFile': SimTypeFunction([SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectAttributes"]),
        #
        'ZwQueryDirectoryFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass", "ReturnSingleEntry", "FileName", "RestartScan"]),
        #
        'ZwQueryDirectoryFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass", "QueryFlags", "FileName"]),
        #
        'ZwQueryVolumeInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FS_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "FsInformation", "Length", "FsInformationClass"]),
        #
        'ZwSetVolumeInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FS_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "FsInformation", "Length", "FsInformationClass"]),
        #
        'ZwFsControlFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "FsControlCode", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength"]),
        #
        'ZwDuplicateObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceProcessHandle", "SourceHandle", "TargetProcessHandle", "TargetHandle", "DesiredAccess", "HandleAttributes", "Options"]),
        #
        'ZwOpenDirectoryObject': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DirectoryHandle", "DesiredAccess", "ObjectAttributes"]),
        #
        'ZwAllocateVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "BaseAddress", "ZeroBits", "RegionSize", "AllocationType", "Protect"]),
        #
        'ZwAllocateVirtualMemoryEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MEM_EXTENDED_PARAMETER", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "BaseAddress", "RegionSize", "AllocationType", "PageProtection", "ExtendedParameters", "ExtendedParameterCount"]),
        #
        'ZwFreeVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "BaseAddress", "RegionSize", "FreeType"]),
        #
        'ZwQueryVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="MEMORY_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "BaseAddress", "MemoryInformationClass", "MemoryInformation", "MemoryInformationLength", "ReturnLength"]),
        #
        'ZwSetInformationVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="VIRTUAL_MEMORY_INFORMATION_CLASS"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("MEMORY_RANGE_ENTRY", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "VmInformationClass", "NumberOfEntries", "VirtualAddresses", "VmInformation", "VmInformationLength"]),
        #
        'ZwWaitForSingleObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "Alertable", "Timeout"]),
        #
        'ZwSetEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EventHandle", "PreviousState"]),
        #
        'ZwFlushVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "BaseAddress", "RegionSize", "IoStatus"]),
        #
        'ZwOpenProcessTokenEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "DesiredAccess", "HandleAttributes", "TokenHandle"]),
        #
        'ZwOpenThreadTokenEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle", "DesiredAccess", "OpenAsSelf", "HandleAttributes", "TokenHandle"]),
        #
        'ZwQueryInformationToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TOKEN_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "TokenInformationClass", "TokenInformation", "TokenInformationLength", "ReturnLength"]),
        #
        'ZwSetInformationToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TOKEN_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "TokenInformationClass", "TokenInformation", "TokenInformationLength"]),
        #
        'ZwSetSecurityObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "SecurityInformation", "SecurityDescriptor"]),
        #
        'ZwQuerySecurityObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "SecurityInformation", "SecurityDescriptor", "Length", "LengthNeeded"]),
        #
        'ZwLockFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "ByteOffset", "Length", "Key", "FailImmediately", "ExclusiveLock"]),
        #
        'ZwUnlockFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "ByteOffset", "Length", "Key"]),
        #
        'ZwQueryQuotaInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "Buffer", "Length", "ReturnSingleEntry", "SidList", "SidListLength", "StartSid", "RestartScan"]),
        #
        'ZwSetQuotaInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "Buffer", "Length"]),
        #
        'ZwFlushBuffersFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock"]),
        #
        'ZwFlushBuffersFileEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "FLags", "Parameters", "ParametersSize", "IoStatusBlock"]),
        #
        'ZwQueryEaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "Buffer", "Length", "ReturnSingleEntry", "EaList", "EaListLength", "EaIndex", "RestartScan"]),
        #
        'ZwSetEaFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "Buffer", "Length"]),
        #
        'ZwDuplicateToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="TOKEN_TYPE"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ExistingTokenHandle", "DesiredAccess", "ObjectAttributes", "EffectiveOnly", "TokenType", "NewTokenHandle"]),
        #
        'ZwQueryFullAttributesFile': SimTypeFunction([SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_NETWORK_OPEN_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectAttributes", "FileInformation"]),
        #
        'IoGetOplockKeyContext': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("OPLOCK_KEY_ECP_CONTEXT", SimStruct), offset=0), arg_names=["FileObject"]),
        #
        'IoGetOplockKeyContextEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("OPLOCK_KEY_CONTEXT", SimStruct), offset=0), arg_names=["FileObject"]),
        #
        'NtDeviceIoControlFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "IoControlCode", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength"]),
        #
        'NtNotifyChangeMultipleKeys': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["MasterKeyHandle", "Count", "SubordinateObjects", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "CompletionFilter", "WatchTree", "Buffer", "BufferSize", "Asynchronous"]),
        #
        'NtQueryMultipleValueKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("KEY_VALUE_ENTRY", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "ValueEntries", "EntryCount", "ValueBuffer", "BufferLength", "RequiredBufferLength"]),
        #
        'NtRenameKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "NewName"]),
        #
        'NtSetInformationKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="KEY_SET_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "KeySetInformationClass", "KeySetInformation", "KeySetInformationLength"]),
        #
        'ZwSetInformationKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="KEY_SET_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "KeySetInformationClass", "KeySetInformation", "KeySetInformationLength"]),
        #
        'NtQuerySystemInformation': SimTypeFunction([SimTypeInt(signed=False, label="SYSTEM_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SystemInformationClass", "SystemInformation", "SystemInformationLength", "ReturnLength"]),
        #
        'NtQuerySystemTime': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SystemTime"]),
        #
        'NtQueryTimerResolution': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MaximumTime", "MinimumTime", "CurrentTime"]),
        #
        'NtManagePartition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PARTITION_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetHandle", "SourceHandle", "PartitionInformationClass", "PartitionInformation", "PartitionInformationLength"]),
        #
        'NtPowerInformation': SimTypeFunction([SimTypeInt(signed=False, label="POWER_INFORMATION_LEVEL"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["InformationLevel", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength"]),
        #
        'RtlAssert': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["VoidFailedAssertion", "VoidFileName", "LineNumber", "MutableMessage"]),
        #
        'RtlIntegerToUnicodeString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Value", "Base", "String"]),
        #
        'RtlInt64ToUnicodeString': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Value", "Base", "String"]),
        #
        'RtlUnicodeStringToInteger': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["String", "Base", "Value"]),
        #
        'RtlUnicodeStringToInt64': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["String", "Base", "Number", "EndPointer"]),
        #
        'RtlInitUTF8String': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlQueryRegistryValues': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("RTL_QUERY_REGISTRY_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RelativeTo", "Path", "QueryTable", "Context", "Environment"]),
        #
        'MmGetSystemRoutineAddress': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["SystemRoutineName"]),
        #
        'RtlWriteRegistryValue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["RelativeTo", "Path", "ValueName", "ValueType", "ValueData", "ValueLength"]),
        #
        'RtlDeleteRegistryValue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RelativeTo", "Path", "ValueName"]),
        #
        'RtlCreateRegistryKey': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RelativeTo", "Path"]),
        #
        'RtlCheckRegistryKey': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RelativeTo", "Path"]),
        #
        'RtlInitUTF8StringEx': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlCompareUnicodeStrings': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["String1", "String1Length", "String2", "String2Length", "CaseInSensitive"]),
        #
        'RtlCompareUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["String1", "String2", "CaseInSensitive"]),
        #
        'RtlEqualUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["String1", "String2", "CaseInSensitive"]),
        #
        'RtlHashUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["String", "CaseInSensitive", "HashAlgorithm", "HashValue"]),
        #
        'RtlCopyUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlAppendUnicodeStringToString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Destination", "Source"]),
        #
        'RtlAppendUnicodeToString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Destination", "Source"]),
        #
        'RtlUpcaseUnicodeChar': SimTypeFunction([SimTypeChar(label="Char")], SimTypeChar(label="Char"), arg_names=["SourceCharacter"]),
        #
        'RtlDowncaseUnicodeChar': SimTypeFunction([SimTypeChar(label="Char")], SimTypeChar(label="Char"), arg_names=["SourceCharacter"]),
        #
        'RtlFreeUTF8String': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["utf8String"]),
        #
        'RtlxUnicodeStringToAnsiSize': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UnicodeString"]),
        #
        'RtlxAnsiStringToUnicodeSize': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AnsiString"]),
        #
        'RtlUnicodeToUTF8N': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["UTF8StringDestination", "UTF8StringMaxByteCount", "UTF8StringActualByteCount", "UnicodeStringSource", "UnicodeStringByteCount"]),
        #
        'RtlUTF8ToUnicodeN': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["UnicodeStringDestination", "UnicodeStringMaxByteCount", "UnicodeStringActualByteCount", "UTF8StringSource", "UTF8StringByteCount"]),
        #
        'RtlUnicodeStringToUTF8String': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlUTF8StringToUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlStringFromGUID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Guid", "GuidString"]),
        #
        'RtlGUIDFromString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["GuidString", "Guid"]),
        #
        'RtlGenerateClass5Guid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NamespaceGuid", "Buffer", "BufferSize", "Guid"]),
        #
        'RtlPrefetchMemoryNonTemporal': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Source", "Length"]),
        #
        'DbgBreakPointWithStatus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Status"]),
        #
        'DbgPrint': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Format"]),
        #
        'DbgPrintEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ComponentId", "Level", "Format"]),
        #
        'vDbgPrintEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ComponentId", "Level", "Format", "arglist"]),
        #
        'vDbgPrintExWithPrefix': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Prefix", "ComponentId", "Level", "Format", "arglist"]),
        #
        'DbgPrintReturnControlC': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Format"]),
        #
        'DbgQueryDebugFilterState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ComponentId", "Level"]),
        #
        'DbgSetDebugFilterState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["ComponentId", "Level", "State"]),
        #
        'DbgSetDebugPrintCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Output", "ComponentId", "Level"]), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DebugPrintCallback", "Enable"]),
        #
        'RtlTimeToTimeFields': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("TIME_FIELDS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Time", "TimeFields"]),
        #
        'RtlTimeFieldsToTime': SimTypeFunction([SimTypePointer(SimTypeRef("TIME_FIELDS", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeChar(label="Byte"), arg_names=["TimeFields", "Time"]),
        #
        'RtlInitializeBitMap': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["BitMapHeader", "BitMapBuffer", "SizeOfBitMap"]),
        #
        'RtlClearBit': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["BitMapHeader", "BitNumber"]),
        #
        'RtlSetBit': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["BitMapHeader", "BitNumber"]),
        #
        'RtlTestBit': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["BitMapHeader", "BitNumber"]),
        #
        'RtlClearAllBits': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["BitMapHeader"]),
        #
        'RtlSetAllBits': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["BitMapHeader"]),
        #
        'RtlFindClearBits': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "NumberToFind", "HintIndex"]),
        #
        'RtlFindSetBits': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "NumberToFind", "HintIndex"]),
        #
        'RtlFindClearBitsAndSet': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "NumberToFind", "HintIndex"]),
        #
        'RtlFindSetBitsAndClear': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "NumberToFind", "HintIndex"]),
        #
        'RtlClearBits': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["BitMapHeader", "StartingIndex", "NumberToClear"]),
        #
        'RtlSetBits': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["BitMapHeader", "StartingIndex", "NumberToSet"]),
        #
        'RtlFindClearRuns': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_BITMAP_RUN", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "RunArray", "SizeOfRunArray", "LocateLongestRuns"]),
        #
        'RtlFindLongestRunClear': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "StartingIndex"]),
        #
        'RtlFindFirstRunClear': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "StartingIndex"]),
        #
        'RtlNumberOfClearBitsInRange': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "StartingIndex", "Length"]),
        #
        'RtlNumberOfSetBitsInRange': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "StartingIndex", "Length"]),
        #
        'RtlNumberOfClearBits': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader"]),
        #
        'RtlNumberOfSetBits': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader"]),
        #
        'RtlAreBitsClear': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["BitMapHeader", "StartingIndex", "Length"]),
        #
        'RtlAreBitsSet': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["BitMapHeader", "StartingIndex", "Length"]),
        #
        'RtlFindNextForwardRunClear': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "FromIndex", "StartingRunIndex"]),
        #
        'RtlFindLastBackwardRunClear': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["BitMapHeader", "FromIndex", "StartingRunIndex"]),
        #
        'RtlFindLeastSignificantBit': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeChar(label="SByte"), arg_names=["Set"]),
        #
        'RtlFindMostSignificantBit': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeChar(label="SByte"), arg_names=["Set"]),
        #
        'RtlNumberOfSetBitsUlongPtr': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Target"]),
        #
        'RtlCopyBitMap': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Source", "Destination", "TargetBit"]),
        #
        'RtlExtractBitMap': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_BITMAP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Source", "Destination", "TargetBit", "NumberOfBits"]),
        #
        'RtlCreateSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "Revision"]),
        #
        'RtlValidSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["SecurityDescriptor"]),
        #
        'RtlLengthSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SecurityDescriptor"]),
        #
        'RtlValidRelativeSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["SecurityDescriptorInput", "SecurityDescriptorLength", "RequiredInformation"]),
        #
        'RtlSetDaclSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("ACL", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor", "DaclPresent", "Dacl", "DaclDefaulted"]),
        #
        'RtlGetVersion': SimTypeFunction([SimTypePointer(SimTypeRef("OSVERSIONINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpVersionInformation"]),
        #
        'RtlVerifyVersionInfo': SimTypeFunction([SimTypePointer(SimTypeRef("OSVERSIONINFOEXW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["VersionInfo", "TypeMask", "ConditionMask"]),
        #
        'RtlIsNtDdiVersionAvailable': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["Version"]),
        #
        'RtlIsServicePackVersionInstalled': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["Version"]),
        #
        'RtlIoEncodeMemIoResource': SimTypeFunction([SimTypePointer(SimTypeRef("IO_RESOURCE_DESCRIPTOR", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["Descriptor", "Type", "Length", "Alignment", "MinimumAddress", "MaximumAddress"]),
        #
        'RtlCmEncodeMemIoResource': SimTypeFunction([SimTypePointer(SimTypeRef("CM_PARTIAL_RESOURCE_DESCRIPTOR", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["Descriptor", "Type", "Length", "Start"]),
        #
        'RtlIoDecodeMemIoResource': SimTypeFunction([SimTypePointer(SimTypeRef("IO_RESOURCE_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["Descriptor", "Alignment", "MinimumAddress", "MaximumAddress"]),
        #
        'RtlCmDecodeMemIoResource': SimTypeFunction([SimTypePointer(SimTypeRef("CM_PARTIAL_RESOURCE_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["Descriptor", "Start"]),
        #
        'RtlFindClosestEncodableLength': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceLength", "TargetLength"]),
        #
        'RtlIsUntrustedObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "Object", "UntrustedObject"]),
        #
        'RtlQueryValidationRunlevel': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ComponentName"]),
        #
        'NtCreateTransactionManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TmHandle", "DesiredAccess", "ObjectAttributes", "LogFileName", "CreateOptions", "CommitStrength"]),
        #
        'NtOpenTransactionManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TmHandle", "DesiredAccess", "ObjectAttributes", "LogFileName", "TmIdentity", "OpenOptions"]),
        #
        'NtRenameTransactionManager': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogFileName", "ExistingTransactionManagerGuid"]),
        #
        'NtRollforwardTransactionManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionManagerHandle", "TmVirtualClock"]),
        #
        'NtRecoverTransactionManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionManagerHandle"]),
        #
        'NtQueryInformationTransactionManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSACTIONMANAGER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionManagerHandle", "TransactionManagerInformationClass", "TransactionManagerInformation", "TransactionManagerInformationLength", "ReturnLength"]),
        #
        'NtSetInformationTransactionManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSACTIONMANAGER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TmHandle", "TransactionManagerInformationClass", "TransactionManagerInformation", "TransactionManagerInformationLength"]),
        #
        'NtEnumerateTransactionObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="KTMOBJECT_TYPE"), SimTypePointer(SimTypeRef("KTMOBJECT_CURSOR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RootObjectHandle", "QueryType", "ObjectCursor", "ObjectCursorLength", "ReturnLength"]),
        #
        'NtCreateTransaction': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "DesiredAccess", "ObjectAttributes", "Uow", "TmHandle", "CreateOptions", "IsolationLevel", "IsolationFlags", "Timeout", "Description"]),
        #
        'NtOpenTransaction': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "DesiredAccess", "ObjectAttributes", "Uow", "TmHandle"]),
        #
        'NtQueryInformationTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSACTION_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "TransactionInformationClass", "TransactionInformation", "TransactionInformationLength", "ReturnLength"]),
        #
        'NtSetInformationTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSACTION_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "TransactionInformationClass", "TransactionInformation", "TransactionInformationLength"]),
        #
        'NtCommitTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "Wait"]),
        #
        'NtRollbackTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "Wait"]),
        #
        'NtCreateEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "DesiredAccess", "ResourceManagerHandle", "TransactionHandle", "ObjectAttributes", "CreateOptions", "NotificationMask", "EnlistmentKey"]),
        #
        'NtOpenEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "DesiredAccess", "ResourceManagerHandle", "EnlistmentGuid", "ObjectAttributes"]),
        #
        'NtQueryInformationEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ENLISTMENT_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "EnlistmentInformationClass", "EnlistmentInformation", "EnlistmentInformationLength", "ReturnLength"]),
        #
        'NtSetInformationEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ENLISTMENT_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "EnlistmentInformationClass", "EnlistmentInformation", "EnlistmentInformationLength"]),
        #
        'NtRecoverEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "EnlistmentKey"]),
        #
        'NtPrePrepareEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'NtPrepareEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'NtCommitEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'NtRollbackEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'NtPrePrepareComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'NtPrepareComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'NtCommitComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'NtReadOnlyEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'NtRollbackComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'NtSinglePhaseReject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'NtCreateResourceManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "DesiredAccess", "TmHandle", "RmGuid", "ObjectAttributes", "CreateOptions", "Description"]),
        #
        'NtOpenResourceManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "DesiredAccess", "TmHandle", "ResourceManagerGuid", "ObjectAttributes"]),
        #
        'NtRecoverResourceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle"]),
        #
        'NtGetNotificationResourceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TRANSACTION_NOTIFICATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "TransactionNotification", "NotificationLength", "Timeout", "ReturnLength", "Asynchronous", "AsynchronousContext"]),
        #
        'NtQueryInformationResourceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RESOURCEMANAGER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "ResourceManagerInformationClass", "ResourceManagerInformation", "ResourceManagerInformationLength", "ReturnLength"]),
        #
        'NtSetInformationResourceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RESOURCEMANAGER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "ResourceManagerInformationClass", "ResourceManagerInformation", "ResourceManagerInformationLength"]),
        #
        'NtRegisterProtocolAddressInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManager", "ProtocolId", "ProtocolInformationSize", "ProtocolInformation", "CreateOptions"]),
        #
        'NtPropagationComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "RequestCookie", "BufferLength", "Buffer"]),
        #
        'NtPropagationFailed': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "RequestCookie", "PropStatus"]),
        #
        'KfRaiseIrql': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["NewIrql"]),
        #
        'KeFlushIoBuffers': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Mdl", "ReadOperation", "DmaOperation"]),
        #
        'KeGetCurrentIrql': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'KeInitializeDpc': SimTypeFunction([SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Dpc", "DeferredRoutine", "DeferredContext"]),
        #
        'KeInitializeThreadedDpc': SimTypeFunction([SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Dpc", "DeferredRoutine", "DeferredContext"]),
        #
        'KeInsertQueueDpc': SimTypeFunction([SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Dpc", "SystemArgument1", "SystemArgument2"]),
        #
        'KeRemoveQueueDpc': SimTypeFunction([SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Dpc"]),
        #
        'KeRemoveQueueDpcEx': SimTypeFunction([SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["Dpc", "WaitIfActive"]),
        #
        'KeInitializeCrashDumpHeader': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DumpType", "Flags", "Buffer", "BufferSize", "BufferNeeded"]),
        #
        'KeSetImportanceDpc': SimTypeFunction([SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0), SimTypeInt(signed=False, label="KDPC_IMPORTANCE")], SimTypeBottom(label="Void"), arg_names=["Dpc", "Importance"]),
        #
        'KeSetTargetProcessorDpc': SimTypeFunction([SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["Dpc", "Number"]),
        #
        'KeFlushQueuedDpcs': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'KeInitializeDeviceQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KDEVICE_QUEUE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceQueue"]),
        #
        'KeInsertDeviceQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KDEVICE_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("KDEVICE_QUEUE_ENTRY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["DeviceQueue", "DeviceQueueEntry"]),
        #
        'KeInsertByKeyDeviceQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KDEVICE_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("KDEVICE_QUEUE_ENTRY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["DeviceQueue", "DeviceQueueEntry", "SortKey"]),
        #
        'KeRemoveDeviceQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KDEVICE_QUEUE", SimStruct), offset=0)], SimTypePointer(SimTypeRef("KDEVICE_QUEUE_ENTRY", SimStruct), offset=0), arg_names=["DeviceQueue"]),
        #
        'KeRemoveByKeyDeviceQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KDEVICE_QUEUE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("KDEVICE_QUEUE_ENTRY", SimStruct), offset=0), arg_names=["DeviceQueue", "SortKey"]),
        #
        'KeRemoveByKeyDeviceQueueIfBusy': SimTypeFunction([SimTypePointer(SimTypeRef("KDEVICE_QUEUE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("KDEVICE_QUEUE_ENTRY", SimStruct), offset=0), arg_names=["DeviceQueue", "SortKey"]),
        #
        'KeRemoveEntryDeviceQueue': SimTypeFunction([SimTypePointer(SimTypeRef("KDEVICE_QUEUE", SimStruct), offset=0), SimTypePointer(SimTypeRef("KDEVICE_QUEUE_ENTRY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["DeviceQueue", "DeviceQueueEntry"]),
        #
        'KeSynchronizeExecution': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([], SimTypeChar(label="Byte")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Interrupt", "SynchronizeRoutine", "SynchronizeContext"]),
        #
        'KeAcquireInterruptSpinLock': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Interrupt"]),
        #
        'KeReleaseInterruptSpinLock': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Interrupt", "OldIrql"]),
        #
        'KeInitializeEvent': SimTypeFunction([SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), SimTypeInt(signed=False, label="EVENT_TYPE"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Event", "Type", "State"]),
        #
        'KeClearEvent': SimTypeFunction([SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Event"]),
        #
        'KeReadStateEvent': SimTypeFunction([SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Event"]),
        #
        'KeResetEvent': SimTypeFunction([SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Event"]),
        #
        'KeSetEvent': SimTypeFunction([SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Event", "Increment", "Wait"]),
        #
        'KeInitializeMutex': SimTypeFunction([SimTypePointer(SimTypeRef("KMUTANT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Mutex", "Level"]),
        #
        'KeReadStateMutex': SimTypeFunction([SimTypePointer(SimTypeRef("KMUTANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Mutex"]),
        #
        'KeReleaseMutex': SimTypeFunction([SimTypePointer(SimTypeRef("KMUTANT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Mutex", "Wait"]),
        #
        'KeInitializeSemaphore': SimTypeFunction([SimTypePointer(SimTypeRef("KSEMAPHORE", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["Semaphore", "Count", "Limit"]),
        #
        'KeReadStateSemaphore': SimTypeFunction([SimTypePointer(SimTypeRef("KSEMAPHORE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Semaphore"]),
        #
        'KeReleaseSemaphore': SimTypeFunction([SimTypePointer(SimTypeRef("KSEMAPHORE", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Semaphore", "Increment", "Adjustment", "Wait"]),
        #
        'KeDelayExecutionThread': SimTypeFunction([SimTypeChar(label="SByte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WaitMode", "Alertable", "Interval"]),
        #
        'KeQueryPriorityThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread"]),
        #
        'KeQueryRuntimeThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Thread", "UserTime"]),
        #
        'KeQueryTotalCycleTimeThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["Thread", "CycleTimeStamp"]),
        #
        'KeSetTargetProcessorDpcEx': SimTypeFunction([SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROCESSOR_NUMBER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Dpc", "ProcNumber"]),
        #
        'KeRevertToUserAffinityThread': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'KeSetSystemAffinityThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Affinity"]),
        #
        'KeRevertToUserAffinityThreadEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Affinity"]),
        #
        'KeSetSystemGroupAffinityThread': SimTypeFunction([SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), offset=0), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Affinity", "PreviousAffinity"]),
        #
        'KeRevertToUserGroupAffinityThread': SimTypeFunction([SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PreviousAffinity"]),
        #
        'KeSetSystemAffinityThreadEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["Affinity"]),
        #
        'KeSetPriorityThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread", "Priority"]),
        #
        'KeEnterCriticalRegion': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'KeLeaveCriticalRegion': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'KeEnterGuardedRegion': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'KeLeaveGuardedRegion': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'KeAreApcsDisabled': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'KeInitializeTimer': SimTypeFunction([SimTypePointer(SimTypeRef("KTIMER", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Timer"]),
        #
        'KeInitializeTimerEx': SimTypeFunction([SimTypePointer(SimTypeRef("KTIMER", SimStruct), offset=0), SimTypeInt(signed=False, label="TIMER_TYPE")], SimTypeBottom(label="Void"), arg_names=["Timer", "Type"]),
        #
        'KeCancelTimer': SimTypeFunction([SimTypePointer(SimTypeRef("KTIMER", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["param0"]),
        #
        'KeReadStateTimer': SimTypeFunction([SimTypePointer(SimTypeRef("KTIMER", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Timer"]),
        #
        'KeSetTimer': SimTypeFunction([SimTypePointer(SimTypeRef("KTIMER", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Timer", "DueTime", "Dpc"]),
        #
        'KeSetTimerEx': SimTypeFunction([SimTypePointer(SimTypeRef("KTIMER", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Timer", "DueTime", "Period", "Dpc"]),
        #
        'KeSetCoalescableTimer': SimTypeFunction([SimTypePointer(SimTypeRef("KTIMER", SimStruct), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("KDPC", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Timer", "DueTime", "Period", "TolerableDelay", "Dpc"]),
        #
        'KeWaitForMultipleObjects': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="WAIT_TYPE"), SimTypeInt(signed=False, label="KWAIT_REASON"), SimTypeChar(label="SByte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("KWAIT_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Count", "Object", "WaitType", "WaitReason", "WaitMode", "Alertable", "Timeout", "WaitBlockArray"]),
        #
        'KeWaitForSingleObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="KWAIT_REASON"), SimTypeChar(label="SByte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "WaitReason", "WaitMode", "Alertable", "Timeout"]),
        #
        'KeIpiGenericCall': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["BroadcastFunction", "Context"]),
        #
        'KeInitializeSpinLock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["SpinLock"]),
        #
        'KeTestSpinLock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["SpinLock"]),
        #
        'KeTryToAcquireSpinLockAtDpcLevel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["SpinLock"]),
        #
        'KeAcquireSpinLockForDpc': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["SpinLock"]),
        #
        'KeReleaseSpinLockForDpc': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["SpinLock", "OldIrql"]),
        #
        'KeAcquireInStackQueuedSpinLock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("KLOCK_QUEUE_HANDLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SpinLock", "LockHandle"]),
        #
        'KeReleaseInStackQueuedSpinLock': SimTypeFunction([SimTypePointer(SimTypeRef("KLOCK_QUEUE_HANDLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["LockHandle"]),
        #
        'KeAcquireInStackQueuedSpinLockAtDpcLevel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("KLOCK_QUEUE_HANDLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SpinLock", "LockHandle"]),
        #
        'KeReleaseInStackQueuedSpinLockFromDpcLevel': SimTypeFunction([SimTypePointer(SimTypeRef("KLOCK_QUEUE_HANDLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["LockHandle"]),
        #
        'KeAcquireInStackQueuedSpinLockForDpc': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("KLOCK_QUEUE_HANDLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SpinLock", "LockHandle"]),
        #
        'KeReleaseInStackQueuedSpinLockForDpc': SimTypeFunction([SimTypePointer(SimTypeRef("KLOCK_QUEUE_HANDLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["LockHandle"]),
        #
        'KeQueryDpcWatchdogInformation': SimTypeFunction([SimTypePointer(SimTypeRef("KDPC_WATCHDOG_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WatchdogInformation"]),
        #
        'KeIsExecutingDpc': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'KeDeregisterBugCheckCallback': SimTypeFunction([SimTypePointer(SimTypeRef("KBUGCHECK_CALLBACK_RECORD", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["CallbackRecord"]),
        #
        'KeRegisterBugCheckCallback': SimTypeFunction([SimTypePointer(SimTypeRef("KBUGCHECK_CALLBACK_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["CallbackRecord", "CallbackRoutine", "Buffer", "Length", "Component"]),
        #
        'KeInitializeTriageDumpDataArray': SimTypeFunction([SimTypePointer(SimTypeRef("KTRIAGE_DUMP_DATA_ARRAY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["KtriageDumpDataArray", "Size"]),
        #
        'KeAddTriageDumpDataBlock': SimTypeFunction([SimTypePointer(SimTypeRef("KTRIAGE_DUMP_DATA_ARRAY", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KtriageDumpDataArray", "Address", "Size"]),
        #
        'KeDeregisterBugCheckReasonCallback': SimTypeFunction([SimTypePointer(SimTypeRef("KBUGCHECK_REASON_CALLBACK_RECORD", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["CallbackRecord"]),
        #
        'KeRegisterBugCheckReasonCallback': SimTypeFunction([SimTypePointer(SimTypeRef("KBUGCHECK_REASON_CALLBACK_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypeInt(signed=False, label="KBUGCHECK_CALLBACK_REASON"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeChar(label="Byte"), arg_names=["CallbackRecord", "CallbackRoutine", "Reason", "Component"]),
        #
        'KeRegisterNmiCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeChar(label="Byte")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["CallbackRoutine", "Context"]),
        #
        'KeDeregisterNmiCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'KeRegisterBoundCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeInt(signed=False, label="BOUND_CALLBACK_STATUS")), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["CallbackRoutine"]),
        #
        'KeDeregisterBoundCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'KeBugCheckEx': SimTypeFunction([SimTypeInt(signed=False, label="BUGCHECK_ERROR"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["BugCheckCode", "BugCheckParameter1", "BugCheckParameter2", "BugCheckParameter3", "BugCheckParameter4"]),
        #
        'KeQuerySystemTimePrecise': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CurrentTime"]),
        #
        'KeQueryInterruptTimePrecise': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["QpcTimeStamp"]),
        #
        'KeQueryUnbiasedInterruptTimePrecise': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["QpcTimeStamp"]),
        #
        'KeQueryTimeIncrement': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'KeQueryUnbiasedInterruptTime': SimTypeFunction([], SimTypeLongLong(signed=False, label="UInt64")),
        #
        'KeGetRecommendedSharedDataAlignment': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'KeQueryActiveProcessors': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)),
        #
        'KeQueryActiveProcessorCount': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ActiveProcessors"]),
        #
        'KeQueryActiveProcessorCountEx': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["GroupNumber"]),
        #
        'KeQueryMaximumProcessorCount': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'KeQueryMaximumProcessorCountEx': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["GroupNumber"]),
        #
        'KeQueryActiveGroupCount': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'KeQueryMaximumGroupCount': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'KeQueryGroupAffinity': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["GroupNumber"]),
        #
        'KeGetCurrentProcessorNumberEx': SimTypeFunction([SimTypePointer(SimTypeRef("PROCESSOR_NUMBER", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProcNumber"]),
        #
        'KeQueryNodeActiveAffinity': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NodeNumber", "Affinity", "Count"]),
        #
        'KeQueryNodeMaximumProcessorCount': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["NodeNumber"]),
        #
        'KeQueryHighestNodeNumber': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'KeGetCurrentNodeNumber': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'KeQueryLogicalProcessorRelationship': SimTypeFunction([SimTypePointer(SimTypeRef("PROCESSOR_NUMBER", SimStruct), offset=0), SimTypeInt(signed=False, label="LOGICAL_PROCESSOR_RELATIONSHIP"), SimTypePointer(SimTypeRef("SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessorNumber", "RelationshipType", "Information", "Length"]),
        #
        'KeShouldYieldProcessor': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'KeQueryNodeActiveAffinity2': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NodeNumber", "GroupAffinities", "GroupAffinitiesCount", "GroupAffinitiesRequired"]),
        #
        'KeQueryNodeActiveProcessorCount': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["NodeNumber"]),
        #
        'KeAreAllApcsDisabled': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'KeInitializeGuardedMutex': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mutex"]),
        #
        'KeAcquireGuardedMutex': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mutex"]),
        #
        'KeReleaseGuardedMutex': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mutex"]),
        #
        'KeTryToAcquireGuardedMutex': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Mutex"]),
        #
        'KeAcquireGuardedMutexUnsafe': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FastMutex"]),
        #
        'KeReleaseGuardedMutexUnsafe': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FastMutex"]),
        #
        'KeRegisterProcessorChangeCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["CallbackFunction", "CallbackContext", "Flags"]),
        #
        'KeDeregisterProcessorChangeCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackHandle"]),
        #
        'KeGetProcessorNumberFromIndex': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROCESSOR_NUMBER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcIndex", "ProcNumber"]),
        #
        'KeGetProcessorIndexFromNumber': SimTypeFunction([SimTypePointer(SimTypeRef("PROCESSOR_NUMBER", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProcNumber"]),
        #
        'KeSaveExtendedProcessorState': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("XSTATE_SAVE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Mask", "XStateSave"]),
        #
        'KeRestoreExtendedProcessorState': SimTypeFunction([SimTypePointer(SimTypeRef("XSTATE_SAVE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["XStateSave"]),
        #
        'KeConvertAuxiliaryCounterToPerformanceCounter': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuxiliaryCounterValue", "PerformanceCounterValue", "ConversionError"]),
        #
        'KeConvertPerformanceCounterToAuxiliaryCounter': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PerformanceCounterValue", "AuxiliaryCounterValue", "ConversionError"]),
        #
        'KeQueryAuxiliaryCounterFrequency': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuxiliaryCounterFrequency"]),
        #
        'KdDisableDebugger': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'KdEnableDebugger': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'KdRefreshDebuggerNotPresent': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'KdChangeOption': SimTypeFunction([SimTypeInt(signed=False, label="KD_OPTION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Option", "InBufferBytes", "InBuffer", "OutBufferBytes", "OutBuffer", "OutBufferNeeded"]),
        #
        'ExAllocatePool': SimTypeFunction([SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PoolType", "NumberOfBytes"]),
        #
        'ExAllocatePoolWithQuota': SimTypeFunction([SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PoolType", "NumberOfBytes"]),
        #
        'ExAllocatePoolWithTag': SimTypeFunction([SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PoolType", "NumberOfBytes", "Tag"]),
        #
        'ExAllocatePoolWithTagPriority': SimTypeFunction([SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="EX_POOL_PRIORITY")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PoolType", "NumberOfBytes", "Tag", "Priority"]),
        #
        'ExAllocatePool2': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Flags", "NumberOfBytes", "Tag"]),
        #
        'ExAllocatePool3': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POOL_EXTENDED_PARAMETER", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Flags", "NumberOfBytes", "Tag", "ExtendedParameters", "ExtendedParametersCount"]),
        #
        'ExFreePool2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("POOL_EXTENDED_PARAMETER", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["P", "Tag", "ExtendedParameters", "ExtendedParametersCount"]),
        #
        'ExCreatePool': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("POOL_CREATE_EXTENDED_PARAMS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "Tag", "Params", "PoolHandle"]),
        #
        'ExDestroyPool': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["PoolHandle"]),
        #
        'ExSecurePoolUpdate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurePoolHandle", "Tag", "Allocation", "Cookie", "Offset", "Size", "Buffer"]),
        #
        'ExSecurePoolValidate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SecurePoolHandle", "Tag", "Allocation", "Cookie"]),
        #
        'ExAllocatePoolWithQuotaTag': SimTypeFunction([SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PoolType", "NumberOfBytes", "Tag"]),
        #
        'ExFreePool': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["P"]),
        #
        'ExFreePoolWithTag': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["P", "Tag"]),
        #
        'ExAcquireFastMutexUnsafe': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FastMutex"]),
        #
        'ExReleaseFastMutexUnsafe': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FastMutex"]),
        #
        'ExAcquireFastMutex': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FastMutex"]),
        #
        'ExReleaseFastMutex': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FastMutex"]),
        #
        'ExTryToAcquireFastMutex': SimTypeFunction([SimTypePointer(SimTypeRef("FAST_MUTEX", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FastMutex"]),
        #
        'ExInterlockedAddLargeInteger': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["Addend", "Increment", "Lock"]),
        #
        'ProbeForRead': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Address", "Length", "Alignment"]),
        #
        'ExRaiseStatus': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["Status"]),
        #
        'ProbeForWrite': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Address", "Length", "Alignment"]),
        #
        'ExQueueWorkItem': SimTypeFunction([SimTypePointer(SimTypeRef("WORK_QUEUE_ITEM", SimStruct), offset=0), SimTypeInt(signed=False, label="WORK_QUEUE_TYPE")], SimTypeBottom(label="Void"), arg_names=["WorkItem", "QueueType"]),
        #
        'ExIsProcessorFeaturePresent': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["ProcessorFeature"]),
        #
        'ExInitializeResourceLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Resource"]),
        #
        'ExReinitializeResourceLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Resource"]),
        #
        'ExAcquireResourceSharedLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["Resource", "Wait"]),
        #
        'ExEnterCriticalRegionAndAcquireResourceShared': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Resource"]),
        #
        'ExAcquireResourceExclusiveLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["Resource", "Wait"]),
        #
        'ExEnterCriticalRegionAndAcquireResourceExclusive': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Resource"]),
        #
        'ExAcquireSharedStarveExclusive': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["Resource", "Wait"]),
        #
        'ExAcquireSharedWaitForExclusive': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["Resource", "Wait"]),
        #
        'ExEnterCriticalRegionAndAcquireSharedWaitForExclusive': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Resource"]),
        #
        'ExReleaseResourceLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Resource"]),
        #
        'ExReleaseResourceAndLeaveCriticalRegion': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Resource"]),
        #
        'ExReleaseResourceForThreadLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Resource", "ResourceThreadId"]),
        #
        'ExSetResourceOwnerPointer': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Resource", "OwnerPointer"]),
        #
        'ExSetResourceOwnerPointerEx': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Resource", "OwnerPointer", "Flags"]),
        #
        'ExConvertExclusiveToSharedLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Resource"]),
        #
        'ExDeleteResourceLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Resource"]),
        #
        'ExGetExclusiveWaiterCount': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Resource"]),
        #
        'ExGetSharedWaiterCount': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Resource"]),
        #
        'ExIsResourceAcquiredExclusiveLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Resource"]),
        #
        'ExIsResourceAcquiredSharedLite': SimTypeFunction([SimTypePointer(SimTypeRef("ERESOURCE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Resource"]),
        #
        'ExGetPreviousMode': SimTypeFunction([], SimTypeChar(label="SByte")),
        #
        'ExSetTimerResolution': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeInt(signed=False, label="UInt32"), arg_names=["DesiredTime", "SetResolution"]),
        #
        'ExQueryTimerResolution': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["MaximumTime", "MinimumTime", "CurrentTime"]),
        #
        'ExSystemTimeToLocalTime': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SystemTime", "LocalTime"]),
        #
        'ExLocalTimeToSystemTime': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeBottom(label="Void"), arg_names=["LocalTime", "SystemTime"]),
        #
        'ExAllocateTimer': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Callback", "CallbackContext", "Attributes"]),
        #
        'ExSetTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeRef("_EXT_SET_PARAMETERS_V0", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Timer", "DueTime", "Period", "Parameters"]),
        #
        'ExCancelTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Timer", "Parameters"]),
        #
        'ExDeleteTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("EXT_DELETE_PARAMETERS", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Timer", "Cancel", "Wait", "Parameters"]),
        #
        'ExCreateCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackObject", "ObjectAttributes", "Create", "AllowMultipleCallbacks"]),
        #
        'ExRegisterCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["CallbackObject", "CallbackFunction", "CallbackContext"]),
        #
        'ExUnregisterCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackRegistration"]),
        #
        'ExNotifyCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackObject", "Argument1", "Argument2"]),
        #
        'ExVerifySuite': SimTypeFunction([SimTypeInt(signed=False, label="SUITE_TYPE")], SimTypeChar(label="Byte"), arg_names=["SuiteType"]),
        #
        'ExInitializeRundownProtection': SimTypeFunction([SimTypePointer(SimTypeRef("EX_RUNDOWN_REF", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRef"]),
        #
        'ExReInitializeRundownProtection': SimTypeFunction([SimTypePointer(SimTypeRef("EX_RUNDOWN_REF", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRef"]),
        #
        'ExAcquireRundownProtection': SimTypeFunction([SimTypePointer(SimTypeRef("EX_RUNDOWN_REF", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["RunRef"]),
        #
        'ExAcquireRundownProtectionEx': SimTypeFunction([SimTypePointer(SimTypeRef("EX_RUNDOWN_REF", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["RunRef", "Count"]),
        #
        'ExReleaseRundownProtection': SimTypeFunction([SimTypePointer(SimTypeRef("EX_RUNDOWN_REF", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRef"]),
        #
        'ExReleaseRundownProtectionEx': SimTypeFunction([SimTypePointer(SimTypeRef("EX_RUNDOWN_REF", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["RunRef", "Count"]),
        #
        'ExRundownCompleted': SimTypeFunction([SimTypePointer(SimTypeRef("EX_RUNDOWN_REF", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRef"]),
        #
        'ExWaitForRundownProtectionRelease': SimTypeFunction([SimTypePointer(SimTypeRef("EX_RUNDOWN_REF", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRef"]),
        #
        'ExAllocateCacheAwareRundownProtection': SimTypeFunction([SimTypeInt(signed=False, label="POOL_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["PoolType", "PoolTag"]),
        #
        'ExSizeOfRundownProtectionCacheAware': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)),
        #
        'ExInitializeRundownProtectionCacheAware': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRefCacheAware", "RunRefSize"]),
        #
        'ExFreeCacheAwareRundownProtection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRefCacheAware"]),
        #
        'ExAcquireRundownProtectionCacheAware': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["RunRefCacheAware"]),
        #
        'ExReleaseRundownProtectionCacheAware': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRefCacheAware"]),
        #
        'ExAcquireRundownProtectionCacheAwareEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["RunRefCacheAware", "Count"]),
        #
        'ExReleaseRundownProtectionCacheAwareEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["RunRef", "Count"]),
        #
        'ExWaitForRundownProtectionReleaseCacheAware': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRef"]),
        #
        'ExReInitializeRundownProtectionCacheAware': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRefCacheAware"]),
        #
        'ExRundownCompletedCacheAware': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRefCacheAware"]),
        #
        'ExInitializeRundownProtectionCacheAwareEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["RunRefCacheAware", "Flags"]),
        #
        'ExCleanupRundownProtectionCacheAware': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["RunRefCacheAware"]),
        #
        'ExInitializePushLock': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["PushLock"]),
        #
        'ExAcquirePushLockExclusiveEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["PushLock", "Flags"]),
        #
        'ExAcquirePushLockSharedEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["PushLock", "Flags"]),
        #
        'ExReleasePushLockExclusiveEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["PushLock", "Flags"]),
        #
        'ExReleasePushLockSharedEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["PushLock", "Flags"]),
        #
        'ExAcquireSpinLockSharedAtDpcLevel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SpinLock"]),
        #
        'ExAcquireSpinLockShared': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["SpinLock"]),
        #
        'ExReleaseSpinLockSharedFromDpcLevel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SpinLock"]),
        #
        'ExReleaseSpinLockShared': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["SpinLock", "OldIrql"]),
        #
        'ExTryConvertSharedSpinLockExclusive': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SpinLock"]),
        #
        'ExAcquireSpinLockExclusiveAtDpcLevel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SpinLock"]),
        #
        'ExAcquireSpinLockExclusive': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["SpinLock"]),
        #
        'ExReleaseSpinLockExclusiveFromDpcLevel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SpinLock"]),
        #
        'ExReleaseSpinLockExclusive': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["SpinLock", "OldIrql"]),
        #
        'ExTryAcquireSpinLockSharedAtDpcLevel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SpinLock"]),
        #
        'ExTryAcquireSpinLockExclusiveAtDpcLevel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["SpinLock"]),
        #
        'ExGetFirmwareEnvironmentVariable': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VariableName", "VendorGuid", "Value", "ValueLength", "Attributes"]),
        #
        'ExSetFirmwareEnvironmentVariable': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["VariableName", "VendorGuid", "Value", "ValueLength", "Attributes"]),
        #
        'ExIsManufacturingModeEnabled': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'ExIsSoftBoot': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'ExGetFirmwareType': SimTypeFunction([], SimTypeInt(signed=False, label="FIRMWARE_TYPE")),
        #
        'ExEnumerateSystemFirmwareTables': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FirmwareTableProviderSignature", "FirmwareTableBuffer", "BufferLength", "ReturnLength"]),
        #
        'ExGetSystemFirmwareTable': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FirmwareTableProviderSignature", "FirmwareTableID", "FirmwareTableBuffer", "BufferLength", "ReturnLength"]),
        #
        'CmRegisterCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Function", "Context", "Cookie"]),
        #
        'CmUnRegisterCallback': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64")], SimTypeInt(signed=True, label="Int32"), arg_names=["Cookie"]),
        #
        'CmRegisterCallbackEx': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Function", "Altitude", "Driver", "Context", "Cookie", "Reserved"]),
        #
        'CmGetCallbackVersion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Major", "Minor"]),
        #
        'CmSetCallbackObjectContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "Cookie", "NewContext", "OldContext"]),
        #
        'CmCallbackGetKeyObjectID': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Cookie", "Object", "ObjectID", "ObjectName"]),
        #
        'CmGetBoundTransaction': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Cookie", "Object"]),
        #
        'CmCallbackGetKeyObjectIDEx': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Cookie", "Object", "ObjectID", "ObjectName", "Flags"]),
        #
        'CmCallbackReleaseKeyObjectIDEx': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ObjectName"]),
        #
        'MmQuerySystemSize': SimTypeFunction([], SimTypeInt(signed=False, label="MM_SYSTEMSIZE")),
        #
        'MmIsVerifierEnabled': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VerifierFlags"]),
        #
        'MmAddVerifierThunks': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ThunkBuffer", "ThunkBufferSize"]),
        #
        'MmAddVerifierSpecialThunks': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["EntryRoutine", "ThunkBuffer", "ThunkBufferSize"]),
        #
        'MmProbeAndLockSelectedPages': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimUnion({"Buffer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Alignment": SimTypeLongLong(signed=False, label="UInt64")}, name="<anon>", label="None"), offset=0), SimTypeChar(label="SByte"), SimTypeInt(signed=False, label="LOCK_OPERATION")], SimTypeBottom(label="Void"), arg_names=["MemoryDescriptorList", "SegmentArray", "AccessMode", "Operation"]),
        #
        'MmProbeAndLockProcessPages': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="SByte"), SimTypeInt(signed=False, label="LOCK_OPERATION")], SimTypeBottom(label="Void"), arg_names=["MemoryDescriptorList", "Process", "AccessMode", "Operation"]),
        #
        'MmProbeAndLockPages': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeChar(label="SByte"), SimTypeInt(signed=False, label="LOCK_OPERATION")], SimTypeBottom(label="Void"), arg_names=["MemoryDescriptorList", "AccessMode", "Operation"]),
        #
        'MmUnlockPages': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["MemoryDescriptorList"]),
        #
        'MmBuildMdlForNonPagedPool': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["MemoryDescriptorList"]),
        #
        'MmAllocateMdlForIoSpace': SimTypeFunction([SimTypePointer(SimTypeRef("MM_PHYSICAL_ADDRESS_LIST", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PhysicalAddressList", "NumberOfEntries", "NewMdl"]),
        #
        'MmAreMdlPagesCached': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["MemoryDescriptorList"]),
        #
        'MmSetPermanentCacheAttribute': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["StartAddress", "NumberOfBytes", "CacheType", "Flags"]),
        #
        'MmMapLockedPages': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeChar(label="SByte")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["MemoryDescriptorList", "AccessMode"]),
        #
        'MmMapMdl': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MemoryDescriptorList", "Protection", "DriverRoutine", "DriverContext"]),
        #
        'MmMapMemoryDumpMdlEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Va", "PageTotal", "MemoryDumpMdl", "Flags"]),
        #
        'MmIsIoSpaceActive': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["StartAddress", "NumberOfBytes"]),
        #
        'MmAdvanceMdl': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Mdl", "NumberOfBytes"]),
        #
        'MmProtectMdlSystemAddress': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["MemoryDescriptorList", "NewProtect"]),
        #
        'MmMapLockedPagesSpecifyCache': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeChar(label="SByte"), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["MemoryDescriptorList", "AccessMode", "CacheType", "RequestedAddress", "BugCheckOnFailure", "Priority"]),
        #
        'MmUnmapLockedPages': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["BaseAddress", "MemoryDescriptorList"]),
        #
        'MmAllocateMappingAddressEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NumberOfBytes", "PoolTag", "Flags"]),
        #
        'MmAllocateMappingAddress': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NumberOfBytes", "PoolTag"]),
        #
        'MmFreeMappingAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["BaseAddress", "PoolTag"]),
        #
        'MmMapLockedPagesWithReservedMapping': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["MappingAddress", "PoolTag", "MemoryDescriptorList", "CacheType"]),
        #
        'MmUnmapReservedMapping': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["BaseAddress", "PoolTag", "MemoryDescriptorList"]),
        #
        'MmAllocateNodePagesForMdlEx': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), arg_names=["LowAddress", "HighAddress", "SkipBytes", "TotalBytes", "CacheType", "IdealNode", "Flags"]),
        #
        'MmAllocatePartitionNodePagesForMdlEx': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), arg_names=["LowAddress", "HighAddress", "SkipBytes", "TotalBytes", "CacheType", "IdealNode", "Flags", "PartitionObject"]),
        #
        'MmAllocatePagesForMdlEx': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), arg_names=["LowAddress", "HighAddress", "SkipBytes", "TotalBytes", "CacheType", "Flags"]),
        #
        'MmAllocatePagesForMdl': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), arg_names=["LowAddress", "HighAddress", "SkipBytes", "TotalBytes"]),
        #
        'MmFreePagesFromMdlEx': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["MemoryDescriptorList", "Flags"]),
        #
        'MmFreePagesFromMdl': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["MemoryDescriptorList"]),
        #
        'MmMapIoSpace': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PhysicalAddress", "NumberOfBytes", "CacheType"]),
        #
        'MmUnmapIoSpace': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["BaseAddress", "NumberOfBytes"]),
        #
        'MmMapIoSpaceEx': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PhysicalAddress", "NumberOfBytes", "Protect"]),
        #
        'MmAllocateContiguousMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NumberOfBytes", "HighestAcceptableAddress"]),
        #
        'MmAllocateContiguousMemorySpecifyCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NumberOfBytes", "LowestAcceptableAddress", "HighestAcceptableAddress", "BoundaryAddressMultiple", "CacheType"]),
        #
        'MmAllocateContiguousMemorySpecifyCacheNode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NumberOfBytes", "LowestAcceptableAddress", "HighestAcceptableAddress", "BoundaryAddressMultiple", "CacheType", "PreferredNode"]),
        #
        'MmAllocateContiguousNodeMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NumberOfBytes", "LowestAcceptableAddress", "HighestAcceptableAddress", "BoundaryAddressMultiple", "Protect", "PreferredNode"]),
        #
        'MmAllocateContiguousMemoryEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NumberOfBytes", "LowestAcceptableAddress", "HighestAcceptableAddress", "BoundaryAddressMultiple", "PreferredNode", "Protect", "PartitionObject", "Tag", "Flags", "BaseAddress"]),
        #
        'MmFreeContiguousMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["BaseAddress"]),
        #
        'MmFreeContiguousMemorySpecifyCache': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE")], SimTypeBottom(label="Void"), arg_names=["BaseAddress", "NumberOfBytes", "CacheType"]),
        #
        'MmSizeOfMdl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["Base", "Length"]),
        #
        'MmCreateMdl': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), arg_names=["MemoryDescriptorList", "Base", "Length"]),
        #
        'MmMdlPageContentsState': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="MM_MDL_PAGE_CONTENTS_STATE")], SimTypeInt(signed=False, label="MM_MDL_PAGE_CONTENTS_STATE"), arg_names=["MemoryDescriptorList", "State"]),
        #
        'MmLockPagableDataSection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["AddressWithinSection"]),
        #
        'MmResetDriverPaging': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["AddressWithinSection"]),
        #
        'MmPageEntireDriver': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["AddressWithinSection"]),
        #
        'MmUnlockPagableImageSection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ImageSectionHandle"]),
        #
        'MmIsDriverSuspectForVerifier': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DriverObject"]),
        #
        'MmIsDriverVerifying': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DriverObject"]),
        #
        'MmIsDriverVerifyingByAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AddressWithinSection"]),
        #
        'MmProtectDriverSection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["AddressWithinSection", "Size", "Flags"]),
        #
        'SeCaptureSubjectContext': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SubjectContext"]),
        #
        'SeLockSubjectContext': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SubjectContext"]),
        #
        'SeUnlockSubjectContext': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SubjectContext"]),
        #
        'SeReleaseSubjectContext': SimTypeFunction([SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["SubjectContext"]),
        #
        'SeAssignSecurity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeInt(signed=False, label="POOL_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["ParentDescriptor", "ExplicitDescriptor", "NewDescriptor", "IsDirectoryObject", "SubjectContext", "GenericMapping", "PoolType"]),
        #
        'SeComputeAutoInheritByObjectType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ObjectType", "SecurityDescriptor", "ParentSecurityDescriptor"]),
        #
        'SeAssignSecurityEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeInt(signed=False, label="POOL_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["ParentDescriptor", "ExplicitDescriptor", "NewDescriptor", "ObjectType", "IsDirectoryObject", "AutoInheritFlags", "SubjectContext", "GenericMapping", "PoolType"]),
        #
        'SeDeassignSecurity': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SecurityDescriptor"]),
        #
        'SeAccessCheck': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SECURITY_SUBJECT_CONTEXT", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("PRIVILEGE_SET", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["SecurityDescriptor", "SubjectSecurityContext", "SubjectContextLocked", "DesiredAccess", "PreviouslyGrantedAccess", "Privileges", "GenericMapping", "AccessMode", "GrantedAccess", "AccessStatus"]),
        #
        'SeSetAuditParameter': SimTypeFunction([SimTypePointer(SimTypeRef("SE_ADT_PARAMETER_ARRAY", SimStruct), offset=0), SimTypeInt(signed=False, label="SE_ADT_PARAMETER_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AuditParameters", "Type", "Index", "Data"]),
        #
        'SeReportSecurityEvent': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SE_ADT_PARAMETER_ARRAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Flags", "SourceName", "UserSid", "AuditParameters"]),
        #
        'SeValidSecurityDescriptor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Length", "SecurityDescriptor"]),
        #
        'SeRegisterImageVerificationCallback': SimTypeFunction([SimTypeInt(signed=False, label="SE_IMAGE_TYPE"), SimTypeInt(signed=False, label="SE_IMAGE_VERIFICATION_CALLBACK_TYPE"), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ImageType", "CallbackType", "CallbackFunction", "CallbackContext", "Token", "CallbackHandle"]),
        #
        'SeUnregisterImageVerificationCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackHandle"]),
        #
        'PsCreateSystemThread': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLIENT_ID", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle", "DesiredAccess", "ObjectAttributes", "ProcessHandle", "ClientId", "StartRoutine", "StartContext"]),
        #
        'PsTerminateSystemThread': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ExitStatus"]),
        #
        'PsWrapApcWow64Thread': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ApcContext", "ApcRoutine"]),
        #
        'PsGetVersion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["MajorVersion", "MinorVersion", "BuildNumber", "CSDVersion"]),
        #
        'PsQueryTotalCycleTimeProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["Process", "CycleTimeStamp"]),
        #
        'PsAllocateAffinityToken': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AffinityToken"]),
        #
        'PsFreeAffinityToken': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["AffinityToken"]),
        #
        'PsSetSystemMultipleGroupAffinityThread': SimTypeFunction([SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["GroupAffinities", "GroupCount", "AffinityToken"]),
        #
        'PsRevertToUserMultipleGroupAffinityThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["AffinityToken"]),
        #
        'IoAcquireCancelSpinLock': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irql"]),
        #
        'IoAllocateDriverObjectExtension': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "ClientIdentificationAddress", "DriverObjectExtensionSize", "DriverObjectExtension"]),
        #
        'IoAllocateErrorLogEntry': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["IoObject", "EntrySize"]),
        #
        'IoAllocateIrp': SimTypeFunction([SimTypeChar(label="SByte"), SimTypeChar(label="Byte")], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), arg_names=["StackSize", "ChargeQuota"]),
        #
        'IoAllocateIrpEx': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="SByte"), SimTypeChar(label="Byte")], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), arg_names=["DeviceObject", "StackSize", "ChargeQuota"]),
        #
        'IoAllocateMdl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), arg_names=["VirtualAddress", "Length", "SecondaryBuffer", "ChargeQuota", "Irp"]),
        #
        'IoAttachDevice': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceDevice", "TargetDevice", "AttachedDevice"]),
        #
        'IoAttachDeviceToDeviceStack': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), arg_names=["SourceDevice", "TargetDevice"]),
        #
        'IoBuildAsynchronousFsdRequest': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), arg_names=["MajorFunction", "DeviceObject", "Buffer", "Length", "StartingOffset", "IoStatusBlock"]),
        #
        'IoBuildDeviceIoControlRequest': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), arg_names=["IoControlCode", "DeviceObject", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength", "InternalDeviceIoControl", "Event", "IoStatusBlock"]),
        #
        'IoBuildPartialMdl': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["SourceMdl", "TargetMdl", "VirtualAddress", "Length"]),
        #
        'IoGetBootDiskInformation': SimTypeFunction([SimTypePointer(SimTypeRef("BOOTDISK_INFORMATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["BootDiskInformation", "Size"]),
        #
        'IoGetBootDiskInformationLite': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("BOOTDISK_INFORMATION_LITE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BootDiskInformation"]),
        #
        'IoBuildSynchronousFsdRequest': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0)], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), arg_names=["MajorFunction", "DeviceObject", "Buffer", "Length", "StartingOffset", "Event", "IoStatusBlock"]),
        #
        'IofCallDriver': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "Irp"]),
        #
        'IoCancelIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Irp"]),
        #
        'IoCheckShareAccess': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DesiredAccess", "DesiredShareAccess", "FileObject", "ShareAccess", "Update"]),
        #
        'IoCheckShareAccessEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DesiredAccess", "DesiredShareAccess", "FileObject", "ShareAccess", "Update", "WritePermission"]),
        #
        'IoCheckLinkShareAccess': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0), SimTypePointer(SimTypeRef("LINK_SHARE_ACCESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["DesiredAccess", "DesiredShareAccess", "FileObject", "ShareAccess", "LinkShareAccess", "IoShareAccessFlags"]),
        #
        'IofCompleteRequest': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["Irp", "PriorityBoost"]),
        #
        'IoConnectInterrupt': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([], SimTypeChar(label="Byte")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="KINTERRUPT_MODE"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["InterruptObject", "ServiceRoutine", "ServiceContext", "SpinLock", "Vector", "Irql", "SynchronizeIrql", "InterruptMode", "ShareVector", "ProcessorEnableMask", "FloatingSave"]),
        #
        'IoConnectInterruptEx': SimTypeFunction([SimTypePointer(SimTypeRef("IO_CONNECT_INTERRUPT_PARAMETERS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Parameters"]),
        #
        'IoCreateDevice': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "DeviceExtensionSize", "DeviceName", "DeviceType", "DeviceCharacteristics", "Exclusive", "DeviceObject"]),
        #
        'IoIsWdmVersionAvailable': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["MajorVersion", "MinorVersion"]),
        #
        'IoCreateFile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CREATE_FILE_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "AllocationSize", "FileAttributes", "ShareAccess", "Disposition", "CreateOptions", "EaBuffer", "EaLength", "CreateFileType", "InternalParameters", "Options"]),
        #
        'IoCreateNotificationEvent': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), arg_names=["EventName", "EventHandle"]),
        #
        'IoCreateSymbolicLink': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SymbolicLinkName", "DeviceName"]),
        #
        'IoCreateSynchronizationEvent': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), arg_names=["EventName", "EventHandle"]),
        #
        'IoCreateUnprotectedSymbolicLink': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SymbolicLinkName", "DeviceName"]),
        #
        'IoDeleteDevice': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject"]),
        #
        'IoDeleteSymbolicLink': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SymbolicLinkName"]),
        #
        'IoDetachDevice': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["TargetDevice"]),
        #
        'IoDisconnectInterrupt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["InterruptObject"]),
        #
        'IoDisconnectInterruptEx': SimTypeFunction([SimTypePointer(SimTypeRef("IO_DISCONNECT_INTERRUPT_PARAMETERS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Parameters"]),
        #
        'IoReportInterruptActive': SimTypeFunction([SimTypePointer(SimTypeRef("IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Parameters"]),
        #
        'IoReportInterruptInactive': SimTypeFunction([SimTypePointer(SimTypeRef("IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Parameters"]),
        #
        'IoGetAffinityInterrupt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("GROUP_AFFINITY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterruptObject", "GroupAffinity"]),
        #
        'IoFreeIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irp"]),
        #
        'IoFreeMdl': SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mdl"]),
        #
        'IoGetAttachedDeviceReference': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), arg_names=["DeviceObject"]),
        #
        'IoGetDriverObjectExtension': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["DriverObject", "ClientIdentificationAddress"]),
        #
        'IoGetCurrentProcess': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'IoGetDeviceObjectPointer': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectName", "DesiredAccess", "FileObject", "DeviceObject"]),
        #
        'IoGetDmaAdapter': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_DESCRIPTION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypePointer(SimTypeRef("DMA_ADAPTER", SimStruct), offset=0), arg_names=["PhysicalDeviceObject", "DeviceDescription", "NumberOfMapRegisters"]),
        #
        'IoGetIommuInterface': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DMA_IOMMU_INTERFACE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Version", "InterfaceOut"]),
        #
        'IoGetIommuInterfaceEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("DMA_IOMMU_INTERFACE_EX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Version", "Flags", "InterfaceOut"]),
        #
        'IoForwardIrpSynchronously': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["DeviceObject", "Irp"]),
        #
        'IoSynchronousCallDriver': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "Irp"]),
        #
        'IoGetInitialStack': SimTypeFunction([], SimTypePointer(SimTypeBottom(label="Void"), offset=0)),
        #
        'IoGetStackLimits': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["LowLimit", "HighLimit"]),
        #
        'IoWithinStackLimits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RegionStart", "RegionSize"]),
        #
        'IoGetRelatedDeviceObject': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), arg_names=["FileObject"]),
        #
        'IoGetTopLevelIrp': SimTypeFunction([], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)),
        #
        'IoInitializeIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["Irp", "PacketSize", "StackSize"]),
        #
        'IoCleanupIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irp"]),
        #
        'IoInitializeIrpEx': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeChar(label="SByte")], SimTypeBottom(label="Void"), arg_names=["Irp", "DeviceObject", "PacketSize", "StackSize"]),
        #
        'IoInitializeTimer': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "TimerRoutine", "Context"]),
        #
        'IoReuseIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["Irp", "Iostatus"]),
        #
        'IoRegisterShutdownNotification': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject"]),
        #
        'IoRegisterLastChanceShutdownNotification': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject"]),
        #
        'IoReleaseCancelSpinLock': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Irql"]),
        #
        'IoRemoveShareAccess': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "ShareAccess"]),
        #
        'IoRemoveLinkShareAccess': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0), SimTypePointer(SimTypeRef("LINK_SHARE_ACCESS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "ShareAccess", "LinkShareAccess"]),
        #
        'IoRemoveLinkShareAccessEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0), SimTypePointer(SimTypeRef("LINK_SHARE_ACCESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["FileObject", "ShareAccess", "LinkShareAccess", "IoShareAccessFlags"]),
        #
        'IoSetCompletionRoutineEx': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "Irp", "CompletionRoutine", "Context", "InvokeOnSuccess", "InvokeOnError", "InvokeOnCancel"]),
        #
        'IoSetShareAccess': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DesiredAccess", "DesiredShareAccess", "FileObject", "ShareAccess"]),
        #
        'IoSetShareAccessEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DesiredAccess", "DesiredShareAccess", "FileObject", "ShareAccess", "WritePermission"]),
        #
        'IoSetLinkShareAccess': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0), SimTypePointer(SimTypeRef("LINK_SHARE_ACCESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["DesiredAccess", "DesiredShareAccess", "FileObject", "ShareAccess", "LinkShareAccess", "IoShareAccessFlags"]),
        #
        'IoSetTopLevelIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irp"]),
        #
        'IoInitializeRemoveLockEx': SimTypeFunction([SimTypePointer(SimTypeRef("IO_REMOVE_LOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Lock", "AllocateTag", "MaxLockedMinutes", "HighWatermark", "RemlockSize"]),
        #
        'IoAcquireRemoveLockEx': SimTypeFunction([SimTypePointer(SimTypeRef("IO_REMOVE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["RemoveLock", "Tag", "File", "Line", "RemlockSize"]),
        #
        'IoReleaseRemoveLockEx': SimTypeFunction([SimTypePointer(SimTypeRef("IO_REMOVE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["RemoveLock", "Tag", "RemlockSize"]),
        #
        'IoReleaseRemoveLockAndWaitEx': SimTypeFunction([SimTypePointer(SimTypeRef("IO_REMOVE_LOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["RemoveLock", "Tag", "RemlockSize"]),
        #
        'IoSizeOfIrpEx': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="SByte")], SimTypeShort(signed=False, label="UInt16"), arg_names=["DeviceObject", "StackSize"]),
        #
        'IoStartNextPacket': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "Cancelable"]),
        #
        'IoStartNextPacketByKey': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "Cancelable", "Key"]),
        #
        'IoStartPacket': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "Irp"]), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "Irp", "Key", "CancelFunction"]),
        #
        'IoSetStartIoAttributes': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "DeferredStartIo", "NonCancelable"]),
        #
        'IoStartTimer': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject"]),
        #
        'IoStopTimer': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject"]),
        #
        'IoUnregisterShutdownNotification': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject"]),
        #
        'IoUpdateShareAccess': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "ShareAccess"]),
        #
        'IoUpdateLinkShareAccess': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0), SimTypePointer(SimTypeRef("LINK_SHARE_ACCESS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FileObject", "ShareAccess", "LinkShareAccess"]),
        #
        'IoUpdateLinkShareAccessEx': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHARE_ACCESS", SimStruct), offset=0), SimTypePointer(SimTypeRef("LINK_SHARE_ACCESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["FileObject", "ShareAccess", "LinkShareAccess", "IoShareAccessFlags"]),
        #
        'IoWriteErrorLogEntry': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ElEntry"]),
        #
        'IoCreateSystemThread': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("CLIENT_ID", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["IoObject", "ThreadHandle", "DesiredAccess", "ObjectAttributes", "ProcessHandle", "ClientId", "StartRoutine", "StartContext"]),
        #
        'IoAllocateWorkItem': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["DeviceObject"]),
        #
        'IoFreeWorkItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["IoWorkItem"]),
        #
        'IoQueueWorkItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypeInt(signed=False, label="WORK_QUEUE_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["IoWorkItem", "WorkerRoutine", "QueueType", "Context"]),
        #
        'IoQueueWorkItemEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypeInt(signed=False, label="WORK_QUEUE_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["IoWorkItem", "WorkerRoutine", "QueueType", "Context"]),
        #
        'IoSizeofWorkItem': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'IoInitializeWorkItem': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["IoObject", "IoWorkItem"]),
        #
        'IoUninitializeWorkItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["IoWorkItem"]),
        #
        'IoTryQueueWorkItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypeInt(signed=False, label="WORK_QUEUE_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["IoWorkItem", "WorkerRoutine", "QueueType", "Context"]),
        #
        'IoWMIRegistrationControl': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "Action"]),
        #
        'IoWMIAllocateInstanceIds': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Guid", "InstanceCount", "FirstInstanceId"]),
        #
        'IoWMISuggestInstanceName': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PhysicalDeviceObject", "SymbolicLinkName", "CombineNames", "SuggestedInstanceName"]),
        #
        'IoWMIWriteEvent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WnodeEventItem"]),
        #
        'IoWMIOpenBlock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Guid", "DesiredAccess", "DataBlockObject"]),
        #
        'IoWMIQueryAllData': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataBlockObject", "InOutBufferSize", "OutBuffer"]),
        #
        'IoWMIQueryAllDataMultiple': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataBlockObjectList", "ObjectCount", "InOutBufferSize", "OutBuffer"]),
        #
        'IoWMIQuerySingleInstance': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataBlockObject", "InstanceName", "InOutBufferSize", "OutBuffer"]),
        #
        'IoWMIQuerySingleInstanceMultiple': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataBlockObjectList", "InstanceNames", "ObjectCount", "InOutBufferSize", "OutBuffer"]),
        #
        'IoWMISetSingleInstance': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataBlockObject", "InstanceName", "Version", "ValueBufferSize", "ValueBuffer"]),
        #
        'IoWMISetSingleItem': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataBlockObject", "InstanceName", "DataItemId", "Version", "ValueBufferSize", "ValueBuffer"]),
        #
        'IoWMIExecuteMethod': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataBlockObject", "InstanceName", "MethodId", "InBufferSize", "OutBufferSize", "InOutBuffer"]),
        #
        'IoWMISetNotificationCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "Callback", "Context"]),
        #
        'IoWMIHandleToInstanceName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataBlockObject", "FileHandle", "InstanceName"]),
        #
        'IoWMIDeviceObjectToInstanceName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataBlockObject", "DeviceObject", "InstanceName"]),
        #
        'IoIs32bitProcess': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Irp"]),
        #
        'IoIsInitiator32bitProcess': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Irp"]),
        #
        'IoFreeErrorLogEntry': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ElEntry"]),
        #
        'IoCsqInitialize': SimTypeFunction([SimTypePointer(SimTypeRef("IO_CSQ", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Csq", "CsqInsertIrp", "CsqRemoveIrp", "CsqPeekNextIrp", "CsqAcquireLock", "CsqReleaseLock", "CsqCompleteCanceledIrp"]),
        #
        'IoCsqInitializeEx': SimTypeFunction([SimTypePointer(SimTypeRef("IO_CSQ", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Csq", "CsqInsertIrp", "CsqRemoveIrp", "CsqPeekNextIrp", "CsqAcquireLock", "CsqReleaseLock", "CsqCompleteCanceledIrp"]),
        #
        'IoCsqInsertIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IO_CSQ", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_CSQ_IRP_CONTEXT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Csq", "Irp", "Context"]),
        #
        'IoCsqInsertIrpEx': SimTypeFunction([SimTypePointer(SimTypeRef("IO_CSQ", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_CSQ_IRP_CONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Csq", "Irp", "Context", "InsertContext"]),
        #
        'IoCsqRemoveNextIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IO_CSQ", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), arg_names=["Csq", "PeekContext"]),
        #
        'IoCsqRemoveIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IO_CSQ", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_CSQ_IRP_CONTEXT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), arg_names=["Csq", "Context"]),
        #
        'IoValidateDeviceIoControlAccess': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "RequiredAccess"]),
        #
        'IoGetIoPriorityHint': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=False, label="IO_PRIORITY_HINT"), arg_names=["Irp"]),
        #
        'IoSetIoPriorityHint': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="IO_PRIORITY_HINT")], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "PriorityHint"]),
        #
        'IoAllocateSfioStreamIdentifier': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "Length", "Signature", "StreamIdentifier"]),
        #
        'IoGetSfioStreamIdentifier': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["FileObject", "Signature"]),
        #
        'IoFreeSfioStreamIdentifier': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "Signature"]),
        #
        'IoGetIoAttributionHandle': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "IoAttributionHandle"]),
        #
        'IoRecordIoAttribution': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_ATTRIBUTION_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["OpaqueHandle", "AttributionInformation"]),
        #
        'IoSetIoAttributionIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "AttributionSource", "Flags"]),
        #
        'IoGetContainerInformation': SimTypeFunction([SimTypeInt(signed=False, label="IO_CONTAINER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["InformationClass", "ContainerObject", "Buffer", "BufferLength"]),
        #
        'IoRegisterContainerNotification': SimTypeFunction([SimTypeInt(signed=False, label="IO_CONTAINER_NOTIFICATION_CLASS"), SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotificationClass", "CallbackFunction", "NotificationInformation", "NotificationInformationLength", "CallbackRegistration"]),
        #
        'IoUnregisterContainerNotification': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackRegistration"]),
        #
        'IoReserveKsrPersistentMemory': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "PhysicalDeviceObject", "Size", "Flags", "DataHandle"]),
        #
        'IoFreeKsrPersistentMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataHandle"]),
        #
        'IoQueryKsrPersistentMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "PhysicalDeviceObject", "BufferSize"]),
        #
        'IoAcquireKsrPersistentMemory': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "PhysicalDeviceObject", "Buffer", "Size"]),
        #
        'IoWriteKsrPersistentMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DataHandle", "Buffer", "Size"]),
        #
        'IoEnumerateKsrPersistentMemoryEx': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "PhysicalDeviceObject", "PhysicalDeviceId", "Callback", "CallbackContext"]),
        #
        'IoReserveKsrPersistentMemoryEx': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "PhysicalDeviceObject", "PhysicalDeviceId", "DataTag", "DataVersion", "Size", "Flags", "DataHandle"]),
        #
        'IoQueryKsrPersistentMemorySizeEx': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "PhysicalDeviceObject", "PhysicalDeviceId", "DataTag", "DataVersion", "BufferSize"]),
        #
        'IoAcquireKsrPersistentMemoryEx': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "PhysicalDeviceObject", "PhysicalDeviceId", "DataTag", "DataVersion", "Buffer", "Size"]),
        #
        'WmiQueryTraceInformation': SimTypeFunction([SimTypeInt(signed=False, label="TRACE_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TraceInformationClass", "TraceInformation", "TraceInformationLength", "RequiredLength", "Buffer"]),
        #
        'EtwRegister': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProviderId", "EnableCallback", "CallbackContext", "RegHandle"]),
        #
        'EtwUnregister': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["RegHandle"]),
        #
        'EtwSetInformation': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="EVENT_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["RegHandle", "InformationClass", "EventInformation", "InformationLength"]),
        #
        'EtwEventEnabled': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["RegHandle", "EventDescriptor"]),
        #
        'EtwProviderEnabled': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeChar(label="Byte"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeChar(label="Byte"), arg_names=["RegHandle", "Level", "Keyword"]),
        #
        'EtwActivityIdControl': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ControlCode", "ActivityId"]),
        #
        'EtwWrite': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EVENT_DATA_DESCRIPTOR", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RegHandle", "EventDescriptor", "ActivityId", "UserDataCount", "UserData"]),
        #
        'EtwWriteTransfer': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EVENT_DATA_DESCRIPTOR", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RegHandle", "EventDescriptor", "ActivityId", "RelatedActivityId", "UserDataCount", "UserData"]),
        #
        'EtwWriteString': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeChar(label="Byte"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RegHandle", "Level", "Keyword", "ActivityId", "String"]),
        #
        'EtwWriteEx': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("EVENT_DATA_DESCRIPTOR", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RegHandle", "EventDescriptor", "Filter", "Flags", "ActivityId", "RelatedActivityId", "UserDataCount", "UserData"]),
        #
        'SeEtwWriteKMCveEvent': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CveId", "AdditionalDetails"]),
        #
        'IoInvalidateDeviceRelations': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DEVICE_RELATION_TYPE")], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "Type"]),
        #
        'IoRequestDeviceEject': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PhysicalDeviceObject"]),
        #
        'IoRequestDeviceEjectEx': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Status", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PhysicalDeviceObject", "Callback", "Context", "DriverObject"]),
        #
        'IoGetDeviceProperty': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DEVICE_REGISTRY_PROPERTY"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "DeviceProperty", "BufferLength", "PropertyBuffer", "ResultLength"]),
        #
        'IoOpenDeviceRegistryKey': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "DevInstKeyType", "DesiredAccess", "DeviceRegKey"]),
        #
        'IoRegisterDeviceInterface': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PhysicalDeviceObject", "InterfaceClassGuid", "ReferenceString", "SymbolicLinkName"]),
        #
        'IoOpenDeviceInterfaceRegistryKey': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SymbolicLinkName", "DesiredAccess", "DeviceInterfaceRegKey"]),
        #
        'IoSetDeviceInterfaceState': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["SymbolicLinkName", "Enable"]),
        #
        'IoGetDeviceInterfaces': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["InterfaceClassGuid", "PhysicalDeviceObject", "Flags", "SymbolicLinkList"]),
        #
        'IoGetDeviceInterfaceAlias': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SymbolicLinkName", "AliasInterfaceClassGuid", "AliasSymbolicLinkName"]),
        #
        'IoRegisterPlugPlayNotification': SimTypeFunction([SimTypeInt(signed=False, label="IO_NOTIFICATION_EVENT_CATEGORY"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotificationStructure", "Context"]), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EventCategory", "EventCategoryFlags", "EventCategoryData", "DriverObject", "CallbackRoutine", "Context", "NotificationEntry"]),
        #
        'IoUnregisterPlugPlayNotification': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotificationEntry"]),
        #
        'IoUnregisterPlugPlayNotificationEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotificationEntry"]),
        #
        'IoReportTargetDeviceChange': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PhysicalDeviceObject", "NotificationStructure"]),
        #
        'IoInvalidateDeviceState': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PhysicalDeviceObject"]),
        #
        'IoReportTargetDeviceChangeAsynchronous': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PhysicalDeviceObject", "NotificationStructure", "Callback", "Context"]),
        #
        'IoGetDriverDirectory': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DRIVER_DIRECTORY_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "DirectoryType", "Flags", "DriverDirectoryHandle"]),
        #
        'IoGetDeviceDirectory': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DEVICE_DIRECTORY_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PhysicalDeviceObject", "DirectoryType", "Flags", "Reserved", "DeviceDirectoryHandle"]),
        #
        'IoOpenDriverRegistryKey': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="DRIVER_REGKEY_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "RegKeyType", "DesiredAccess", "Flags", "DriverRegKey"]),
        #
        'IoSetDevicePropertyData': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVPROPKEY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Pdo", "PropertyKey", "Lcid", "Flags", "Type", "Size", "Data"]),
        #
        'IoGetDevicePropertyData': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVPROPKEY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="DEVPROPTYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Pdo", "PropertyKey", "Lcid", "Flags", "Size", "Data", "RequiredSize", "Type"]),
        #
        'IoSetDeviceInterfacePropertyData': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVPROPKEY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SymbolicLinkName", "PropertyKey", "Lcid", "Flags", "Type", "Size", "Data"]),
        #
        'IoGetDeviceInterfacePropertyData': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVPROPKEY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="DEVPROPTYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SymbolicLinkName", "PropertyKey", "Lcid", "Flags", "Size", "Data", "RequiredSize", "Type"]),
        #
        'IoGetDeviceNumaNode': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Pdo", "NodeNumber"]),
        #
        'IoReplacePartitionUnit': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetPdo", "SparePdo", "Flags"]),
        #
        'PoSetHiberRange': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["MemoryMap", "Flags", "Address", "Length", "Tag"]),
        #
        'PoSetSystemState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Flags"]),
        #
        'PoRegisterSystemState': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["StateHandle", "Flags"]),
        #
        'PoCreatePowerRequest': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("COUNTED_REASON_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PowerRequest", "DeviceObject", "Context"]),
        #
        'PoSetPowerRequest': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="POWER_REQUEST_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["PowerRequest", "Type"]),
        #
        'PoClearPowerRequest': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="POWER_REQUEST_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["PowerRequest", "Type"]),
        #
        'PoDeletePowerRequest': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["PowerRequest"]),
        #
        'PoRequestPowerIrp': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte"), SimUnion({"SystemState": SimTypeInt(signed=False, label="SYSTEM_POWER_STATE"), "DeviceState": SimTypeInt(signed=False, label="DEVICE_POWER_STATE")}, name="<anon>", label="None"), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "MinorFunction", "PowerState", "CompletionFunction", "Context", "Irp"]),
        #
        'PoSetSystemWake': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irp"]),
        #
        'PoSetSystemWakeDevice': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject"]),
        #
        'PoGetSystemWake': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Irp"]),
        #
        'PoUnregisterSystemState': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["StateHandle"]),
        #
        'PoSetPowerState': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="POWER_STATE_TYPE"), SimUnion({"SystemState": SimTypeInt(signed=False, label="SYSTEM_POWER_STATE"), "DeviceState": SimTypeInt(signed=False, label="DEVICE_POWER_STATE")}, name="<anon>", label="None")], SimUnion({"SystemState": SimTypeInt(signed=False, label="SYSTEM_POWER_STATE"), "DeviceState": SimTypeInt(signed=False, label="DEVICE_POWER_STATE")}, name="<anon>", label="None"), arg_names=["DeviceObject", "Type", "State"]),
        #
        'PoCallDriver': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "Irp"]),
        #
        'PoStartNextPowerIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irp"]),
        #
        'PoRegisterDeviceForIdleDetection': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DEVICE_POWER_STATE")], SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), arg_names=["DeviceObject", "ConservationIdleTime", "PerformanceIdleTime", "State"]),
        #
        'PoSetDeviceBusyEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["IdlePointer"]),
        #
        'PoStartDeviceBusy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["IdlePointer"]),
        #
        'PoEndDeviceBusy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["IdlePointer"]),
        #
        'PoQueryWatchdogTime': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Pdo", "SecondsRemaining"]),
        #
        'PoRegisterPowerSettingCallback': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "SettingGuid", "Callback", "Context", "Handle"]),
        #
        'PoUnregisterPowerSettingCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'PoFxRegisterDevice': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("PO_FX_DEVICE_V1", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Pdo", "Device", "Handle"]),
        #
        'PoFxStartDevicePowerManagement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle"]),
        #
        'PoFxUnregisterDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle"]),
        #
        'PoFxRegisterCrashdumpDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'PoFxPowerOnCrashdumpDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "Context"]),
        #
        'PoFxActivateComponent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Handle", "Component", "Flags"]),
        #
        'PoFxCompleteDevicePowerNotRequired': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle"]),
        #
        'PoFxCompleteIdleCondition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Handle", "Component"]),
        #
        'PoFxCompleteIdleState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Handle", "Component"]),
        #
        'PoFxIdleComponent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Handle", "Component", "Flags"]),
        #
        'PoFxSetComponentLatency': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeBottom(label="Void"), arg_names=["Handle", "Component", "Latency"]),
        #
        'PoFxSetComponentResidency': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeBottom(label="Void"), arg_names=["Handle", "Component", "Residency"]),
        #
        'PoFxSetComponentWake': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["Handle", "Component", "WakeHint"]),
        #
        'PoFxSetDeviceIdleTimeout': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64")], SimTypeBottom(label="Void"), arg_names=["Handle", "IdleTimeout"]),
        #
        'PoFxReportDevicePoweredOn': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle"]),
        #
        'PoFxPowerControl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "PowerControlCode", "InBuffer", "InBufferSize", "OutBuffer", "OutBufferSize", "BytesReturned"]),
        #
        'PoFxNotifySurprisePowerOn': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Pdo"]),
        #
        'PoFxRegisterComponentPerfStates': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeRef("PO_FX_COMPONENT_PERF_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PO_FX_COMPONENT_PERF_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "Component", "Flags", "ComponentPerfStateCallback", "InputStateInfo", "OutputStateInfo"]),
        #
        'PoFxIssueComponentPerfStateChange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PO_FX_PERF_STATE_CHANGE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "Flags", "Component", "PerfChange", "Context"]),
        #
        'PoFxIssueComponentPerfStateChangeMultiple': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PO_FX_PERF_STATE_CHANGE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "Flags", "Component", "PerfChangesCount", "PerfChanges", "Context"]),
        #
        'PoFxQueryCurrentComponentPerfState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "Flags", "Component", "SetIndex", "CurrentPerf"]),
        #
        'PoFxSetTargetDripsDevicePowerState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DEVICE_POWER_STATE")], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "TargetState"]),
        #
        'PoFxCompleteDirectedPowerDown': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle"]),
        #
        'PoCreateThermalRequest': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("COUNTED_REASON_CONTEXT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ThermalRequest", "TargetDeviceObject", "PolicyDeviceObject", "Context", "Flags"]),
        #
        'PoGetThermalRequestSupport': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="PO_THERMAL_REQUEST_TYPE")], SimTypeChar(label="Byte"), arg_names=["ThermalRequest", "Type"]),
        #
        'PoSetThermalPassiveCooling': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["ThermalRequest", "Throttle"]),
        #
        'PoSetThermalActiveCooling': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["ThermalRequest", "Engaged"]),
        #
        'PoDeleteThermalRequest': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ThermalRequest"]),
        #
        'PoFxRegisterDripsWatchdogCallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "Callback", "IncludeChildDevices", "MatchingDriverObject"]),
        #
        'ObReferenceObjectByHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="SByte"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("OBJECT_HANDLE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "DesiredAccess", "ObjectType", "AccessMode", "Object", "HandleInformation"]),
        #
        'ObReferenceObjectByHandleWithTag': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="SByte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("OBJECT_HANDLE_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "DesiredAccess", "ObjectType", "AccessMode", "Tag", "Object", "HandleInformation"]),
        #
        'ObReferenceObjectSafe': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Object"]),
        #
        'ObReferenceObjectSafeWithTag': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["Object", "Tag"]),
        #
        'ObCloseHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "PreviousMode"]),
        #
        'ObfReferenceObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Object"]),
        #
        'ObfReferenceObjectWithTag': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Object", "Tag"]),
        #
        'ObReferenceObjectByPointer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="SByte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "DesiredAccess", "ObjectType", "AccessMode"]),
        #
        'ObReferenceObjectByPointerWithTag': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="SByte"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "DesiredAccess", "ObjectType", "AccessMode", "Tag"]),
        #
        'ObfDereferenceObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Object"]),
        #
        'ObfDereferenceObjectWithTag': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Object", "Tag"]),
        #
        'ObDereferenceObjectDeferDelete': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Object"]),
        #
        'ObDereferenceObjectDeferDeleteWithTag': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Object", "Tag"]),
        #
        'ObGetObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Object", "SecurityDescriptor", "MemoryAllocated"]),
        #
        'ObReleaseObjectSecurity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["SecurityDescriptor", "MemoryAllocated"]),
        #
        'ObRegisterCallbacks': SimTypeFunction([SimTypePointer(SimTypeRef("OB_CALLBACK_REGISTRATION", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CallbackRegistration", "RegistrationHandle"]),
        #
        'ObUnRegisterCallbacks': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["RegistrationHandle"]),
        #
        'ObGetFilterVersion': SimTypeFunction([], SimTypeShort(signed=False, label="UInt16")),
        #
        'ZwCreateFile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "AllocationSize", "FileAttributes", "ShareAccess", "CreateDisposition", "CreateOptions", "EaBuffer", "EaLength"]),
        #
        'ZwOpenFile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "ShareAccess", "OpenOptions"]),
        #
        'ZwLoadDriver': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverServiceName"]),
        #
        'ZwUnloadDriver': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverServiceName"]),
        #
        'ZwQueryInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass"]),
        #
        'ZwSetInformationFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass"]),
        #
        'ZwReadFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "Buffer", "Length", "ByteOffset", "Key"]),
        #
        'ZwWriteFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "Buffer", "Length", "ByteOffset", "Key"]),
        #
        'ZwClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'ZwCreateDirectoryObject': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DirectoryHandle", "DesiredAccess", "ObjectAttributes"]),
        #
        'ZwMakeTemporaryObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle"]),
        #
        'ZwCreateSection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SectionHandle", "DesiredAccess", "ObjectAttributes", "MaximumSize", "SectionPageProtection", "AllocationAttributes", "FileHandle"]),
        #
        'ZwOpenSection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SectionHandle", "DesiredAccess", "ObjectAttributes"]),
        #
        'ZwMapViewOfSection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="SECTION_INHERIT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SectionHandle", "ProcessHandle", "BaseAddress", "ZeroBits", "CommitSize", "SectionOffset", "ViewSize", "InheritDisposition", "AllocationType", "Win32Protect"]),
        #
        'ZwUnmapViewOfSection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "BaseAddress"]),
        #
        'ZwCreateKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "DesiredAccess", "ObjectAttributes", "TitleIndex", "Class", "CreateOptions", "Disposition"]),
        #
        'ZwCreateKeyTransacted': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "DesiredAccess", "ObjectAttributes", "TitleIndex", "Class", "CreateOptions", "TransactionHandle", "Disposition"]),
        #
        'ZwCreateRegistryTransaction': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "DesiredAccess", "ObjectAttributes", "CreateOptions"]),
        #
        'NtOpenRegistryTransaction': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "DesiredAccess", "ObjectAttributes"]),
        #
        'ZwCommitRegistryTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "Flags"]),
        #
        'NtRollbackRegistryTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "Flags"]),
        #
        'ZwOpenKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "DesiredAccess", "ObjectAttributes"]),
        #
        'ZwOpenKeyEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "DesiredAccess", "ObjectAttributes", "OpenOptions"]),
        #
        'ZwOpenKeyTransacted': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "DesiredAccess", "ObjectAttributes", "TransactionHandle"]),
        #
        'ZwOpenKeyTransactedEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "DesiredAccess", "ObjectAttributes", "OpenOptions", "TransactionHandle"]),
        #
        'ZwDeleteKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle"]),
        #
        'ZwDeleteValueKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "ValueName"]),
        #
        'ZwEnumerateKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="KEY_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "Index", "KeyInformationClass", "KeyInformation", "Length", "ResultLength"]),
        #
        'ZwEnumerateValueKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="KEY_VALUE_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "Index", "KeyValueInformationClass", "KeyValueInformation", "Length", "ResultLength"]),
        #
        'ZwFlushKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle"]),
        #
        'ZwQueryKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="KEY_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "KeyInformationClass", "KeyInformation", "Length", "ResultLength"]),
        #
        'ZwQueryValueKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="KEY_VALUE_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "ValueName", "KeyValueInformationClass", "KeyValueInformation", "Length", "ResultLength"]),
        #
        'ZwRenameKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "NewName"]),
        #
        'ZwSaveKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "FileHandle"]),
        #
        'ZwSaveKeyEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "FileHandle", "Format"]),
        #
        'ZwRestoreKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "FileHandle", "Flags"]),
        #
        'ZwSetValueKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "ValueName", "TitleIndex", "Type", "Data", "DataSize"]),
        #
        'ZwOpenSymbolicLinkObject': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LinkHandle", "DesiredAccess", "ObjectAttributes"]),
        #
        'ZwQuerySymbolicLinkObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LinkHandle", "LinkTarget", "ReturnedLength"]),
        #
        'ZwCreateTransactionManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TmHandle", "DesiredAccess", "ObjectAttributes", "LogFileName", "CreateOptions", "CommitStrength"]),
        #
        'ZwOpenTransactionManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TmHandle", "DesiredAccess", "ObjectAttributes", "LogFileName", "TmIdentity", "OpenOptions"]),
        #
        'ZwRollforwardTransactionManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionManagerHandle", "TmVirtualClock"]),
        #
        'ZwRecoverTransactionManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionManagerHandle"]),
        #
        'ZwQueryInformationTransactionManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSACTIONMANAGER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionManagerHandle", "TransactionManagerInformationClass", "TransactionManagerInformation", "TransactionManagerInformationLength", "ReturnLength"]),
        #
        'ZwSetInformationTransactionManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSACTIONMANAGER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TmHandle", "TransactionManagerInformationClass", "TransactionManagerInformation", "TransactionManagerInformationLength"]),
        #
        'ZwEnumerateTransactionObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="KTMOBJECT_TYPE"), SimTypePointer(SimTypeRef("KTMOBJECT_CURSOR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RootObjectHandle", "QueryType", "ObjectCursor", "ObjectCursorLength", "ReturnLength"]),
        #
        'ZwCreateTransaction': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "DesiredAccess", "ObjectAttributes", "Uow", "TmHandle", "CreateOptions", "IsolationLevel", "IsolationFlags", "Timeout", "Description"]),
        #
        'ZwOpenTransaction': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "DesiredAccess", "ObjectAttributes", "Uow", "TmHandle"]),
        #
        'ZwQueryInformationTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSACTION_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "TransactionInformationClass", "TransactionInformation", "TransactionInformationLength", "ReturnLength"]),
        #
        'ZwSetInformationTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TRANSACTION_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "TransactionInformationClass", "TransactionInformation", "TransactionInformationLength"]),
        #
        'ZwCommitTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "Wait"]),
        #
        'ZwRollbackTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionHandle", "Wait"]),
        #
        'ZwCreateResourceManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "DesiredAccess", "TmHandle", "ResourceManagerGuid", "ObjectAttributes", "CreateOptions", "Description"]),
        #
        'ZwOpenResourceManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "DesiredAccess", "TmHandle", "ResourceManagerGuid", "ObjectAttributes"]),
        #
        'ZwRecoverResourceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle"]),
        #
        'ZwGetNotificationResourceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("TRANSACTION_NOTIFICATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "TransactionNotification", "NotificationLength", "Timeout", "ReturnLength", "Asynchronous", "AsynchronousContext"]),
        #
        'ZwQueryInformationResourceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RESOURCEMANAGER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "ResourceManagerInformationClass", "ResourceManagerInformation", "ResourceManagerInformationLength", "ReturnLength"]),
        #
        'ZwSetInformationResourceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="RESOURCEMANAGER_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManagerHandle", "ResourceManagerInformationClass", "ResourceManagerInformation", "ResourceManagerInformationLength"]),
        #
        'ZwCreateEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "DesiredAccess", "ResourceManagerHandle", "TransactionHandle", "ObjectAttributes", "CreateOptions", "NotificationMask", "EnlistmentKey"]),
        #
        'ZwOpenEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "DesiredAccess", "RmHandle", "EnlistmentGuid", "ObjectAttributes"]),
        #
        'ZwQueryInformationEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ENLISTMENT_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "EnlistmentInformationClass", "EnlistmentInformation", "EnlistmentInformationLength", "ReturnLength"]),
        #
        'ZwSetInformationEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ENLISTMENT_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "EnlistmentInformationClass", "EnlistmentInformation", "EnlistmentInformationLength"]),
        #
        'ZwRecoverEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "EnlistmentKey"]),
        #
        'ZwPrePrepareEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'ZwPrepareEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'ZwCommitEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'ZwRollbackEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'ZwPrePrepareComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'ZwPrepareComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'ZwCommitComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'ZwReadOnlyEnlistment': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'ZwRollbackComplete': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'ZwSinglePhaseReject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "TmVirtualClock"]),
        #
        'ZwOpenEvent': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EventHandle", "DesiredAccess", "ObjectAttributes"]),
        #
        'ZwQueryInformationByName': SimTypeFunction([SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS")], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectAttributes", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass"]),
        #
        'TmInitializeTransactionManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TransactionManager", "LogFileName", "TmId", "CreateOptions"]),
        #
        'TmRenameTransactionManager': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LogFileName", "ExistingTransactionManagerGuid"]),
        #
        'TmRecoverTransactionManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Tm", "TargetVirtualClock"]),
        #
        'TmCommitTransaction': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Transaction", "Wait"]),
        #
        'TmRollbackTransaction': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Transaction", "Wait"]),
        #
        'TmCreateEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeChar(label="SByte"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentHandle", "PreviousMode", "DesiredAccess", "ObjectAttributes", "ResourceManager", "Transaction", "CreateOptions", "NotificationMask", "EnlistmentKey"]),
        #
        'TmRecoverEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "EnlistmentKey"]),
        #
        'TmPrePrepareEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmPrepareEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmCommitEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmRollbackEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmPrePrepareComplete': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmPrepareComplete': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmReadOnlyEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmCommitComplete': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmRollbackComplete': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmReferenceEnlistmentKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "Key"]),
        #
        'TmDereferenceEnlistmentKey': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "LastReference"]),
        #
        'TmSinglePhaseReject': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmRequestOutcomeEnlistment': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Enlistment", "TmVirtualClock"]),
        #
        'TmEnableCallbacks': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["EnlistmentObject", "RMContext", "TransactionContext", "TransactionNotification", "TmVirtualClock", "ArgumentLength", "Argument"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManager", "CallbackRoutine", "RMKey"]),
        #
        'TmRecoverResourceManager': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManager"]),
        #
        'TmPropagationComplete': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManager", "RequestCookie", "BufferLength", "Buffer"]),
        #
        'TmPropagationFailed': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ResourceManager", "RequestCookie", "Status"]),
        #
        'TmGetTransactionId': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Transaction", "TransactionId"]),
        #
        'TmIsTransactionActive': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["Transaction"]),
        #
        'PcwRegister': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("PCW_REGISTRATION_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Registration", "Info"]),
        #
        'PcwUnregister': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Registration"]),
        #
        'PcwCreateInstance': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PCW_DATA", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Instance", "Registration", "Name", "Count", "Data"]),
        #
        'PcwCloseInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Instance"]),
        #
        'PcwAddInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PCW_DATA", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Buffer", "Name", "Id", "Count", "Data"]),
        #
        'VslCreateSecureSection': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "TargetProcess", "Mdl", "DevicePageProtection", "Attributes"]),
        #
        'VslDeleteSecureSection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["GlobalHandle"]),
        #
        'RtlRunOnceInitialize': SimTypeFunction([SimTypePointer(SimUnion({"Ptr": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), offset=0)], SimTypeBottom(label="Void"), arg_names=["RunOnce"]),
        #
        'RtlRunOnceExecuteOnce': SimTypeFunction([SimTypePointer(SimUnion({"Ptr": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RunOnce", "InitFn", "Parameter", "Context"]),
        #
        'RtlRunOnceBeginInitialize': SimTypeFunction([SimTypePointer(SimUnion({"Ptr": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RunOnce", "Flags", "Context"]),
        #
        'RtlRunOnceComplete': SimTypeFunction([SimTypePointer(SimUnion({"Ptr": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="<anon>", label="None"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RunOnce", "Flags", "Context"]),
        #
        'RtlInitializeGenericTableAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeInt(signed=False, label="RTL_GENERIC_COMPARE_RESULTS")), offset=0), SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeBottom(label="Void"), offset=0)), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Table", "CompareRoutine", "AllocateRoutine", "FreeRoutine", "TableContext"]),
        #
        'RtlInsertElementGenericTableAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Buffer", "BufferSize", "NewElement"]),
        #
        'RtlInsertElementGenericTableFullAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="TABLE_SEARCH_RESULT")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Buffer", "BufferSize", "NewElement", "NodeOrParent", "SearchResult"]),
        #
        'RtlDeleteElementGenericTableAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Table", "Buffer"]),
        #
        'RtlDeleteElementGenericTableAvlEx': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Table", "NodeOrParent"]),
        #
        'RtlLookupElementGenericTableAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Buffer"]),
        #
        'RtlLookupElementGenericTableFullAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="TABLE_SEARCH_RESULT"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Buffer", "NodeOrParent", "SearchResult"]),
        #
        'RtlEnumerateGenericTableAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Restart"]),
        #
        'RtlEnumerateGenericTableWithoutSplayingAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "RestartKey"]),
        #
        'RtlLookupFirstMatchingElementGenericTableAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Buffer", "RestartKey"]),
        #
        'RtlEnumerateGenericTableLikeADirectory': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "MatchFunction", "MatchData", "NextFlag", "RestartKey", "DeleteCount", "Buffer"]),
        #
        'RtlGetElementGenericTableAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "I"]),
        #
        'RtlNumberGenericTableElementsAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Table"]),
        #
        'RtlIsGenericTableEmptyAvl': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_AVL_TABLE", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Table"]),
        #
        'RtlSplay': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0), arg_names=["Links"]),
        #
        'RtlDelete': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0), arg_names=["Links"]),
        #
        'RtlDeleteNoSplay': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Links", "Root"]),
        #
        'RtlSubtreeSuccessor': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0), arg_names=["Links"]),
        #
        'RtlSubtreePredecessor': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0), arg_names=["Links"]),
        #
        'RtlRealSuccessor': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0), arg_names=["Links"]),
        #
        'RtlRealPredecessor': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_SPLAY_LINKS", SimStruct), offset=0), arg_names=["Links"]),
        #
        'RtlInitializeGenericTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeFunction([], SimTypeInt(signed=False, label="RTL_GENERIC_COMPARE_RESULTS")), offset=0), SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeBottom(label="Void"), offset=0)), offset=0), SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Table", "CompareRoutine", "AllocateRoutine", "FreeRoutine", "TableContext"]),
        #
        'RtlInsertElementGenericTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Buffer", "BufferSize", "NewElement"]),
        #
        'RtlInsertElementGenericTableFull': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="TABLE_SEARCH_RESULT")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Buffer", "BufferSize", "NewElement", "NodeOrParent", "SearchResult"]),
        #
        'RtlDeleteElementGenericTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Table", "Buffer"]),
        #
        'RtlLookupElementGenericTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Buffer"]),
        #
        'RtlLookupElementGenericTableFull': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="TABLE_SEARCH_RESULT"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Buffer", "NodeOrParent", "SearchResult"]),
        #
        'RtlEnumerateGenericTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "Restart"]),
        #
        'RtlEnumerateGenericTableWithoutSplaying': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "RestartKey"]),
        #
        'RtlGetElementGenericTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Table", "I"]),
        #
        'RtlNumberGenericTableElements': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Table"]),
        #
        'RtlIsGenericTableEmpty': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_GENERIC_TABLE", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["Table"]),
        #
        'RtlCreateHashTable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HashTable", "Shift", "Flags"]),
        #
        'RtlCreateHashTableEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HashTable", "InitialSize", "Shift", "Flags"]),
        #
        'RtlDeleteHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["HashTable"]),
        #
        'RtlInsertEntryHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_CONTEXT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["HashTable", "Entry", "Signature", "Context"]),
        #
        'RtlRemoveEntryHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENTRY", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_CONTEXT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["HashTable", "Entry", "Context"]),
        #
        'RtlLookupEntryHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_CONTEXT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENTRY", SimStruct), offset=0), arg_names=["HashTable", "Signature", "Context"]),
        #
        'RtlGetNextEntryHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_CONTEXT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENTRY", SimStruct), offset=0), arg_names=["HashTable", "Context"]),
        #
        'RtlInitEnumerationHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENUMERATOR", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["HashTable", "Enumerator"]),
        #
        'RtlEnumerateEntryHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENUMERATOR", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENTRY", SimStruct), offset=0), arg_names=["HashTable", "Enumerator"]),
        #
        'RtlEndEnumerationHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENUMERATOR", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["HashTable", "Enumerator"]),
        #
        'RtlInitWeakEnumerationHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENUMERATOR", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["HashTable", "Enumerator"]),
        #
        'RtlWeaklyEnumerateEntryHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENUMERATOR", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENTRY", SimStruct), offset=0), arg_names=["HashTable", "Enumerator"]),
        #
        'RtlEndWeakEnumerationHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENUMERATOR", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["HashTable", "Enumerator"]),
        #
        'RtlInitStrongEnumerationHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENUMERATOR", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["HashTable", "Enumerator"]),
        #
        'RtlStronglyEnumerateEntryHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENUMERATOR", SimStruct), offset=0)], SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENTRY", SimStruct), offset=0), arg_names=["HashTable", "Enumerator"]),
        #
        'RtlEndStrongEnumerationHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE_ENUMERATOR", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["HashTable", "Enumerator"]),
        #
        'RtlExpandHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["HashTable"]),
        #
        'RtlContractHashTable': SimTypeFunction([SimTypePointer(SimTypeRef("RTL_DYNAMIC_HASH_TABLE", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["HashTable"]),
        #
        'RtlGetCallersAddress': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallersAddress", "CallersCaller"]),
        #
        'RtlWalkFrameChain': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Callers", "Count", "Flags"]),
        #
        'RtlGetEnabledExtendedFeatures': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["FeatureMask"]),
        #
        'RtlCopyString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlUpperChar': SimTypeFunction([SimTypeChar(label="SByte")], SimTypeChar(label="SByte"), arg_names=["Character"]),
        #
        'RtlCompareString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["String1", "String2", "CaseInSensitive"]),
        #
        'RtlEqualString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["String1", "String2", "CaseInSensitive"]),
        #
        'RtlUpperString': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DestinationString", "SourceString"]),
        #
        'RtlPrefixUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["String1", "String2", "CaseInSensitive"]),
        #
        'RtlSuffixUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["String1", "String2", "CaseInSensitive"]),
        #
        'RtlUpcaseUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        #
        'RtlQueryRegistryValueWithFallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PrimaryHandle", "FallbackHandle", "ValueName", "ValueLength", "ValueType", "ValueData", "ResultLength"]),
        #
        'RtlMapGenericMask': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["AccessMask", "GenericMapping"]),
        #
        'RtlVolumeDeviceToDosName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeDeviceObject", "DosName"]),
        #
        'DbgPrompt': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Prompt", "Response", "Length"]),
        #
        'RtlGetActiveConsoleId': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'RtlGetConsoleSessionForegroundProcessId': SimTypeFunction([], SimTypeLongLong(signed=False, label="UInt64")),
        #
        'RtlGetSuiteMask': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'RtlIsMultiSessionSku': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'RtlIsStateSeparationEnabled': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'RtlGetPersistedStateLocation': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="STATE_LOCATION_TYPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceID", "CustomValue", "DefaultPath", "StateLocationType", "TargetPath", "BufferLengthIn", "BufferLengthOut"]),
        #
        'RtlIsApiSetImplemented': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["apiSetName"]),
        #
        'RtlIsMultiUsersInSessionSku': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'RtlGetNtProductType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="NT_PRODUCT_TYPE"), offset=0)], SimTypeChar(label="Byte"), arg_names=["NtProductType"]),
        #
        'RtlGetNtSystemRoot': SimTypeFunction([], SimTypePointer(SimTypeChar(label="Char"), offset=0)),
        #
        'RtlNormalizeSecurityDescriptor': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["SecurityDescriptor", "SecurityDescriptorLength", "NewSecurityDescriptor", "NewSecurityDescriptorLength", "CheckOnly"]),
        #
        'RtlSetSystemGlobalData': SimTypeFunction([SimTypeInt(signed=False, label="RTL_SYSTEM_GLOBAL_DATA_ID"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["DataId", "Buffer", "Size"]),
        #
        'NtOpenProcess': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIENT_ID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "DesiredAccess", "ObjectAttributes", "ClientId"]),
        #
        'KePulseEvent': SimTypeFunction([SimTypePointer(SimTypeRef("KEVENT", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["Event", "Increment", "Wait"]),
        #
        'KeExpandKernelStackAndCallout': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Callout", "Parameter", "Size"]),
        #
        'KeExpandKernelStackAndCalloutEx': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Callout", "Parameter", "Size", "Wait", "Context"]),
        #
        'KeSetBasePriorityThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread", "Increment"]),
        #
        'KeBugCheck': SimTypeFunction([SimTypeInt(signed=False, label="BUGCHECK_ERROR")], SimTypeBottom(label="Void"), arg_names=["BugCheckCode"]),
        #
        'KeInvalidateAllCaches': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'KeInvalidateRangeAllCaches': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["BaseAddress", "Length"]),
        #
        'KeSetHardwareCounterConfiguration': SimTypeFunction([SimTypePointer(SimTypeRef("HARDWARE_COUNTER", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["CounterArray", "Count"]),
        #
        'KeQueryHardwareCounterConfiguration': SimTypeFunction([SimTypePointer(SimTypeRef("HARDWARE_COUNTER", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CounterArray", "MaximumCount", "Count"]),
        #
        'ExRaiseDatatypeMisalignment': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'ExRaiseAccessViolation': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'ExInitializeZone': SimTypeFunction([SimTypePointer(SimTypeRef("ZONE_HEADER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Zone", "BlockSize", "InitialSegment", "InitialSegmentSize"]),
        #
        'ExExtendZone': SimTypeFunction([SimTypePointer(SimTypeRef("ZONE_HEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Zone", "Segment", "SegmentSize"]),
        #
        'ExInterlockedExtendZone': SimTypeFunction([SimTypePointer(SimTypeRef("ZONE_HEADER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Zone", "Segment", "SegmentSize", "Lock"]),
        #
        'ExUuidCreate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Uuid"]),
        #
        'MmIsThisAnNtAsSystem': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'MmMapUserAddressesToPage': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BaseAddress", "NumberOfBytes", "PageAddress"]),
        #
        'MmAddPhysicalMemory': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["StartAddress", "NumberOfBytes"]),
        #
        'MmRotatePhysicalView': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypeInt(signed=False, label="MM_ROTATE_DIRECTION"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeRef("MDL", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationMdl", "SourceMdl", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VirtualAddress", "NumberOfBytes", "NewMdl", "Direction", "CopyFunction", "Context"]),
        #
        'MmRemovePhysicalMemory': SimTypeFunction([SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["StartAddress", "NumberOfBytes"]),
        #
        'MmGetPhysicalMemoryRanges': SimTypeFunction([], SimTypePointer(SimTypeRef("PHYSICAL_MEMORY_RANGE", SimStruct), offset=0)),
        #
        'MmGetPhysicalMemoryRangesEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeRef("PHYSICAL_MEMORY_RANGE", SimStruct), offset=0), arg_names=["PartitionObject"]),
        #
        'MmGetPhysicalMemoryRangesEx2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("PHYSICAL_MEMORY_RANGE", SimStruct), offset=0), arg_names=["PartitionObject", "Flags"]),
        #
        'MmMapVideoDisplay': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PhysicalAddress", "NumberOfBytes", "CacheType"]),
        #
        'MmUnmapVideoDisplay': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["BaseAddress", "NumberOfBytes"]),
        #
        'MmGetPhysicalAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["BaseAddress"]),
        #
        'MmGetCacheAttribute': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PhysicalAddress", "CacheType"]),
        #
        'MmCopyMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeRef("MM_COPY_ADDRESS", SimStruct), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TargetAddress", "SourceAddress", "NumberOfBytes", "Flags", "NumberOfBytesTransferred"]),
        #
        'MmGetCacheAttributeEx': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="MEMORY_CACHING_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PhysicalAddress", "Flags", "CacheType"]),
        #
        'MmGetVirtualForPhysical': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["PhysicalAddress"]),
        #
        'MmAllocateNonCachedMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NumberOfBytes"]),
        #
        'MmFreeNonCachedMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["BaseAddress", "NumberOfBytes"]),
        #
        'MmIsAddressValid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["VirtualAddress"]),
        #
        'MmIsNonPagedSystemAddressValid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["VirtualAddress"]),
        #
        'MmLockPagableSectionByHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ImageSectionHandle"]),
        #
        'MmSecureVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Address", "Size", "ProbeMode"]),
        #
        'MmSecureVirtualMemoryEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Address", "Size", "ProbeMode", "Flags"]),
        #
        'MmUnsecureVirtualMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["SecureHandle"]),
        #
        'MmMapViewInSystemSpaceEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Section", "MappedBase", "ViewSize", "SectionOffset", "Flags"]),
        #
        'MmMapViewInSystemSpace': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Section", "MappedBase", "ViewSize"]),
        #
        'MmUnmapViewInSystemSpace': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MappedBase"]),
        #
        'MmMapViewInSessionSpaceEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Section", "MappedBase", "ViewSize", "SectionOffset", "Flags"]),
        #
        'MmMapViewInSessionSpace': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Section", "MappedBase", "ViewSize"]),
        #
        'MmUnmapViewInSessionSpace': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MappedBase"]),
        #
        'MmCreateMirror': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SeSinglePrivilegeCheck': SimTypeFunction([SimTypeRef("LUID", SimStruct), SimTypeChar(label="SByte")], SimTypeChar(label="Byte"), arg_names=["PrivilegeValue", "PreviousMode"]),
        #
        'PsSetCreateProcessNotifyRoutine': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["ParentId", "ProcessId", "Create"]), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["NotifyRoutine", "Remove"]),
        #
        'PsSetCreateProcessNotifyRoutineEx': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PS_CREATE_NOTIFY_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Process", "ProcessId", "CreateInfo"]), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["NotifyRoutine", "Remove"]),
        #
        'PsSetCreateProcessNotifyRoutineEx2': SimTypeFunction([SimTypeInt(signed=False, label="PSCREATEPROCESSNOTIFYTYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["NotifyType", "NotifyInformation", "Remove"]),
        #
        'PsSetCreateThreadNotifyRoutine': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["ProcessId", "ThreadId", "Create"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotifyRoutine"]),
        #
        'PsSetCreateThreadNotifyRoutineEx': SimTypeFunction([SimTypeInt(signed=False, label="PSCREATETHREADNOTIFYTYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotifyType", "NotifyInformation"]),
        #
        'PsRemoveCreateThreadNotifyRoutine': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["ProcessId", "ThreadId", "Create"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotifyRoutine"]),
        #
        'PsSetLoadImageNotifyRoutine': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IMAGE_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FullImageName", "ProcessId", "ImageInfo"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotifyRoutine"]),
        #
        'PsSetLoadImageNotifyRoutineEx': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IMAGE_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FullImageName", "ProcessId", "ImageInfo"]), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotifyRoutine", "Flags"]),
        #
        'PsRemoveLoadImageNotifyRoutine': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("IMAGE_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["FullImageName", "ProcessId", "ImageInfo"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotifyRoutine"]),
        #
        'PsGetCurrentProcessId': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'PsGetCurrentThreadId': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'PsSetCurrentThreadPrefetching': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["Prefetching"]),
        #
        'PsIsCurrentThreadPrefetching': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'PsGetProcessCreateTimeQuadPart': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["Process"]),
        #
        'PsGetProcessStartKey': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeLongLong(signed=False, label="UInt64"), arg_names=["Process"]),
        #
        'PsGetProcessExitStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Process"]),
        #
        'PsGetThreadExitStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Thread"]),
        #
        'PsGetProcessId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Process"]),
        #
        'PsGetThreadId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Thread"]),
        #
        'PsGetThreadProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Thread", "Key", "Flags"]),
        #
        'PsGetThreadProcessId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Thread"]),
        #
        'PsGetThreadCreateTime': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeLongLong(signed=True, label="Int64"), arg_names=["Thread"]),
        #
        'PsGetCurrentThreadTeb': SimTypeFunction([], SimTypePointer(SimTypeBottom(label="Void"), offset=0)),
        #
        'PsGetJobSilo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Job", "Silo"]),
        #
        'PsGetJobServerSilo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Job", "ServerSilo"]),
        #
        'PsGetEffectiveServerSilo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Silo"]),
        #
        'PsAttachSiloToCurrentThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Silo"]),
        #
        'PsDetachSiloFromCurrentThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["PreviousSilo"]),
        #
        'PsIsHostSilo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["Silo"]),
        #
        'PsGetHostSilo': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'PsGetCurrentSilo': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'PsGetCurrentServerSilo': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'PsGetCurrentServerSiloName': SimTypeFunction([], SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)),
        #
        'PsIsCurrentThreadInServerSilo': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'PsAcquireSiloHardReference': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Silo"]),
        #
        'PsReleaseSiloHardReference': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Silo"]),
        #
        'PsAllocSiloContextSlot': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Reserved", "ReturnedContextSlot"]),
        #
        'PsFreeSiloContextSlot': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ContextSlot"]),
        #
        'PsCreateSiloContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="POOL_TYPE"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SiloContext"]), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Silo", "Size", "PoolType", "ContextCleanupCallback", "ReturnedSiloContext"]),
        #
        'PsInsertSiloContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Silo", "ContextSlot", "SiloContext"]),
        #
        'PsReplaceSiloContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Silo", "ContextSlot", "NewSiloContext", "OldSiloContext"]),
        #
        'PsGetSiloContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Silo", "ContextSlot", "ReturnedSiloContext"]),
        #
        'PsRemoveSiloContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Silo", "ContextSlot", "RemovedSiloContext"]),
        #
        'PsReferenceSiloContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SiloContext"]),
        #
        'PsDereferenceSiloContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["SiloContext"]),
        #
        'PsInsertPermanentSiloContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Silo", "ContextSlot", "SiloContext"]),
        #
        'PsMakeSiloContextPermanent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Silo", "ContextSlot"]),
        #
        'PsGetPermanentSiloContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Silo", "ContextSlot", "ReturnedSiloContext"]),
        #
        'PsRegisterSiloMonitor': SimTypeFunction([SimTypePointer(SimTypeRef("SILO_MONITOR_REGISTRATION", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Registration", "ReturnedMonitor"]),
        #
        'PsStartSiloMonitor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Monitor"]),
        #
        'PsGetSiloMonitorContextSlot': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Monitor"]),
        #
        'PsUnregisterSiloMonitor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["Monitor"]),
        #
        'PsGetServerSiloServiceSessionId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Silo"]),
        #
        'PsTerminateServerSilo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["ServerSilo", "ExitStatus"]),
        #
        'PsGetParentSilo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Job"]),
        #
        'PsGetThreadServerSilo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["Thread"]),
        #
        'PsGetSiloContainerId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Guid"), offset=0), arg_names=["Silo"]),
        #
        'IoAllocateAdapterChannel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="IO_ALLOCATION_ACTION"), arg_names=["DeviceObject", "Irp", "MapRegisterBase", "Context"]), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AdapterObject", "DeviceObject", "NumberOfMapRegisters", "ExecutionRoutine", "Context"]),
        #
        'IoAllocateController': SimTypeFunction([SimTypePointer(SimTypeRef("CONTROLLER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="IO_ALLOCATION_ACTION"), arg_names=["DeviceObject", "Irp", "MapRegisterBase", "Context"]), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ControllerObject", "DeviceObject", "ExecutionRoutine", "Context"]),
        #
        'IoAssignResources': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_RESOURCE_REQUIREMENTS_LIST", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("CM_RESOURCE_LIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RegistryPath", "DriverClassName", "DriverObject", "DeviceObject", "RequestedResources", "AllocatedResources"]),
        #
        'IoAttachDeviceByPointer': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceDevice", "TargetDevice"]),
        #
        'IoCreateController': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("CONTROLLER_OBJECT", SimStruct), offset=0), arg_names=["Size"]),
        #
        'IoDeleteController': SimTypeFunction([SimTypePointer(SimTypeRef("CONTROLLER_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ControllerObject"]),
        #
        'IoFreeController': SimTypeFunction([SimTypePointer(SimTypeRef("CONTROLLER_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ControllerObject"]),
        #
        'IoGetConfigurationInformation': SimTypeFunction([], SimTypePointer(SimTypeRef("CONFIGURATION_INFORMATION", SimStruct), offset=0)),
        #
        'IoGetFileObjectGenericMapping': SimTypeFunction([], SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)),
        #
        'IoCancelFileOpen': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "FileObject"]),
        #
        'IoMakeAssociatedIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeChar(label="SByte")], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), arg_names=["Irp", "StackSize"]),
        #
        'IoMakeAssociatedIrpEx': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="SByte")], SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), arg_names=["Irp", "DeviceObject", "StackSize"]),
        #
        'IoQueryDeviceDescription': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="INTERFACE_TYPE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CONFIGURATION_TYPE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="CONFIGURATION_TYPE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="INTERFACE_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("KEY_VALUE_FULL_INFORMATION", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="CONFIGURATION_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("KEY_VALUE_FULL_INFORMATION", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="CONFIGURATION_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("KEY_VALUE_FULL_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Context", "PathName", "BusType", "BusNumber", "BusInformation", "ControllerType", "ControllerNumber", "ControllerInformation", "PeripheralType", "PeripheralNumber", "PeripheralInformation"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BusType", "BusNumber", "ControllerType", "ControllerNumber", "PeripheralType", "PeripheralNumber", "CalloutRoutine", "Context"]),
        #
        'IoRaiseHardError': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeRef("VPB", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irp", "Vpb", "RealDeviceObject"]),
        #
        'IoRaiseInformationalHardError': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["ErrorStatus", "String", "Thread"]),
        #
        'IoSetThreadHardErrorMode': SimTypeFunction([SimTypeChar(label="Byte")], SimTypeChar(label="Byte"), arg_names=["EnableHardErrors"]),
        #
        'IoRegisterBootDriverReinitialization': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["DriverObject", "Context", "Count"]), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DriverObject", "DriverReinitializationRoutine", "Context"]),
        #
        'IoRegisterDriverReinitialization': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["DriverObject", "Context", "Count"]), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DriverObject", "DriverReinitializationRoutine", "Context"]),
        #
        'IoReportResourceUsage': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CM_RESOURCE_LIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CM_RESOURCE_LIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverClassName", "DriverObject", "DriverList", "DriverListSize", "DeviceObject", "DeviceList", "DeviceListSize", "OverrideConflict", "ConflictDetected"]),
        #
        'IoTranslateBusAddress': SimTypeFunction([SimTypeInt(signed=False, label="INTERFACE_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeChar(label="Byte"), arg_names=["InterfaceType", "BusNumber", "BusAddress", "AddressSpace", "TranslatedAddress"]),
        #
        'IoSetHardErrorOrVerifyDevice': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irp", "DeviceObject"]),
        #
        'HalExamineMBR': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["DeviceObject", "SectorSize", "MBRTypeIdentifier", "Buffer"]),
        #
        'IoReadPartitionTable': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("DRIVE_LAYOUT_INFORMATION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "SectorSize", "ReturnRecognizedPartitions", "PartitionBuffer"]),
        #
        'IoSetPartitionInformation': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "SectorSize", "PartitionNumber", "PartitionType"]),
        #
        'IoWritePartitionTable': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DRIVE_LAYOUT_INFORMATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "SectorSize", "SectorsPerTrack", "NumberOfHeads", "PartitionBuffer"]),
        #
        'IoCreateDisk': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CREATE_DISK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "Disk"]),
        #
        'IoReadPartitionTableEx': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DRIVE_LAYOUT_INFORMATION_EX", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "DriveLayout"]),
        #
        'IoWritePartitionTableEx': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DRIVE_LAYOUT_INFORMATION_EX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "DriveLayout"]),
        #
        'IoSetPartitionInformationEx': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SET_PARTITION_INFORMATION_EX", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "PartitionNumber", "PartitionInfo"]),
        #
        'IoVerifyPartitionTable': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "FixErrors"]),
        #
        'IoReadDiskSignature': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DISK_SIGNATURE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceObject", "BytesPerSector", "Signature"]),
        #
        'IoVolumeDeviceToDosName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeDeviceObject", "DosName"]),
        #
        'IoVolumeDeviceToGuidPath': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeDeviceObject", "GuidPath"]),
        #
        'IoVolumeDeviceToGuid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeDeviceObject", "Guid"]),
        #
        'IoVolumeDeviceNameToGuid': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeDeviceName", "Guid"]),
        #
        'IoVolumeDeviceNameToGuidPath': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeDeviceName", "GuidPath"]),
        #
        'IoSetSystemPartition': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["VolumeNameString"]),
        #
        'IoCreateFileSpecifyDeviceObjectHint': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CREATE_FILE_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "AllocationSize", "FileAttributes", "ShareAccess", "Disposition", "CreateOptions", "EaBuffer", "EaLength", "CreateFileType", "InternalParameters", "Options", "DeviceObject"]),
        #
        'IoGetSiloParameters': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("IO_FOEXT_SILO_PARAMETERS", SimStruct), offset=0), arg_names=["FileObject"]),
        #
        'IoGetSilo': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["FileObject"]),
        #
        'IoGetTransactionParameterBlock': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeRef("TXN_PARAMETER_BLOCK", SimStruct), offset=0), arg_names=["FileObject"]),
        #
        'IoCreateFileEx': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="CREATE_FILE_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IO_DRIVER_CREATE_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "DesiredAccess", "ObjectAttributes", "IoStatusBlock", "AllocationSize", "FileAttributes", "ShareAccess", "Disposition", "CreateOptions", "EaBuffer", "EaLength", "CreateFileType", "InternalParameters", "Options", "DriverContext"]),
        #
        'IoSetIrpExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "ExtraCreateParameter"]),
        #
        'IoClearIrpExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Irp"]),
        #
        'IoGetIrpExtraCreateParameter': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "ExtraCreateParameter"]),
        #
        'IoQueryInformationByName': SimTypeFunction([SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FILE_INFORMATION_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IO_DRIVER_CREATE_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ObjectAttributes", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass", "Options", "DriverContext"]),
        #
        'IoAttachDeviceToDeviceStackSafe': SimTypeFunction([SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceDevice", "TargetDevice", "AttachedToDeviceObject"]),
        #
        'IoIsFileOriginRemote': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject"]),
        #
        'IoSetFileOrigin': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "Remote"]),
        #
        'IoIsFileObjectIgnoringSharing': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["FileObject"]),
        #
        'IoSetFileObjectIgnoreSharing': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject"]),
        #
        'IoGetPagingIoPriority': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=False, label="IO_PAGING_PRIORITY"), arg_names=["Irp"]),
        #
        'IoRegisterBootDriverCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeBottom(label="Void")), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["CallbackFunction", "CallbackContext"]),
        #
        'IoUnregisterBootDriverCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallbackHandle"]),
        #
        'IoGetActivityIdIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "Guid"]),
        #
        'IoSetActivityIdIrp': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "Guid"]),
        #
        'IoPropagateActivityIdToThread': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "PropagatedId", "OriginalId"]),
        #
        'IoSetActivityIdThread': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypePointer(SimTypeBottom(label="Guid"), offset=0), arg_names=["ActivityId"]),
        #
        'IoClearActivityIdThread': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["OriginalId"]),
        #
        'IoGetActivityIdThread': SimTypeFunction([], SimTypePointer(SimTypeBottom(label="Guid"), offset=0)),
        #
        'IoTransferActivityId': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ActivityId", "RelatedActivityId"]),
        #
        'IoGetFsZeroingOffset': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "ZeroingOffset"]),
        #
        'IoSetFsZeroingOffsetRequired': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp"]),
        #
        'IoSetFsZeroingOffset': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Irp", "ZeroingOffset"]),
        #
        'IoIsValidIrpStatus': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Status"]),
        #
        'IoIncrementKeepAliveCount': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "Process"]),
        #
        'IoDecrementKeepAliveCount': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FileObject", "Process"]),
        #
        'IoGetInitiatorProcess': SimTypeFunction([SimTypePointer(SimTypeRef("FILE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["FileObject"]),
        #
        'IoSetMasterIrpStatus': SimTypeFunction([SimTypePointer(SimTypeRef("IRP", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["MasterIrp", "Status"]),
        #
        'IoQueryFullDriverPath': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "FullPath"]),
        #
        'IoReportDetectedDevice': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypeInt(signed=False, label="INTERFACE_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("CM_RESOURCE_LIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("IO_RESOURCE_REQUIREMENTS_LIST", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "LegacyBusType", "BusNumber", "SlotNumber", "ResourceList", "ResourceRequirements", "ResourceAssigned", "DeviceObject"]),
        #
        'IoReportRootDevice': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject"]),
        #
        'IoReportResourceForDetection': SimTypeFunction([SimTypePointer(SimTypeRef("DRIVER_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CM_RESOURCE_LIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeRef("CM_RESOURCE_LIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DriverObject", "DriverList", "DriverListSize", "DeviceObject", "DeviceList", "DeviceListSize", "ConflictDetected"]),
        #
        'FsRtlIsTotalDeviceFailure': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeChar(label="Byte"), arg_names=["Status"]),
        #
        'ZwCreateTimer': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="TIMER_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["TimerHandle", "DesiredAccess", "ObjectAttributes", "TimerType"]),
        #
        'ZwOpenTimer': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TimerHandle", "DesiredAccess", "ObjectAttributes"]),
        #
        'ZwCancelTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TimerHandle", "CurrentState"]),
        #
        'ZwSetTimer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["TimerContext", "TimerLowValue", "TimerHighValue"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TimerHandle", "DueTime", "TimerApcRoutine", "TimerContext", "ResumeTimer", "Period", "PreviousState"]),
        #
        'ZwSetTimerEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TIMER_SET_INFORMATION_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["TimerHandle", "TimerSetInformationClass", "TimerSetInformation", "TimerSetInformationLength"]),
        #
        'ZwDeviceIoControlFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "IoControlCode", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength"]),
        #
        'ZwDisplayString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["String"]),
        #
        'ZwPowerInformation': SimTypeFunction([SimTypeInt(signed=False, label="POWER_INFORMATION_LEVEL"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["InformationLevel", "InputBuffer", "InputBufferLength", "OutputBuffer", "OutputBufferLength"]),
        #
        'ZwAllocateLocallyUniqueId': SimTypeFunction([SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Luid"]),
        #
        'ZwTerminateProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "ExitStatus"]),
        #
        'ZwOpenProcess': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIENT_ID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "DesiredAccess", "ObjectAttributes", "ClientId"]),
        #
        'WheaAddErrorSourceDeviceDriver': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Context", "Configuration", "NumberPreallocatedErrorReports"]),
        #
        'WheaAddErrorSourceDeviceDriverV1': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Context", "Configuration", "NumBuffersToPreallocate", "MaxDataLength"]),
        #
        'WheaRemoveErrorSourceDeviceDriver': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ErrorSourceId"]),
        #
        'WheaReportHwErrorDeviceDriver': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="WHEA_ERROR_SEVERITY"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ErrorSourceId", "DeviceObject", "ErrorData", "ErrorDataLength", "SectionTypeGuid", "ErrorSeverity", "DeviceFriendlyName"]),
        #
        'WheaCreateHwErrorReportDeviceDriver': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVICE_OBJECT", SimStruct), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["ErrorSourceId", "DeviceObject"]),
        #
        'WheaAddHwErrorReportSectionDeviceDriver': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WHEA_DRIVER_BUFFER_SET", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ErrorHandle", "SectionDataLength", "BufferSet"]),
        #
        'WheaHwErrorReportAbandonDeviceDriver': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ErrorHandle"]),
        #
        'WheaHwErrorReportSubmitDeviceDriver': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ErrorHandle"]),
        #
        'WheaHwErrorReportSetSeverityDeviceDriver': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="WHEA_ERROR_SEVERITY")], SimTypeInt(signed=True, label="Int32"), arg_names=["ErrorHandle", "ErrorSeverity"]),
        #
        'WheaHwErrorReportSetSectionNameDeviceDriver': SimTypeFunction([SimTypePointer(SimTypeRef("WHEA_DRIVER_BUFFER_SET", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["BufferSet", "NameLength", "Name"]),
        #
        'WheaReportHwError': SimTypeFunction([SimTypePointer(SimTypeRef("WHEA_ERROR_PACKET_V2", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ErrorPacket"]),
        #
        'WheaAddErrorSource': SimTypeFunction([SimTypePointer(SimTypeRef("WHEA_ERROR_SOURCE_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ErrorSource", "Context"]),
        #
        'WheaInitializeRecordHeader': SimTypeFunction([SimTypePointer(SimTypeRef("WHEA_ERROR_RECORD_HEADER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Header"]),
        #
        'WheaConfigureErrorSource': SimTypeFunction([SimTypeInt(signed=False, label="WHEA_ERROR_SOURCE_TYPE"), SimTypePointer(SimTypeRef("WHEA_ERROR_SOURCE_CONFIGURATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceType", "Configuration"]),
        #
        'WheaUnconfigureErrorSource': SimTypeFunction([SimTypeInt(signed=False, label="WHEA_ERROR_SOURCE_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["SourceType"]),
        #
        'WheaRemoveErrorSource': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ErrorSourceId"]),
        #
        'WheaLogInternalEvent': SimTypeFunction([SimTypePointer(SimTypeRef("WHEA_EVENT_LOG_ENTRY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Entry"]),
        #
        'WheaErrorSourceGetState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WHEA_ERROR_SOURCE_STATE"), arg_names=["ErrorSourceId"]),
        #
        'WheaIsCriticalState': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'WheaHighIrqlLogSelEventHandlerRegister': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IPMI_OS_SEL_RECORD", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Context", "OsSelRecord"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Handler", "Context"]),
        #
        'WheaHighIrqlLogSelEventHandlerUnregister': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'WheaRegisterInUsePageOfflineNotification': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Page", "Flags", "Poisoned", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Callback", "Context"]),
        #
        'WheaUnregisterInUsePageOfflineNotification': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeChar(label="Byte"), arg_names=["Page", "Flags", "Poisoned", "Context"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Callback"]),
        #
        'WheaGetNotifyAllOfflinesPolicy': SimTypeFunction([], SimTypeChar(label="Byte")),
        #
        'HvlRegisterWheaErrorNotification': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Callback"]),
        #
        'HvlUnregisterWheaErrorNotification': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypeInt(signed=True, label="Int32")), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Callback"]),
        #
        'NtQueryInformationProcess': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PROCESSINFOCLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "ProcessInformationClass", "ProcessInformation", "ProcessInformationLength", "ReturnLength"]),
        #
        'NtQueryInformationThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="THREADINFOCLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle", "ThreadInformationClass", "ThreadInformation", "ThreadInformationLength", "ReturnLength"]),
        #
        'NtSetInformationThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="THREADINFOCLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle", "ThreadInformationClass", "ThreadInformation", "ThreadInformationLength"]),
        #
        'NtWaitForSingleObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "Alertable", "Timeout"]),
        #
        'ZwSetInformationThread': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="THREADINFOCLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ThreadHandle", "ThreadInformationClass", "ThreadInformation", "ThreadInformationLength"]),
    }

lib.set_prototypes(prototypes)
