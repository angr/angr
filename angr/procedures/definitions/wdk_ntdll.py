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
lib.set_library_names("ntdll.dll")
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
        'PfxInitialize': SimTypeFunction([SimTypePointer(SimTypeRef("PREFIX_TABLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PrefixTable"]),
        # 
        'PfxInsertPrefix': SimTypeFunction([SimTypePointer(SimTypeRef("PREFIX_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("PREFIX_TABLE_ENTRY", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["PrefixTable", "Prefix", "PrefixTableEntry"]),
        # 
        'PfxRemovePrefix': SimTypeFunction([SimTypePointer(SimTypeRef("PREFIX_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("PREFIX_TABLE_ENTRY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PrefixTable", "PrefixTableEntry"]),
        # 
        'PfxFindPrefix': SimTypeFunction([SimTypePointer(SimTypeRef("PREFIX_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0)], SimTypePointer(SimTypeRef("PREFIX_TABLE_ENTRY", SimStruct), offset=0), arg_names=["PrefixTable", "FullName"]),
        # 
        'RtlGetCompressionWorkSpaceSize': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormatAndEngine", "CompressBufferWorkSpaceSize", "CompressFragmentWorkSpaceSize"]),
        # 
        'RtlCompressBuffer': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormatAndEngine", "UncompressedBuffer", "UncompressedBufferSize", "CompressedBuffer", "CompressedBufferSize", "UncompressedChunkSize", "FinalCompressedSize", "WorkSpace"]),
        # 
        'RtlDecompressBuffer': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormat", "UncompressedBuffer", "UncompressedBufferSize", "CompressedBuffer", "CompressedBufferSize", "FinalUncompressedSize"]),
        # 
        'RtlDecompressBufferEx': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormat", "UncompressedBuffer", "UncompressedBufferSize", "CompressedBuffer", "CompressedBufferSize", "FinalUncompressedSize", "WorkSpace"]),
        # 
        'RtlDecompressFragment': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["CompressionFormat", "UncompressedFragment", "UncompressedFragmentSize", "CompressedBuffer", "CompressedBufferSize", "FragmentOffset", "FinalUncompressedSize", "WorkSpace"]),
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
        'RtlInitUTF8String': SimTypeFunction([SimTypePointer(SimTypeRef("STRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["DestinationString", "SourceString"]),
        # 
        'RtlQueryRegistryValues': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("RTL_QUERY_REGISTRY_TABLE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RelativeTo", "Path", "QueryTable", "Context", "Environment"]),
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
        'EtwEventEnabled': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("EVENT_DESCRIPTOR", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["RegHandle", "EventDescriptor"]),
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
        'RtlUpcaseUnicodeString': SimTypeFunction([SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["DestinationString", "SourceString", "AllocateDestinationString"]),
        # 
        'RtlQueryRegistryValueWithFallback': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UNICODE_STRING", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PrimaryHandle", "FallbackHandle", "ValueName", "ValueLength", "ValueType", "ValueData", "ResultLength"]),
        # 
        'RtlMapGenericMask': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("GENERIC_MAPPING", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["AccessMask", "GenericMapping"]),
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
        'NtOpenProcess': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OBJECT_ATTRIBUTES", SimStruct), offset=0), SimTypePointer(SimTypeRef("CLIENT_ID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProcessHandle", "DesiredAccess", "ObjectAttributes", "ClientId"]),
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
