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
lib.set_library_names("winbio.dll")
prototypes = \
    {
        #
        'WinBioEnumServiceProviders': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("WINBIO_BSP_SCHEMA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Factor", "BspSchemaArray", "BspCount"]),
        #
        'WinBioEnumBiometricUnits': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("WINBIO_UNIT_SCHEMA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Factor", "UnitSchemaArray", "UnitCount"]),
        #
        'WinBioEnumDatabases': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("WINBIO_STORAGE_SCHEMA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Factor", "StorageSchemaArray", "StorageCount"]),
        #
        'WinBioAsyncOpenFramework': SimTypeFunction([SimTypeInt(signed=False, label="WINBIO_ASYNC_NOTIFICATION_METHOD"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("WINBIO_ASYNC_RESULT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["AsyncResult"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NotificationMethod", "TargetWindow", "MessageCode", "CallbackRoutine", "UserData", "AsynchronousOpen", "FrameworkHandle"]),
        #
        'WinBioCloseFramework': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FrameworkHandle"]),
        #
        'WinBioAsyncEnumServiceProviders': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FrameworkHandle", "Factor"]),
        #
        'WinBioAsyncEnumBiometricUnits': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FrameworkHandle", "Factor"]),
        #
        'WinBioAsyncEnumDatabases': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FrameworkHandle", "Factor"]),
        #
        'WinBioAsyncMonitorFrameworkChanges': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FrameworkHandle", "ChangeTypes"]),
        #
        'WinBioOpenSession': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WINBIO_POOL"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Factor", "PoolType", "Flags", "UnitArray", "UnitCount", "DatabaseId", "SessionHandle"]),
        #
        'WinBioAsyncOpenSession': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WINBIO_POOL"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="WINBIO_ASYNC_NOTIFICATION_METHOD"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("WINBIO_ASYNC_RESULT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["AsyncResult"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Factor", "PoolType", "Flags", "UnitArray", "UnitCount", "DatabaseId", "NotificationMethod", "TargetWindow", "MessageCode", "CallbackRoutine", "UserData", "AsynchronousOpen", "SessionHandle"]),
        #
        'WinBioCloseSession': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle"]),
        #
        'WinBioVerify': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WINBIO_IDENTITY", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "Identity", "SubFactor", "UnitId", "Match", "RejectDetail"]),
        #
        'WinBioVerifyWithCallback': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WINBIO_IDENTITY", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["VerifyCallbackContext", "OperationStatus", "UnitId", "Match", "RejectDetail"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "Identity", "SubFactor", "VerifyCallback", "VerifyCallbackContext"]),
        #
        'WinBioIdentify': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WINBIO_IDENTITY", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "UnitId", "Identity", "SubFactor", "RejectDetail"]),
        #
        'WinBioIdentifyWithCallback': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WINBIO_IDENTITY", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["IdentifyCallbackContext", "OperationStatus", "UnitId", "Identity", "SubFactor", "RejectDetail"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "IdentifyCallback", "IdentifyCallbackContext"]),
        #
        'WinBioWait': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle"]),
        #
        'WinBioCancel': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle"]),
        #
        'WinBioLocateSensor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "UnitId"]),
        #
        'WinBioLocateSensorWithCallback': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["LocateCallbackContext", "OperationStatus", "UnitId"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "LocateCallback", "LocateCallbackContext"]),
        #
        'WinBioEnrollBegin': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "SubFactor", "UnitId"]),
        #
        'WinBioEnrollSelect': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "SelectorValue"]),
        #
        'WinBioEnrollCapture': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "RejectDetail"]),
        #
        'WinBioEnrollCaptureWithCallback': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["EnrollCallbackContext", "OperationStatus", "RejectDetail"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "EnrollCallback", "EnrollCallbackContext"]),
        #
        'WinBioEnrollCommit': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WINBIO_IDENTITY", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "Identity", "IsNewTemplate"]),
        #
        'WinBioEnrollDiscard': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle"]),
        #
        'WinBioEnumEnrollments': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WINBIO_IDENTITY", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "UnitId", "Identity", "SubFactorArray", "SubFactorCount"]),
        #
        'WinBioImproveBegin': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "UnitId"]),
        #
        'WinBioImproveEnd': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle"]),
        #
        'WinBioRegisterEventMonitor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("WINBIO_EVENT", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["EventCallbackContext", "OperationStatus", "Event"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "EventMask", "EventCallback", "EventCallbackContext"]),
        #
        'WinBioUnregisterEventMonitor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle"]),
        #
        'WinBioMonitorPresence': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "UnitId"]),
        #
        'WinBioCaptureSample': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("WINBIO_BIR", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "Purpose", "Flags", "UnitId", "Sample", "SampleSize", "RejectDetail"]),
        #
        'WinBioCaptureSampleWithCallback': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WINBIO_BIR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["CaptureCallbackContext", "OperationStatus", "UnitId", "Sample", "SampleSize", "RejectDetail"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "Purpose", "Flags", "CaptureCallback", "CaptureCallbackContext"]),
        #
        'WinBioDeleteTemplate': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WINBIO_IDENTITY", SimStruct), offset=0), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "UnitId", "Identity", "SubFactor"]),
        #
        'WinBioLockUnit': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "UnitId"]),
        #
        'WinBioUnlockUnit': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "UnitId"]),
        #
        'WinBioControlUnit': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WINBIO_COMPONENT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "UnitId", "Component", "ControlCode", "SendBuffer", "SendBufferSize", "ReceiveBuffer", "ReceiveBufferSize", "ReceiveDataSize", "OperationStatus"]),
        #
        'WinBioControlUnitPrivileged': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WINBIO_COMPONENT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "UnitId", "Component", "ControlCode", "SendBuffer", "SendBufferSize", "ReceiveBuffer", "ReceiveBufferSize", "ReceiveDataSize", "OperationStatus"]),
        #
        'WinBioGetProperty': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WINBIO_IDENTITY", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "PropertyType", "PropertyId", "UnitId", "Identity", "SubFactor", "PropertyBuffer", "PropertyBufferSize"]),
        #
        'WinBioSetProperty': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WINBIO_IDENTITY", SimStruct), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle", "PropertyType", "PropertyId", "UnitId", "Identity", "SubFactor", "PropertyBuffer", "PropertyBufferSize"]),
        #
        'WinBioFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Address"]),
        #
        'WinBioSetCredential': SimTypeFunction([SimTypeInt(signed=False, label="WINBIO_CREDENTIAL_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="WINBIO_CREDENTIAL_FORMAT")], SimTypeInt(signed=True, label="Int32"), arg_names=["Type", "Credential", "CredentialSize", "Format"]),
        #
        'WinBioRemoveCredential': SimTypeFunction([SimTypeRef("WINBIO_IDENTITY", SimStruct), SimTypeInt(signed=False, label="WINBIO_CREDENTIAL_TYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["Identity", "Type"]),
        #
        'WinBioRemoveAllCredentials': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'WinBioRemoveAllDomainCredentials': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'WinBioGetCredentialState': SimTypeFunction([SimTypeRef("WINBIO_IDENTITY", SimStruct), SimTypeInt(signed=False, label="WINBIO_CREDENTIAL_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="WINBIO_CREDENTIAL_STATE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Identity", "Type", "CredentialState"]),
        #
        'WinBioLogonIdentifiedUser': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["SessionHandle"]),
        #
        'WinBioGetEnrolledFactors': SimTypeFunction([SimTypePointer(SimTypeRef("WINBIO_IDENTITY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AccountOwner", "EnrolledFactors"]),
        #
        'WinBioGetEnabledSetting': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="WINBIO_SETTING_SOURCE"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Value", "Source"]),
        #
        'WinBioGetLogonSetting': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="WINBIO_SETTING_SOURCE"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Value", "Source"]),
        #
        'WinBioGetDomainLogonSetting': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="WINBIO_SETTING_SOURCE"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Value", "Source"]),
        #
        'WinBioAcquireFocus': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'WinBioReleaseFocus': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
    }

lib.set_prototypes(prototypes)
