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
lib.set_library_names("rpcns4.dll")
prototypes = \
    {
        #
        'RpcIfIdVectorFree': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RPC_IF_ID_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfIdVector"]),
        #
        'RpcNsBindingExportA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "BindingVec", "ObjectUuidVec"]),
        #
        'RpcNsBindingUnexportA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "ObjectUuidVec"]),
        #
        'RpcNsBindingExportW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "BindingVec", "ObjectUuidVec"]),
        #
        'RpcNsBindingUnexportW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "ObjectUuidVec"]),
        #
        'RpcNsBindingExportPnPA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "ObjectVector"]),
        #
        'RpcNsBindingUnexportPnPA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "ObjectVector"]),
        #
        'RpcNsBindingExportPnPW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "ObjectVector"]),
        #
        'RpcNsBindingUnexportPnPW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "ObjectVector"]),
        #
        'RpcNsBindingLookupBeginA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "ObjUuid", "BindingMaxCount", "LookupContext"]),
        #
        'RpcNsBindingLookupBeginW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "ObjUuid", "BindingMaxCount", "LookupContext"]),
        #
        'RpcNsBindingLookupNext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["LookupContext", "BindingVec"]),
        #
        'RpcNsBindingLookupDone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["LookupContext"]),
        #
        'RpcNsGroupDeleteA': SimTypeFunction([SimTypeInt(signed=False, label="GROUP_NAME_SYNTAX"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["GroupNameSyntax", "GroupName"]),
        #
        'RpcNsGroupMbrAddA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["GroupNameSyntax", "GroupName", "MemberNameSyntax", "MemberName"]),
        #
        'RpcNsGroupMbrRemoveA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["GroupNameSyntax", "GroupName", "MemberNameSyntax", "MemberName"]),
        #
        'RpcNsGroupMbrInqBeginA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["GroupNameSyntax", "GroupName", "MemberNameSyntax", "InquiryContext"]),
        #
        'RpcNsGroupMbrInqNextA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext", "MemberName"]),
        #
        'RpcNsGroupDeleteW': SimTypeFunction([SimTypeInt(signed=False, label="GROUP_NAME_SYNTAX"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["GroupNameSyntax", "GroupName"]),
        #
        'RpcNsGroupMbrAddW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["GroupNameSyntax", "GroupName", "MemberNameSyntax", "MemberName"]),
        #
        'RpcNsGroupMbrRemoveW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["GroupNameSyntax", "GroupName", "MemberNameSyntax", "MemberName"]),
        #
        'RpcNsGroupMbrInqBeginW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["GroupNameSyntax", "GroupName", "MemberNameSyntax", "InquiryContext"]),
        #
        'RpcNsGroupMbrInqNextW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext", "MemberName"]),
        #
        'RpcNsGroupMbrInqDone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext"]),
        #
        'RpcNsProfileDeleteA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProfileNameSyntax", "ProfileName"]),
        #
        'RpcNsProfileEltAddA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProfileNameSyntax", "ProfileName", "IfId", "MemberNameSyntax", "MemberName", "Priority", "Annotation"]),
        #
        'RpcNsProfileEltRemoveA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProfileNameSyntax", "ProfileName", "IfId", "MemberNameSyntax", "MemberName"]),
        #
        'RpcNsProfileEltInqBeginA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProfileNameSyntax", "ProfileName", "InquiryType", "IfId", "VersOption", "MemberNameSyntax", "MemberName", "InquiryContext"]),
        #
        'RpcNsProfileEltInqNextA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext", "IfId", "MemberName", "Priority", "Annotation"]),
        #
        'RpcNsProfileDeleteW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProfileNameSyntax", "ProfileName"]),
        #
        'RpcNsProfileEltAddW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProfileNameSyntax", "ProfileName", "IfId", "MemberNameSyntax", "MemberName", "Priority", "Annotation"]),
        #
        'RpcNsProfileEltRemoveW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProfileNameSyntax", "ProfileName", "IfId", "MemberNameSyntax", "MemberName"]),
        #
        'RpcNsProfileEltInqBeginW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProfileNameSyntax", "ProfileName", "InquiryType", "IfId", "VersOption", "MemberNameSyntax", "MemberName", "InquiryContext"]),
        #
        'RpcNsProfileEltInqNextW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext", "IfId", "MemberName", "Priority", "Annotation"]),
        #
        'RpcNsProfileEltInqDone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext"]),
        #
        'RpcNsEntryObjectInqBeginA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "InquiryContext"]),
        #
        'RpcNsEntryObjectInqBeginW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "InquiryContext"]),
        #
        'RpcNsEntryObjectInqNext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext", "ObjUuid"]),
        #
        'RpcNsEntryObjectInqDone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext"]),
        #
        'RpcNsEntryExpandNameA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "ExpandedName"]),
        #
        'RpcNsMgmtBindingUnexportA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfId", "VersOption", "ObjectUuidVec"]),
        #
        'RpcNsMgmtEntryCreateA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName"]),
        #
        'RpcNsMgmtEntryDeleteA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName"]),
        #
        'RpcNsMgmtEntryInqIfIdsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RPC_IF_ID_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfIdVec"]),
        #
        'RpcNsMgmtHandleSetExpAge': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["NsHandle", "ExpirationAge"]),
        #
        'RpcNsMgmtInqExpAge': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ExpirationAge"]),
        #
        'RpcNsMgmtSetExpAge': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ExpirationAge"]),
        #
        'RpcNsEntryExpandNameW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "ExpandedName"]),
        #
        'RpcNsMgmtBindingUnexportW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfId", "VersOption", "ObjectUuidVec"]),
        #
        'RpcNsMgmtEntryCreateW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName"]),
        #
        'RpcNsMgmtEntryDeleteW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName"]),
        #
        'RpcNsMgmtEntryInqIfIdsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RPC_IF_ID_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfIdVec"]),
        #
        'RpcNsBindingImportBeginA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "ObjUuid", "ImportContext"]),
        #
        'RpcNsBindingImportBeginW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "IfSpec", "ObjUuid", "ImportContext"]),
        #
        'RpcNsBindingImportNext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ImportContext", "Binding"]),
        #
        'RpcNsBindingImportDone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ImportContext"]),
        #
        'RpcNsBindingSelect': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["BindingVec", "Binding"]),
        #
        'I_RpcNsGetBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message"]),
        #
        'I_RpcNsSendReceive': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message", "Handle"]),
        #
        'I_RpcNsRaiseException': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypeInt(signed=False, label="RPC_STATUS")], SimTypeBottom(label="Void"), arg_names=["Message", "Status"]),
        #
        'I_RpcReBindBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message"]),
    }

lib.set_prototypes(prototypes)
