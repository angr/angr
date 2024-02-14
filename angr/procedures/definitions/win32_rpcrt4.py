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
lib.set_library_names("rpcrt4.dll")
prototypes = \
    {
        #
        'IUnknown_QueryInterface_Proxy': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["This", "riid", "ppvObject"]),
        #
        'IUnknown_AddRef_Proxy': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=False, label="UInt32"), arg_names=["This"]),
        #
        'IUnknown_Release_Proxy': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=False, label="UInt32"), arg_names=["This"]),
        #
        'RpcBindingCopy': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["SourceBinding", "DestinationBinding"]),
        #
        'RpcBindingFree': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding"]),
        #
        'RpcBindingSetOption': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["hBinding", "option", "optionValue"]),
        #
        'RpcBindingInqOption': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["hBinding", "option", "pOptionValue"]),
        #
        'RpcBindingFromStringBindingA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["StringBinding", "Binding"]),
        #
        'RpcBindingFromStringBindingW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["StringBinding", "Binding"]),
        #
        'RpcSsGetContextBinding': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ContextHandle", "Binding"]),
        #
        'RpcBindingInqMaxCalls': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "MaxCalls"]),
        #
        'RpcBindingInqObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ObjectUuid"]),
        #
        'RpcBindingReset': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding"]),
        #
        'RpcBindingSetObject': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ObjectUuid"]),
        #
        'RpcMgmtInqDefaultProtectLevel': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["AuthnSvc", "AuthnLevel"]),
        #
        'RpcBindingToStringBindingA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "StringBinding"]),
        #
        'RpcBindingToStringBindingW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "StringBinding"]),
        #
        'RpcBindingVectorFree': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["BindingVector"]),
        #
        'RpcStringBindingComposeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ObjUuid", "ProtSeq", "NetworkAddr", "Endpoint", "Options", "StringBinding"]),
        #
        'RpcStringBindingComposeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ObjUuid", "ProtSeq", "NetworkAddr", "Endpoint", "Options", "StringBinding"]),
        #
        'RpcStringBindingParseA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["StringBinding", "ObjUuid", "Protseq", "NetworkAddr", "Endpoint", "NetworkOptions"]),
        #
        'RpcStringBindingParseW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["StringBinding", "ObjUuid", "Protseq", "NetworkAddr", "Endpoint", "NetworkOptions"]),
        #
        'RpcStringFreeA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["String"]),
        #
        'RpcStringFreeW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["String"]),
        #
        'RpcIfInqId': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["RpcIfHandle", "RpcIfId"]),
        #
        'RpcNetworkIsProtseqValidA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq"]),
        #
        'RpcNetworkIsProtseqValidW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq"]),
        #
        'RpcMgmtInqComTimeout': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "Timeout"]),
        #
        'RpcMgmtSetComTimeout': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "Timeout"]),
        #
        'RpcMgmtSetCancelTimeout': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Timeout"]),
        #
        'RpcNetworkInqProtseqsA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RPC_PROTSEQ_VECTORA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProtseqVector"]),
        #
        'RpcNetworkInqProtseqsW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RPC_PROTSEQ_VECTORW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProtseqVector"]),
        #
        'RpcObjectInqType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ObjUuid", "TypeUuid"]),
        #
        'RpcObjectSetInqFn': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="RPC_STATUS"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ObjectUuid", "TypeUuid", "Status"]), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryFn"]),
        #
        'RpcObjectSetType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ObjUuid", "TypeUuid"]),
        #
        'RpcProtseqVectorFreeA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RPC_PROTSEQ_VECTORA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProtseqVector"]),
        #
        'RpcProtseqVectorFreeW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RPC_PROTSEQ_VECTORW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ProtseqVector"]),
        #
        'RpcServerInqBindings': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["BindingVector"]),
        #
        'RpcServerInqBindingsEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["SecurityDescriptor", "BindingVector"]),
        #
        'RpcServerInqIf': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "MgrTypeUuid", "MgrEpv"]),
        #
        'RpcServerListen': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["MinimumCallThreads", "MaxCalls", "DontWait"]),
        #
        'RpcServerRegisterIf': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "MgrTypeUuid", "MgrEpv"]),
        #
        'RpcServerRegisterIfEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InterfaceUuid", "Context"]), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "MgrTypeUuid", "MgrEpv", "Flags", "MaxCalls", "IfCallback"]),
        #
        'RpcServerRegisterIf2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InterfaceUuid", "Context"]), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "MgrTypeUuid", "MgrEpv", "Flags", "MaxCalls", "MaxRpcSize", "IfCallbackFn"]),
        #
        'RpcServerRegisterIf3': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InterfaceUuid", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "MgrTypeUuid", "MgrEpv", "Flags", "MaxCalls", "MaxRpcSize", "IfCallback", "SecurityDescriptor"]),
        #
        'RpcServerUnregisterIf': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "MgrTypeUuid", "WaitForCallsToComplete"]),
        #
        'RpcServerUnregisterIfEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "MgrTypeUuid", "RundownContextHandles"]),
        #
        'RpcServerUseAllProtseqs': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["MaxCalls", "SecurityDescriptor"]),
        #
        'RpcServerUseAllProtseqsEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["MaxCalls", "SecurityDescriptor", "Policy"]),
        #
        'RpcServerUseAllProtseqsIf': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["MaxCalls", "IfSpec", "SecurityDescriptor"]),
        #
        'RpcServerUseAllProtseqsIfEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["MaxCalls", "IfSpec", "SecurityDescriptor", "Policy"]),
        #
        'RpcServerUseProtseqA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "SecurityDescriptor"]),
        #
        'RpcServerUseProtseqExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "SecurityDescriptor", "Policy"]),
        #
        'RpcServerUseProtseqW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "SecurityDescriptor"]),
        #
        'RpcServerUseProtseqExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "SecurityDescriptor", "Policy"]),
        #
        'RpcServerUseProtseqEpA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "Endpoint", "SecurityDescriptor"]),
        #
        'RpcServerUseProtseqEpExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "Endpoint", "SecurityDescriptor", "Policy"]),
        #
        'RpcServerUseProtseqEpW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "Endpoint", "SecurityDescriptor"]),
        #
        'RpcServerUseProtseqEpExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "Endpoint", "SecurityDescriptor", "Policy"]),
        #
        'RpcServerUseProtseqIfA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "IfSpec", "SecurityDescriptor"]),
        #
        'RpcServerUseProtseqIfExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "IfSpec", "SecurityDescriptor", "Policy"]),
        #
        'RpcServerUseProtseqIfW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "IfSpec", "SecurityDescriptor"]),
        #
        'RpcServerUseProtseqIfExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "MaxCalls", "IfSpec", "SecurityDescriptor", "Policy"]),
        #
        'RpcServerYield': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'RpcMgmtStatsVectorFree': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("RPC_STATS_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["StatsVector"]),
        #
        'RpcMgmtInqStats': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RPC_STATS_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "Statistics"]),
        #
        'RpcMgmtIsServerListening': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding"]),
        #
        'RpcMgmtStopServerListening': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding"]),
        #
        'RpcMgmtWaitServerListen': SimTypeFunction([], SimTypeInt(signed=False, label="RPC_STATUS")),
        #
        'RpcMgmtSetServerStackSize': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ThreadStackSize"]),
        #
        'RpcSsDontSerializeContext': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'RpcMgmtEnableIdleCleanup': SimTypeFunction([], SimTypeInt(signed=False, label="RPC_STATUS")),
        #
        'RpcMgmtInqIfIds': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RPC_IF_ID_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "IfIdVector"]),
        #
        'RpcMgmtInqServerPrincNameA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "AuthnSvc", "ServerPrincName"]),
        #
        'RpcMgmtInqServerPrincNameW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "AuthnSvc", "ServerPrincName"]),
        #
        'RpcServerInqDefaultPrincNameA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["AuthnSvc", "PrincName"]),
        #
        'RpcServerInqDefaultPrincNameW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["AuthnSvc", "PrincName"]),
        #
        'RpcEpResolveBinding': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "IfSpec"]),
        #
        'RpcNsBindingInqEntryNameA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "EntryNameSyntax", "EntryName"]),
        #
        'RpcNsBindingInqEntryNameW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "EntryNameSyntax", "EntryName"]),
        #
        'RpcBindingCreateA': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_BINDING_HANDLE_TEMPLATE_V1_A", SimStruct), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_HANDLE_SECURITY_V1_A", SimStruct), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_HANDLE_OPTIONS_V1", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Template", "Security", "Options", "Binding"]),
        #
        'RpcBindingCreateW': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_BINDING_HANDLE_TEMPLATE_V1_W", SimStruct), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_HANDLE_SECURITY_V1_W", SimStruct), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_HANDLE_OPTIONS_V1", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Template", "Security", "Options", "Binding"]),
        #
        'RpcServerInqBindingHandle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding"]),
        #
        'RpcImpersonateClient': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["BindingHandle"]),
        #
        'RpcImpersonateClient2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["BindingHandle"]),
        #
        'RpcRevertToSelfEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["BindingHandle"]),
        #
        'RpcRevertToSelf': SimTypeFunction([], SimTypeInt(signed=False, label="RPC_STATUS")),
        #
        'RpcImpersonateClientContainer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["BindingHandle"]),
        #
        'RpcRevertContainerImpersonation': SimTypeFunction([], SimTypeInt(signed=False, label="RPC_STATUS")),
        #
        'RpcBindingInqAuthClientA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ClientBinding", "Privs", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthzSvc"]),
        #
        'RpcBindingInqAuthClientW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ClientBinding", "Privs", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthzSvc"]),
        #
        'RpcBindingInqAuthClientExA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ClientBinding", "Privs", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthzSvc", "Flags"]),
        #
        'RpcBindingInqAuthClientExW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ClientBinding", "Privs", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthzSvc", "Flags"]),
        #
        'RpcBindingInqAuthInfoA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthIdentity", "AuthzSvc"]),
        #
        'RpcBindingInqAuthInfoW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthIdentity", "AuthzSvc"]),
        #
        'RpcBindingSetAuthInfoA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthIdentity", "AuthzSvc"]),
        #
        'RpcBindingSetAuthInfoExA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RPC_SECURITY_QOS", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthIdentity", "AuthzSvc", "SecurityQos"]),
        #
        'RpcBindingSetAuthInfoW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthIdentity", "AuthzSvc"]),
        #
        'RpcBindingSetAuthInfoExW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RPC_SECURITY_QOS", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthIdentity", "AuthzSvc", "SecurityQOS"]),
        #
        'RpcBindingInqAuthInfoExA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RPC_SECURITY_QOS", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthIdentity", "AuthzSvc", "RpcQosVersion", "SecurityQOS"]),
        #
        'RpcBindingInqAuthInfoExW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RPC_SECURITY_QOS", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ServerPrincName", "AuthnLevel", "AuthnSvc", "AuthIdentity", "AuthzSvc", "RpcQosVersion", "SecurityQOS"]),
        #
        'RpcServerCompleteSecurityCallback': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="RPC_STATUS")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["BindingHandle", "Status"]),
        #
        'RpcServerRegisterAuthInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="RPC_STATUS"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Arg", "ServerPrincName", "KeyVer", "Key", "Status"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ServerPrincName", "AuthnSvc", "GetKeyFn", "Arg"]),
        #
        'RpcServerRegisterAuthInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="RPC_STATUS"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Arg", "ServerPrincName", "KeyVer", "Key", "Status"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ServerPrincName", "AuthnSvc", "GetKeyFn", "Arg"]),
        #
        'RpcBindingServerFromClient': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ClientBinding", "ServerBinding"]),
        #
        'RpcRaiseException': SimTypeFunction([SimTypeInt(signed=False, label="RPC_STATUS")], SimTypeBottom(label="Void"), arg_names=["exception"]),
        #
        'RpcTestCancel': SimTypeFunction([], SimTypeInt(signed=False, label="RPC_STATUS")),
        #
        'RpcServerTestCancel': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["BindingHandle"]),
        #
        'RpcCancelThread': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Thread"]),
        #
        'RpcCancelThreadEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Thread", "Timeout"]),
        #
        'UuidCreate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Uuid"]),
        #
        'UuidCreateSequential': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Uuid"]),
        #
        'UuidToStringA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Uuid", "StringUuid"]),
        #
        'UuidFromStringA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["StringUuid", "Uuid"]),
        #
        'UuidToStringW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Uuid", "StringUuid"]),
        #
        'UuidFromStringW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["StringUuid", "Uuid"]),
        #
        'UuidCompare': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="RPC_STATUS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Uuid1", "Uuid2", "Status"]),
        #
        'UuidCreateNil': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["NilUuid"]),
        #
        'UuidEqual': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="RPC_STATUS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Uuid1", "Uuid2", "Status"]),
        #
        'UuidHash': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="RPC_STATUS"), offset=0)], SimTypeShort(signed=False, label="UInt16"), arg_names=["Uuid", "Status"]),
        #
        'UuidIsNil': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="RPC_STATUS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Uuid", "Status"]),
        #
        'RpcEpRegisterNoReplaceA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "BindingVector", "UuidVector", "Annotation"]),
        #
        'RpcEpRegisterNoReplaceW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "BindingVector", "UuidVector", "Annotation"]),
        #
        'RpcEpRegisterA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "BindingVector", "UuidVector", "Annotation"]),
        #
        'RpcEpRegisterW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "BindingVector", "UuidVector", "Annotation"]),
        #
        'RpcEpUnregister': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), SimTypePointer(SimTypeRef("UUID_VECTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfSpec", "BindingVector", "UuidVector"]),
        #
        'DceErrorInqTextA': SimTypeFunction([SimTypeInt(signed=False, label="RPC_STATUS"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["RpcStatus", "ErrorText"]),
        #
        'DceErrorInqTextW': SimTypeFunction([SimTypeInt(signed=False, label="RPC_STATUS"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["RpcStatus", "ErrorText"]),
        #
        'RpcMgmtEpEltInqBegin': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EpBinding", "InquiryType", "IfId", "VersOption", "ObjectUuid", "InquiryContext"]),
        #
        'RpcMgmtEpEltInqDone': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext"]),
        #
        'RpcMgmtEpEltInqNextA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext", "IfId", "Binding", "ObjectUuid", "Annotation"]),
        #
        'RpcMgmtEpEltInqNextW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InquiryContext", "IfId", "Binding", "ObjectUuid", "Annotation"]),
        #
        'RpcMgmtEpUnregister': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_IF_ID", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EpBinding", "IfId", "Binding", "ObjectUuid"]),
        #
        'RpcMgmtSetAuthorizationFn': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="RPC_STATUS"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ClientBinding", "RequestedMgmtOperation", "Status"]), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["AuthorizationFn"]),
        #
        'RpcExceptionFilter': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ExceptionCode"]),
        #
        'RpcServerInterfaceGroupCreateW': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_INTERFACE_TEMPLATEW", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RPC_ENDPOINT_TEMPLATEW", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["IfGroup", "IdleCallbackContext", "IsGroupIdle"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Interfaces", "NumIfs", "Endpoints", "NumEndpoints", "IdlePeriod", "IdleCallbackFn", "IdleCallbackContext", "IfGroup"]),
        #
        'RpcServerInterfaceGroupCreateA': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_INTERFACE_TEMPLATEA", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RPC_ENDPOINT_TEMPLATEA", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["IfGroup", "IdleCallbackContext", "IsGroupIdle"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Interfaces", "NumIfs", "Endpoints", "NumEndpoints", "IdlePeriod", "IdleCallbackFn", "IdleCallbackContext", "IfGroup"]),
        #
        'RpcServerInterfaceGroupClose': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfGroup"]),
        #
        'RpcServerInterfaceGroupActivate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfGroup"]),
        #
        'RpcServerInterfaceGroupDeactivate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfGroup", "ForceDeactivation"]),
        #
        'RpcServerInterfaceGroupInqBindings': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("RPC_BINDING_VECTOR", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["IfGroup", "BindingVector"]),
        #
        'I_RpcNegotiateTransferSyntax': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message"]),
        #
        'I_RpcGetBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message"]),
        #
        'I_RpcGetBufferWithObject': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message", "ObjectUuid"]),
        #
        'I_RpcSendReceive': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message"]),
        #
        'I_RpcFreeBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message"]),
        #
        'I_RpcSend': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message"]),
        #
        'I_RpcReceive': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message", "Size"]),
        #
        'I_RpcFreePipeBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message"]),
        #
        'I_RpcReallocPipeBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message", "NewSize"]),
        #
        'I_RpcRequestMutex': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mutex"]),
        #
        'I_RpcClearMutex': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mutex"]),
        #
        'I_RpcDeleteMutex': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Mutex"]),
        #
        'I_RpcAllocate': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]),
        #
        'I_RpcFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Object"]),
        #
        'I_RpcPauseExecution': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["Milliseconds"]),
        #
        'I_RpcGetExtendedError': SimTypeFunction([], SimTypeInt(signed=False, label="RPC_STATUS")),
        #
        'I_RpcSystemHandleTypeSpecificWork': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="LRPC_SYSTEM_HANDLE_MARSHAL_DIRECTION")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Handle", "ActualType", "IdlType", "MarshalDirection"]),
        #
        'I_RpcGetCurrentCallHandle': SimTypeFunction([], SimTypePointer(SimTypeBottom(label="Void"), offset=0)),
        #
        'I_RpcNsInterfaceExported': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeRef("RPC_SERVER_INTERFACE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "RpcInterfaceInformation"]),
        #
        'I_RpcNsInterfaceUnexported': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeRef("RPC_SERVER_INTERFACE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EntryNameSyntax", "EntryName", "RpcInterfaceInformation"]),
        #
        'I_RpcBindingToStaticStringBindingW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "StringBinding"]),
        #
        'I_RpcBindingInqSecurityContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "SecurityContextHandle"]),
        #
        'I_RpcBindingInqSecurityContextKeyInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "KeyInfo"]),
        #
        'I_RpcBindingInqWireIdForSnego': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "WireId"]),
        #
        'I_RpcBindingInqMarshalledTargetInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "MarshalledTargetInfoSize", "MarshalledTargetInfo"]),
        #
        'I_RpcBindingInqLocalClientPID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "Pid"]),
        #
        'I_RpcBindingHandleToAsyncHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "AsyncHandle"]),
        #
        'I_RpcNsBindingSetEntryNameW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "EntryNameSyntax", "EntryName"]),
        #
        'I_RpcNsBindingSetEntryNameA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "EntryNameSyntax", "EntryName"]),
        #
        'I_RpcServerUseProtseqEp2A': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["NetworkAddress", "Protseq", "MaxCalls", "Endpoint", "SecurityDescriptor", "Policy"]),
        #
        'I_RpcServerUseProtseqEp2W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["NetworkAddress", "Protseq", "MaxCalls", "Endpoint", "SecurityDescriptor", "Policy"]),
        #
        'I_RpcServerUseProtseq2W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["NetworkAddress", "Protseq", "MaxCalls", "SecurityDescriptor", "Policy"]),
        #
        'I_RpcServerUseProtseq2A': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["NetworkAddress", "Protseq", "MaxCalls", "SecurityDescriptor", "Policy"]),
        #
        'I_RpcServerStartService': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Protseq", "Endpoint", "IfSpec"]),
        #
        'I_RpcBindingInqDynamicEndpointW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "DynamicEndpoint"]),
        #
        'I_RpcBindingInqDynamicEndpointA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "DynamicEndpoint"]),
        #
        'I_RpcServerCheckClientRestriction': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Context"]),
        #
        'I_RpcBindingInqTransportType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "Type"]),
        #
        'I_RpcIfInqTransferSyntaxes': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_TRANSFER_SYNTAX", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["RpcIfHandle", "TransferSyntaxes", "TransferSyntaxSize", "TransferSyntaxCount"]),
        #
        'I_UuidCreate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Uuid"]),
        #
        'I_RpcBindingCopy': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["SourceBinding", "DestinationBinding"]),
        #
        'I_RpcBindingIsClientLocal': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["BindingHandle", "ClientLocalFlag"]),
        #
        'I_RpcBindingCreateNP': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ServerName", "ServiceName", "NetworkOptions", "Binding"]),
        #
        'I_RpcSsDontSerializeContext': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'I_RpcServerRegisterForwardFunction': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("RPC_VERSION", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["InterfaceId", "InterfaceVersion", "ObjectId", "Rpcpro", "ppDestEndpoint"]), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pForwardFunction"]),
        #
        'I_RpcServerInqAddressChangeFn': SimTypeFunction([], SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["arg"]), offset=0), offset=0)),
        #
        'I_RpcServerSetAddressChangeFn': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["arg"]), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pAddressChangeFn"]),
        #
        'I_RpcServerInqLocalConnAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "Buffer", "BufferSize", "AddressFormat"]),
        #
        'I_RpcServerInqRemoteConnAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "Buffer", "BufferSize", "AddressFormat"]),
        #
        'I_RpcSessionStrictContextHandle': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'I_RpcTurnOnEEInfoPropagation': SimTypeFunction([], SimTypeInt(signed=False, label="RPC_STATUS")),
        #
        'I_RpcServerInqTransportType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Type"]),
        #
        'I_RpcMapWin32Status': SimTypeFunction([SimTypeInt(signed=False, label="RPC_STATUS")], SimTypeInt(signed=True, label="Int32"), arg_names=["Status"]),
        #
        'I_RpcRecordCalloutFailure': SimTypeFunction([SimTypeInt(signed=False, label="RPC_STATUS"), SimTypePointer(SimTypeRef("RDR_CALLOUT_STATE", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeBottom(label="Void"), arg_names=["RpcStatus", "CallOutState", "DllName"]),
        #
        'I_RpcMgmtEnableDedicatedThreadPool': SimTypeFunction([], SimTypeInt(signed=False, label="RPC_STATUS")),
        #
        'I_RpcGetDefaultSD': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ppSecurityDescriptor"]),
        #
        'I_RpcOpenClientProcess': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "DesiredAccess", "ClientProcess"]),
        #
        'I_RpcBindingIsServerLocal': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "ServerLocalFlag"]),
        #
        'I_RpcBindingSetPrivateOption': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["hBinding", "option", "optionValue"]),
        #
        'I_RpcServerSubscribeForDisconnectNotification': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "hEvent"]),
        #
        'I_RpcServerGetAssociationID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "AssociationID"]),
        #
        'I_RpcServerDisableExceptionFilter': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'I_RpcServerSubscribeForDisconnectNotification2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "hEvent", "SubscriptionId"]),
        #
        'I_RpcServerUnsubscribeForDisconnectNotification': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="Guid")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "SubscriptionId"]),
        #
        'RpcAsyncRegisterInfo': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ASYNC_STATE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pAsync"]),
        #
        'RpcAsyncInitializeHandle': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ASYNC_STATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pAsync", "Size"]),
        #
        'RpcAsyncGetCallStatus': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ASYNC_STATE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pAsync"]),
        #
        'RpcAsyncCompleteCall': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ASYNC_STATE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pAsync", "Reply"]),
        #
        'RpcAsyncAbortCall': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ASYNC_STATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pAsync", "ExceptionCode"]),
        #
        'RpcAsyncCancelCall': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ASYNC_STATE", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pAsync", "fAbort"]),
        #
        'RpcErrorStartEnumeration': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ERROR_ENUM_HANDLE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EnumHandle"]),
        #
        'RpcErrorGetNextRecord': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ERROR_ENUM_HANDLE", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("RPC_EXTENDED_ERROR_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EnumHandle", "CopyStrings", "ErrorInfo"]),
        #
        'RpcErrorEndEnumeration': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ERROR_ENUM_HANDLE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EnumHandle"]),
        #
        'RpcErrorResetEnumeration': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ERROR_ENUM_HANDLE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EnumHandle"]),
        #
        'RpcErrorGetNumberOfRecords': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ERROR_ENUM_HANDLE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EnumHandle", "Records"]),
        #
        'RpcErrorSaveErrorInfo': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ERROR_ENUM_HANDLE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["EnumHandle", "ErrorBlob", "BlobSize"]),
        #
        'RpcErrorLoadErrorInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("RPC_ERROR_ENUM_HANDLE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ErrorBlob", "BlobSize", "EnumHandle"]),
        #
        'RpcErrorAddRecord': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_EXTENDED_ERROR_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ErrorInfo"]),
        #
        'RpcErrorClearInformation': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'RpcGetAuthorizationContextForClient': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypeRef("LUID", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ClientBinding", "ImpersonateOnReturn", "Reserved1", "pExpirationTime", "Reserved2", "Reserved3", "Reserved4", "pAuthzClientContext"]),
        #
        'RpcFreeAuthorizationContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pAuthzClientContext"]),
        #
        'RpcSsContextLockExclusive': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ServerBindingHandle", "UserContext"]),
        #
        'RpcSsContextLockShared': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ServerBindingHandle", "UserContext"]),
        #
        'RpcServerInqCallAttributesW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ClientBinding", "RpcCallAttributes"]),
        #
        'RpcServerInqCallAttributesA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ClientBinding", "RpcCallAttributes"]),
        #
        'RpcServerSubscribeForNotification': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="RPC_NOTIFICATIONS"), SimTypeInt(signed=False, label="RPC_NOTIFICATION_TYPES"), SimTypePointer(SimUnion({"APC": SimTypeRef("_APC_e__Struct", SimStruct), "IOC": SimTypeRef("_IOC_e__Struct", SimStruct), "IntPtr": SimTypeRef("_IntPtr_e__Struct", SimStruct), "hEvent": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "NotificationRoutine": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ASYNC_STATE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="RPC_ASYNC_EVENT")], SimTypeBottom(label="Void"), arg_names=["pAsync", "Context", "Event"]), offset=0)}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "Notification", "NotificationType", "NotificationInfo"]),
        #
        'RpcServerUnsubscribeForNotification': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="RPC_NOTIFICATIONS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "Notification", "NotificationsQueued"]),
        #
        'RpcBindingBind': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ASYNC_STATE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pAsync", "Binding", "IfSpec"]),
        #
        'RpcBindingUnbind': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding"]),
        #
        'I_RpcAsyncSetHandle': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RPC_ASYNC_STATE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Message", "pAsync"]),
        #
        'I_RpcAsyncAbortCall': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_ASYNC_STATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pAsync", "ExceptionCode"]),
        #
        'I_RpcExceptionFilter': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ExceptionCode"]),
        #
        'I_RpcBindingInqClientTokenAttributes': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0), SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0), SimTypePointer(SimTypeRef("LUID", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Binding", "TokenId", "AuthenticationId", "ModifiedId"]),
        #
        'NDRCContextBinding': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["CContext"]),
        #
        'NDRCContextMarshall': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CContext", "pBuff"]),
        #
        'NDRCContextUnmarshall': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pCContext", "hBinding", "pBuff", "DataRepresentation"]),
        #
        'NDRSContextMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["CContext", "pBuff", "userRunDownIn"]),
        #
        'NDRSContextUnmarshall': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), arg_names=["pBuff", "DataRepresentation"]),
        #
        'NDRSContextMarshallEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["BindingHandle", "CContext", "pBuff", "userRunDownIn"]),
        #
        'NDRSContextMarshall2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["BindingHandle", "CContext", "pBuff", "userRunDownIn", "CtxGuard", "Flags"]),
        #
        'NDRSContextUnmarshallEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), arg_names=["BindingHandle", "pBuff", "DataRepresentation"]),
        #
        'NDRSContextUnmarshall2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), arg_names=["BindingHandle", "pBuff", "DataRepresentation", "CtxGuard", "Flags"]),
        #
        'RpcSsDestroyClientContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["ContextHandle"]),
        #
        'NdrSimpleTypeMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "FormatChar"]),
        #
        'NdrPointerMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrSimpleStructMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantStructMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantVaryingStructMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrComplexStructMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrFixedArrayMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantArrayMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantVaryingArrayMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrVaryingArrayMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrComplexArrayMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrNonConformantStringMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantStringMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrEncapsulatedUnionMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrNonEncapsulatedUnionMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrByteCountPointerMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrXmitOrRepAsMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrUserMarshalMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrInterfacePointerMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrClientContextMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "ContextHandle", "fCheck"]),
        #
        'NdrServerContextMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "ContextHandle", "RundownRoutine"]),
        #
        'NdrServerContextNewMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "ContextHandle", "RundownRoutine", "pFormat"]),
        #
        'NdrSimpleTypeUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "FormatChar"]),
        #
        'NdrRangeUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrCorrelationInitialize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "CacheSize", "flags"]),
        #
        'NdrCorrelationPass': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg"]),
        #
        'NdrCorrelationFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg"]),
        #
        'NdrPointerUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrSimpleStructUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrConformantStructUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrConformantVaryingStructUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrComplexStructUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrFixedArrayUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrConformantArrayUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrConformantVaryingArrayUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrVaryingArrayUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrComplexArrayUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrNonConformantStringUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrConformantStringUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrEncapsulatedUnionUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrNonEncapsulatedUnionUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrByteCountPointerUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrXmitOrRepAsUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrUserMarshalUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrInterfacePointerUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "ppMemory", "pFormat", "fMustAlloc"]),
        #
        'NdrClientContextUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pContextHandle", "BindHandle"]),
        #
        'NdrServerContextUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0)], SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), arg_names=["pStubMsg"]),
        #
        'NdrContextHandleInitialize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrServerContextNewUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("NDR_SCONTEXT", SimStruct), offset=0), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrPointerBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrSimpleStructBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantStructBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantVaryingStructBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrComplexStructBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrFixedArrayBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantArrayBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantVaryingArrayBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrVaryingArrayBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrComplexArrayBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantStringBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrNonConformantStringBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrEncapsulatedUnionBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrNonEncapsulatedUnionBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrByteCountPointerBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrXmitOrRepAsBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrUserMarshalBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrInterfacePointerBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrContextHandleSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrPointerMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrSimpleStructMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrConformantStructMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrConformantVaryingStructMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrComplexStructMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrFixedArrayMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrConformantArrayMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrConformantVaryingArrayMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrVaryingArrayMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrComplexArrayMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrConformantStringMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrNonConformantStringMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrEncapsulatedUnionMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrNonEncapsulatedUnionMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrXmitOrRepAsMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrUserMarshalMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrInterfacePointerMemorySize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrPointerFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrSimpleStructFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantStructFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantVaryingStructFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrComplexStructFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrFixedArrayFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantArrayFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConformantVaryingArrayFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrVaryingArrayFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrComplexArrayFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrEncapsulatedUnionFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrNonEncapsulatedUnionFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrByteCountPointerFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrXmitOrRepAsFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrUserMarshalFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrInterfacePointerFree': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory", "pFormat"]),
        #
        'NdrConvert2': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pFormat", "NumberParams"]),
        #
        'NdrConvert': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pFormat"]),
        #
        'NdrUserMarshalSimpleTypeConvert': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeChar(label="Byte")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pFlags", "pBuffer", "FormatChar"]),
        #
        'NdrClientInitializeNew': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pRpcMsg", "pStubMsg", "pStubDescriptor", "ProcNum"]),
        #
        'NdrServerInitializeNew': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pRpcMsg", "pStubMsg", "pStubDescriptor"]),
        #
        'NdrServerInitializePartial': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pRpcMsg", "pStubMsg", "pStubDescriptor", "RequestedBufferSize"]),
        #
        'NdrClientInitialize': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["pRpcMsg", "pStubMsg", "pStubDescriptor", "ProcNum"]),
        #
        'NdrServerInitialize': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pRpcMsg", "pStubMsg", "pStubDescriptor"]),
        #
        'NdrServerInitializeUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pStubDescriptor", "pRpcMsg"]),
        #
        'NdrServerInitializeMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pRpcMsg", "pStubMsg"]),
        #
        'NdrGetBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "BufferLength", "Handle"]),
        #
        'NdrNsGetBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "BufferLength", "Handle"]),
        #
        'NdrSendReceive': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pBufferEnd"]),
        #
        'NdrNsSendReceive': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pStubMsg", "pBufferEnd", "pAutoHandle"]),
        #
        'NdrFreeBuffer': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg"]),
        #
        'NdrGetDcomProtocolVersion': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeRef("RPC_VERSION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStubMsg", "pVersion"]),
        #
        'NdrClientCall2': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimUnion({"Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Simple": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="<anon>", label="None"), arg_names=["pStubDescriptor", "pFormat"]),
        #
        'NdrAsyncClientCall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimUnion({"Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Simple": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="<anon>", label="None"), arg_names=["pStubDescriptor", "pFormat"]),
        #
        'NdrDcomAsyncClientCall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimUnion({"Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Simple": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="<anon>", label="None"), arg_names=["pStubDescriptor", "pFormat"]),
        #
        'NdrAsyncServerCall': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pRpcMsg"]),
        #
        'NdrDcomAsyncStubCall': SimTypeFunction([SimTypeBottom(label="IRpcStubBuffer"), SimTypeBottom(label="IRpcChannelBuffer"), SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pThis", "pChannel", "pRpcMsg", "pdwStubPhase"]),
        #
        'NdrStubCall2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pThis", "pChannel", "pRpcMsg", "pdwStubPhase"]),
        #
        'NdrServerCall2': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pRpcMsg"]),
        #
        'NdrMapCommAndFaultStatus': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="RPC_STATUS")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pStubMsg", "pCommStatus", "pFaultStatus", "Status"]),
        #
        'RpcSsAllocate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]),
        #
        'RpcSsDisableAllocate': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'RpcSsEnableAllocate': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'RpcSsFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NodeToFree"]),
        #
        'RpcSsGetThreadHandle': SimTypeFunction([], SimTypePointer(SimTypeBottom(label="Void"), offset=0)),
        #
        'RpcSsSetClientAllocFree': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Ptr"]), offset=0)], SimTypeBottom(label="Void"), arg_names=["ClientAlloc", "ClientFree"]),
        #
        'RpcSsSetThreadHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Id"]),
        #
        'RpcSsSwapClientAllocFree': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Ptr"]), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Ptr"]), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["ClientAlloc", "ClientFree", "OldClientAlloc", "OldClientFree"]),
        #
        'RpcSmAllocate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="RPC_STATUS"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size", "pStatus"]),
        #
        'RpcSmClientFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pNodeToFree"]),
        #
        'RpcSmDestroyClientContext': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ContextHandle"]),
        #
        'RpcSmDisableAllocate': SimTypeFunction([], SimTypeInt(signed=False, label="RPC_STATUS")),
        #
        'RpcSmEnableAllocate': SimTypeFunction([], SimTypeInt(signed=False, label="RPC_STATUS")),
        #
        'RpcSmFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["NodeToFree"]),
        #
        'RpcSmGetThreadHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="RPC_STATUS"), offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pStatus"]),
        #
        'RpcSmSetClientAllocFree': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Ptr"]), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ClientAlloc", "ClientFree"]),
        #
        'RpcSmSetThreadHandle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Id"]),
        #
        'RpcSmSwapClientAllocFree': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Ptr"]), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Ptr"]), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["ClientAlloc", "ClientFree", "OldClientAlloc", "OldClientFree"]),
        #
        'NdrRpcSsEnableAllocate': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pMessage"]),
        #
        'NdrRpcSsDisableAllocate': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pMessage"]),
        #
        'NdrRpcSmSetClientToOsf': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pMessage"]),
        #
        'NdrRpcSmClientAllocate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]),
        #
        'NdrRpcSmClientFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NodeToFree"]),
        #
        'NdrRpcSsDefaultAllocate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]),
        #
        'NdrRpcSsDefaultFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NodeToFree"]),
        #
        'NdrFullPointerXlatInit': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="XLAT_SIDE")], SimTypePointer(SimTypeRef("FULL_PTR_XLAT_TABLES", SimStruct), offset=0), arg_names=["NumberOfPointers", "XlatSide"]),
        #
        'NdrFullPointerXlatFree': SimTypeFunction([SimTypePointer(SimTypeRef("FULL_PTR_XLAT_TABLES", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pXlatTables"]),
        #
        'NdrAllocate': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pStubMsg", "Len"]),
        #
        'NdrClearOutParameters': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pFormat", "ArgAddr"]),
        #
        'NdrOleAllocate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["Size"]),
        #
        'NdrOleFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["NodeToFree"]),
        #
        'NdrGetUserMarshalInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("NDR_USER_MARSHAL_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pFlags", "InformationLevel", "pMarshalInfo"]),
        #
        'NdrCreateServerInterfaceFromStub': SimTypeFunction([SimTypeBottom(label="IRpcStubBuffer"), SimTypePointer(SimTypeRef("RPC_SERVER_INTERFACE", SimStruct), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pStub", "pServerIf"]),
        #
        'NdrClientCall3': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimUnion({"Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Simple": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="<anon>", label="None"), arg_names=["pProxyInfo", "nProcNum", "pReturnValue"]),
        #
        'Ndr64AsyncClientCall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimUnion({"Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Simple": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="<anon>", label="None"), arg_names=["pProxyInfo", "nProcNum", "pReturnValue"]),
        #
        'Ndr64DcomAsyncClientCall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimUnion({"Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Simple": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="<anon>", label="None"), arg_names=["pProxyInfo", "nProcNum", "pReturnValue"]),
        #
        'Ndr64AsyncServerCall64': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pRpcMsg"]),
        #
        'Ndr64AsyncServerCallAll': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pRpcMsg"]),
        #
        'Ndr64DcomAsyncStubCall': SimTypeFunction([SimTypeBottom(label="IRpcStubBuffer"), SimTypeBottom(label="IRpcChannelBuffer"), SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pThis", "pChannel", "pRpcMsg", "pdwStubPhase"]),
        #
        'NdrStubCall3': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pThis", "pChannel", "pRpcMsg", "pdwStubPhase"]),
        #
        'NdrServerCallAll': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pRpcMsg"]),
        #
        'NdrServerCallNdr64': SimTypeFunction([SimTypePointer(SimTypeRef("RPC_MESSAGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pRpcMsg"]),
        #
        'NdrPartialIgnoreClientMarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory"]),
        #
        'NdrPartialIgnoreServerUnmarshall': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "ppMemory"]),
        #
        'NdrPartialIgnoreClientBufferSize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "pMemory"]),
        #
        'NdrPartialIgnoreServerInitialize': SimTypeFunction([SimTypePointer(SimTypeRef("MIDL_STUB_MESSAGE", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pStubMsg", "ppMemory", "pFormat"]),
        #
        'RpcUserFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["AsyncHandle", "pBuffer"]),
        #
        'MesEncodeIncrementalHandleCreate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["state", "pbuffer", "psize"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["state", "buffer", "size"]), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["UserState", "AllocFn", "WriteFn", "pHandle"]),
        #
        'MesDecodeIncrementalHandleCreate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["state", "pbuffer", "psize"]), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["UserState", "ReadFn", "pHandle"]),
        #
        'MesIncrementalHandleReset': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["state", "pbuffer", "psize"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["state", "buffer", "size"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["state", "pbuffer", "psize"]), offset=0), SimTypeInt(signed=False, label="MIDL_ES_CODE")], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Handle", "UserState", "AllocFn", "WriteFn", "ReadFn", "Operation"]),
        #
        'MesEncodeFixedBufferHandleCreate': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pBuffer", "BufferSize", "pEncodedSize", "pHandle"]),
        #
        'MesEncodeDynBufferHandleCreate': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["pBuffer", "pEncodedSize", "pHandle"]),
        #
        'MesDecodeBufferHandleCreate': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Buffer", "BufferSize", "pHandle"]),
        #
        'MesBufferHandleReset': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MIDL_ES_CODE"), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Handle", "HandleStyle", "Operation", "pBuffer", "BufferSize", "pEncodedSize"]),
        #
        'MesHandleFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Handle"]),
        #
        'MesInqProcEncodingId': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("RPC_SYNTAX_IDENTIFIER", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Handle", "pInterfaceId", "pProcNum"]),
        #
        'NdrMesSimpleTypeAlignSize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["param0"]),
        #
        'NdrMesSimpleTypeDecode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["Handle", "pObject", "Size"]),
        #
        'NdrMesSimpleTypeEncode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["Handle", "pStubDesc", "pObject", "Size"]),
        #
        'NdrMesTypeAlignSize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["Handle", "pStubDesc", "pFormatString", "pObject"]),
        #
        'NdrMesTypeEncode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "pStubDesc", "pFormatString", "pObject"]),
        #
        'NdrMesTypeDecode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "pStubDesc", "pFormatString", "pObject"]),
        #
        'NdrMesTypeAlignSize2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_TYPE_PICKLING_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["Handle", "pPicklingInfo", "pStubDesc", "pFormatString", "pObject"]),
        #
        'NdrMesTypeEncode2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_TYPE_PICKLING_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "pPicklingInfo", "pStubDesc", "pFormatString", "pObject"]),
        #
        'NdrMesTypeDecode2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_TYPE_PICKLING_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "pPicklingInfo", "pStubDesc", "pFormatString", "pObject"]),
        #
        'NdrMesTypeFree2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_TYPE_PICKLING_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "pPicklingInfo", "pStubDesc", "pFormatString", "pObject"]),
        #
        'NdrMesProcEncodeDecode': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "pStubDesc", "pFormatString"]),
        #
        'NdrMesProcEncodeDecode2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_STUB_DESC", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimUnion({"Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Simple": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="<anon>", label="None"), arg_names=["Handle", "pStubDesc", "pFormatString"]),
        #
        'NdrMesTypeAlignSize3': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_TYPE_PICKLING_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["Handle", "pPicklingInfo", "pProxyInfo", "ArrTypeOffset", "nTypeIndex", "pObject"]),
        #
        'NdrMesTypeEncode3': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_TYPE_PICKLING_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "pPicklingInfo", "pProxyInfo", "ArrTypeOffset", "nTypeIndex", "pObject"]),
        #
        'NdrMesTypeDecode3': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_TYPE_PICKLING_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "pPicklingInfo", "pProxyInfo", "ArrTypeOffset", "nTypeIndex", "pObject"]),
        #
        'NdrMesTypeFree3': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_TYPE_PICKLING_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Handle", "pPicklingInfo", "pProxyInfo", "ArrTypeOffset", "nTypeIndex", "pObject"]),
        #
        'NdrMesProcEncodeDecode3': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimUnion({"Pointer": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "Simple": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="<anon>", label="None"), arg_names=["Handle", "pProxyInfo", "nProcNum", "pReturnValue"]),
        #
        'NdrMesSimpleTypeDecodeAll': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["Handle", "pProxyInfo", "pObject", "Size"]),
        #
        'NdrMesSimpleTypeEncodeAll': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=True, label="Int16")], SimTypeBottom(label="Void"), arg_names=["Handle", "pProxyInfo", "pObject", "Size"]),
        #
        'NdrMesSimpleTypeAlignSizeAll': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIDL_STUBLESS_PROXY_INFO", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["Handle", "pProxyInfo"]),
        #
        'RpcCertGeneratePrincipalNameW': SimTypeFunction([SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Context", "Flags", "pBuffer"]),
        #
        'RpcCertGeneratePrincipalNameA': SimTypeFunction([SimTypePointer(SimTypeRef("CERT_CONTEXT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="RPC_STATUS"), arg_names=["Context", "Flags", "pBuffer"]),
    }

lib.set_prototypes(prototypes)
