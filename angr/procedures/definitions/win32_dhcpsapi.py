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
lib.set_library_names("dhcpsapi.dll")
prototypes = \
    {
        #
        'DhcpAddFilterV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_FILTER_ADD_INFO", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "AddFilterInfo", "ForceFlag"]),
        #
        'DhcpDeleteFilterV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_ADDR_PATTERN", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "DeleteFilterInfo"]),
        #
        'DhcpSetFilterV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_FILTER_GLOBAL_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "GlobalFilterInfo"]),
        #
        'DhcpGetFilterV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_FILTER_GLOBAL_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "GlobalFilterInfo"]),
        #
        'DhcpEnumFilterV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_ADDR_PATTERN", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DHCP_FILTER_LIST_TYPE"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_FILTER_ENUM_INFO", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ResumeHandle", "PreferredMaximum", "ListType", "EnumFilterInfo", "ElementsRead", "ElementsTotal"]),
        #
        'DhcpCreateSubnet': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SUBNET_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "SubnetInfo"]),
        #
        'DhcpSetSubnetInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SUBNET_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "SubnetInfo"]),
        #
        'DhcpGetSubnetInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SUBNET_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "SubnetInfo"]),
        #
        'DhcpEnumSubnets': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_IP_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ResumeHandle", "PreferredMaximum", "EnumInfo", "ElementsRead", "ElementsTotal"]),
        #
        'DhcpAddSubnetElement': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "AddElementInfo"]),
        #
        'DhcpEnumSubnetElements': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DHCP_SUBNET_ELEMENT_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_INFO_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "EnumElementType", "ResumeHandle", "PreferredMaximum", "EnumElementInfo", "ElementsRead", "ElementsTotal"]),
        #
        'DhcpRemoveSubnetElement': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="DHCP_FORCE_FLAG")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "RemoveElementInfo", "ForceFlag"]),
        #
        'DhcpDeleteSubnet': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DHCP_FORCE_FLAG")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ForceFlag"]),
        #
        'DhcpCreateOption': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_OPTION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "OptionID", "OptionInfo"]),
        #
        'DhcpSetOptionInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_OPTION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "OptionID", "OptionInfo"]),
        #
        'DhcpGetOptionInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "OptionID", "OptionInfo"]),
        #
        'DhcpEnumOptions': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ResumeHandle", "PreferredMaximum", "Options", "OptionsRead", "OptionsTotal"]),
        #
        'DhcpRemoveOption': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "OptionID"]),
        #
        'DhcpSetOptionValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "OptionID", "ScopeInfo", "OptionValue"]),
        #
        'DhcpSetOptionValues': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_VALUE_ARRAY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ScopeInfo", "OptionValues"]),
        #
        'DhcpGetOptionValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_VALUE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "OptionID", "ScopeInfo", "OptionValue"]),
        #
        'DhcpEnumOptionValues': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_VALUE_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ScopeInfo", "ResumeHandle", "PreferredMaximum", "OptionValues", "OptionsRead", "OptionsTotal"]),
        #
        'DhcpRemoveOptionValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "OptionID", "ScopeInfo"]),
        #
        'DhcpCreateClientInfoVQ': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_VQ", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpSetClientInfoVQ': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_VQ", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpGetClientInfoVQ': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_SEARCH_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_VQ", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SearchInfo", "ClientInfo"]),
        #
        'DhcpEnumSubnetClientsVQ': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_ARRAY_VQ", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ResumeHandle", "PreferredMaximum", "ClientInfo", "ClientsRead", "ClientsTotal"]),
        #
        'DhcpEnumSubnetClientsFilterStatusInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_FILTER_STATUS_INFO_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ResumeHandle", "PreferredMaximum", "ClientInfo", "ClientsRead", "ClientsTotal"]),
        #
        'DhcpCreateClientInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpSetClientInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpGetClientInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_SEARCH_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SearchInfo", "ClientInfo"]),
        #
        'DhcpDeleteClientInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_SEARCH_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpEnumSubnetClients': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ResumeHandle", "PreferredMaximum", "ClientInfo", "ClientsRead", "ClientsTotal"]),
        #
        'DhcpGetClientOptions': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_LIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientIpAddress", "ClientSubnetMask", "ClientOptions"]),
        #
        'DhcpGetMibInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_MIB_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "MibInfo"]),
        #
        'DhcpServerSetConfig': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SERVER_CONFIG_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "FieldsToSet", "ConfigInfo"]),
        #
        'DhcpServerGetConfig': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SERVER_CONFIG_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ConfigInfo"]),
        #
        'DhcpScanDatabase': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SCAN_LIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "FixFlag", "ScanList"]),
        #
        'DhcpRpcFreeMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["BufferPointer"]),
        #
        'DhcpGetVersion': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "MajorVersion", "MinorVersion"]),
        #
        'DhcpAddSubnetElementV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_DATA_V4", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "AddElementInfo"]),
        #
        'DhcpEnumSubnetElementsV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DHCP_SUBNET_ELEMENT_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_INFO_ARRAY_V4", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "EnumElementType", "ResumeHandle", "PreferredMaximum", "EnumElementInfo", "ElementsRead", "ElementsTotal"]),
        #
        'DhcpRemoveSubnetElementV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_DATA_V4", SimStruct), offset=0), SimTypeInt(signed=False, label="DHCP_FORCE_FLAG")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "RemoveElementInfo", "ForceFlag"]),
        #
        'DhcpCreateClientInfoV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_V4", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpSetClientInfoV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_V4", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpGetClientInfoV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_SEARCH_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_V4", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SearchInfo", "ClientInfo"]),
        #
        'DhcpEnumSubnetClientsV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_ARRAY_V4", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ResumeHandle", "PreferredMaximum", "ClientInfo", "ClientsRead", "ClientsTotal"]),
        #
        'DhcpServerSetConfigV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SERVER_CONFIG_INFO_V4", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "FieldsToSet", "ConfigInfo"]),
        #
        'DhcpServerGetConfigV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SERVER_CONFIG_INFO_V4", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ConfigInfo"]),
        #
        'DhcpSetSuperScopeV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "SuperScopeName", "ChangeExisting"]),
        #
        'DhcpDeleteSuperScopeV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SuperScopeName"]),
        #
        'DhcpGetSuperScopeInfoV4': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SUPER_SCOPE_TABLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SuperScopeTable"]),
        #
        'DhcpEnumSubnetClientsV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_ARRAY_V5", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ResumeHandle", "PreferredMaximum", "ClientInfo", "ClientsRead", "ClientsTotal"]),
        #
        'DhcpCreateOptionV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionId", "ClassName", "VendorName", "OptionInfo"]),
        #
        'DhcpSetOptionInfoV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "ClassName", "VendorName", "OptionInfo"]),
        #
        'DhcpGetOptionInfoV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "ClassName", "VendorName", "OptionInfo"]),
        #
        'DhcpEnumOptionsV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "ClassName", "VendorName", "ResumeHandle", "PreferredMaximum", "Options", "OptionsRead", "OptionsTotal"]),
        #
        'DhcpRemoveOptionV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "ClassName", "VendorName"]),
        #
        'DhcpSetOptionValueV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionId", "ClassName", "VendorName", "ScopeInfo", "OptionValue"]),
        #
        'DhcpSetOptionValuesV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_VALUE_ARRAY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "ClassName", "VendorName", "ScopeInfo", "OptionValues"]),
        #
        'DhcpGetOptionValueV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_VALUE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "ClassName", "VendorName", "ScopeInfo", "OptionValue"]),
        #
        'DhcpGetOptionValueV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO6", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_VALUE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "ClassName", "VendorName", "ScopeInfo", "OptionValue"]),
        #
        'DhcpEnumOptionValuesV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_VALUE_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "ClassName", "VendorName", "ScopeInfo", "ResumeHandle", "PreferredMaximum", "OptionValues", "OptionsRead", "OptionsTotal"]),
        #
        'DhcpRemoveOptionValueV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "ClassName", "VendorName", "ScopeInfo"]),
        #
        'DhcpCreateClass': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_CLASS_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ReservedMustBeZero", "ClassInfo"]),
        #
        'DhcpModifyClass': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_CLASS_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ReservedMustBeZero", "ClassInfo"]),
        #
        'DhcpDeleteClass': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ReservedMustBeZero", "ClassName"]),
        #
        'DhcpGetClassInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_CLASS_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLASS_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ReservedMustBeZero", "PartialClassInfo", "FilledClassInfo"]),
        #
        'DhcpEnumClasses': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLASS_INFO_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ReservedMustBeZero", "ResumeHandle", "PreferredMaximum", "ClassInfoArray", "nRead", "nTotal"]),
        #
        'DhcpGetAllOptions': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_ALL_OPTIONS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionStruct"]),
        #
        'DhcpGetAllOptionsV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_ALL_OPTIONS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionStruct"]),
        #
        'DhcpGetAllOptionValues': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_ALL_OPTION_VALUES", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "ScopeInfo", "Values"]),
        #
        'DhcpGetAllOptionValuesV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO6", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_ALL_OPTION_VALUES", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "ScopeInfo", "Values"]),
        #
        'DhcpEnumServers': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCPDS_SERVERS", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "IdInfo", "Servers", "CallbackFn", "CallbackData"]),
        #
        'DhcpAddServer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("DHCPDS_SERVER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "IdInfo", "NewServer", "CallbackFn", "CallbackData"]),
        #
        'DhcpDeleteServer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("DHCPDS_SERVER", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "IdInfo", "NewServer", "CallbackFn", "CallbackData"]),
        #
        'DhcpGetServerBindingInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_BIND_ELEMENT_ARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "BindElementsInfo"]),
        #
        'DhcpSetServerBindingInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_BIND_ELEMENT_ARRAY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "BindElementInfo"]),
        #
        'DhcpAddSubnetElementV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_DATA_V5", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "AddElementInfo"]),
        #
        'DhcpEnumSubnetElementsV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DHCP_SUBNET_ELEMENT_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_INFO_ARRAY_V5", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "EnumElementType", "ResumeHandle", "PreferredMaximum", "EnumElementInfo", "ElementsRead", "ElementsTotal"]),
        #
        'DhcpRemoveSubnetElementV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_DATA_V5", SimStruct), offset=0), SimTypeInt(signed=False, label="DHCP_FORCE_FLAG")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "RemoveElementInfo", "ForceFlag"]),
        #
        'DhcpV4EnumSubnetReservations': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_RESERVATION_INFO_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ResumeHandle", "PreferredMaximum", "EnumElementInfo", "ElementsRead", "ElementsTotal"]),
        #
        'DhcpCreateOptionV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionId", "ClassName", "VendorName", "OptionInfo"]),
        #
        'DhcpRemoveOptionV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "ClassName", "VendorName"]),
        #
        'DhcpEnumOptionsV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "ClassName", "VendorName", "ResumeHandle", "PreferredMaximum", "Options", "OptionsRead", "OptionsTotal"]),
        #
        'DhcpRemoveOptionValueV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO6", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "ClassName", "VendorName", "ScopeInfo"]),
        #
        'DhcpGetOptionInfoV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "ClassName", "VendorName", "OptionInfo"]),
        #
        'DhcpSetOptionInfoV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "ClassName", "VendorName", "OptionInfo"]),
        #
        'DhcpSetOptionValueV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO6", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionId", "ClassName", "VendorName", "ScopeInfo", "OptionValue"]),
        #
        'DhcpGetSubnetInfoVQ': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SUBNET_INFO_VQ", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "SubnetInfo"]),
        #
        'DhcpCreateSubnetVQ': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SUBNET_INFO_VQ", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "SubnetInfo"]),
        #
        'DhcpSetSubnetInfoVQ': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SUBNET_INFO_VQ", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "SubnetInfo"]),
        #
        'DhcpEnumOptionValuesV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO6", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_VALUE_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "ClassName", "VendorName", "ScopeInfo", "ResumeHandle", "PreferredMaximum", "OptionValues", "OptionsRead", "OptionsTotal"]),
        #
        'DhcpDsInit': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'DhcpDsCleanup': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'DhcpSetThreadOptions': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "Reserved"]),
        #
        'DhcpGetThreadOptions': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pFlags", "Reserved"]),
        #
        'DhcpServerQueryAttribute': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_ATTRIB", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddr", "dwReserved", "DhcpAttribId", "pDhcpAttrib"]),
        #
        'DhcpServerQueryAttributes': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_ATTRIB_ARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddr", "dwReserved", "dwAttribCount", "pDhcpAttribs", "pDhcpAttribArr"]),
        #
        'DhcpServerRedoAuthorization': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddr", "dwReserved"]),
        #
        'DhcpAuditLogSetParams': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "AuditLogDir", "DiskCheckInterval", "MaxLogFilesSize", "MinSpaceOnDisk"]),
        #
        'DhcpAuditLogGetParams': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "AuditLogDir", "DiskCheckInterval", "MaxLogFilesSize", "MinSpaceOnDisk"]),
        #
        'DhcpServerQueryDnsRegCredentials': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "UnameSize", "Uname", "DomainSize", "Domain"]),
        #
        'DhcpServerSetDnsRegCredentials': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Uname", "Domain", "Passwd"]),
        #
        'DhcpServerSetDnsRegCredentialsV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Uname", "Domain", "Passwd"]),
        #
        'DhcpServerBackupDatabase': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Path"]),
        #
        'DhcpServerRestoreDatabase': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Path"]),
        #
        'DhcpServerSetConfigVQ': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SERVER_CONFIG_INFO_VQ", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "FieldsToSet", "ConfigInfo"]),
        #
        'DhcpServerGetConfigVQ': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SERVER_CONFIG_INFO_VQ", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ConfigInfo"]),
        #
        'DhcpGetServerSpecificStrings': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SERVER_SPECIFIC_STRINGS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ServerSpecificStrings"]),
        #
        'DhcpServerAuditlogParamsFree': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_SERVER_CONFIG_INFO_VQ", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["ConfigInfo"]),
        #
        'DhcpCreateSubnetV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypePointer(SimTypeRef("DHCP_SUBNET_INFO_V6", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "SubnetInfo"]),
        #
        'DhcpDeleteSubnetV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypeInt(signed=False, label="DHCP_FORCE_FLAG")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ForceFlag"]),
        #
        'DhcpEnumSubnetsV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCPV6_IP_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ResumeHandle", "PreferredMaximum", "EnumInfo", "ElementsRead", "ElementsTotal"]),
        #
        'DhcpAddSubnetElementV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_DATA_V6", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "AddElementInfo"]),
        #
        'DhcpRemoveSubnetElementV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_DATA_V6", SimStruct), offset=0), SimTypeInt(signed=False, label="DHCP_FORCE_FLAG")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "RemoveElementInfo", "ForceFlag"]),
        #
        'DhcpEnumSubnetElementsV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypeInt(signed=False, label="DHCP_SUBNET_ELEMENT_TYPE_V6"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SUBNET_ELEMENT_INFO_ARRAY_V6", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "EnumElementType", "ResumeHandle", "PreferredMaximum", "EnumElementInfo", "ElementsRead", "ElementsTotal"]),
        #
        'DhcpGetSubnetInfoV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SUBNET_INFO_V6", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "SubnetInfo"]),
        #
        'DhcpEnumSubnetClientsV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypePointer(SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_ARRAY_V6", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ResumeHandle", "PreferredMaximum", "ClientInfo", "ClientsRead", "ClientsTotal"]),
        #
        'DhcpServerGetConfigV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO6", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_SERVER_CONFIG_INFO_V6", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ScopeInfo", "ConfigInfo"]),
        #
        'DhcpServerSetConfigV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO6", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_SERVER_CONFIG_INFO_V6", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ScopeInfo", "FieldsToSet", "ConfigInfo"]),
        #
        'DhcpSetSubnetInfoV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypePointer(SimTypeRef("DHCP_SUBNET_INFO_V6", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "SubnetInfo"]),
        #
        'DhcpGetMibInfoV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_MIB_INFO_V6", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "MibInfo"]),
        #
        'DhcpGetServerBindingInfoV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCPV6_BIND_ELEMENT_ARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "BindElementsInfo"]),
        #
        'DhcpSetServerBindingInfoV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCPV6_BIND_ELEMENT_ARRAY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "BindElementInfo"]),
        #
        'DhcpSetClientInfoV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_V6", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpGetClientInfoV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_SEARCH_INFO_V6", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_V6", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SearchInfo", "ClientInfo"]),
        #
        'DhcpDeleteClientInfoV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_SEARCH_INFO_V6", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpCreateClassV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_CLASS_INFO_V6", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ReservedMustBeZero", "ClassInfo"]),
        #
        'DhcpModifyClassV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_CLASS_INFO_V6", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ReservedMustBeZero", "ClassInfo"]),
        #
        'DhcpDeleteClassV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ReservedMustBeZero", "ClassName"]),
        #
        'DhcpEnumClassesV6': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLASS_INFO_ARRAY_V6", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ReservedMustBeZero", "ResumeHandle", "PreferredMaximum", "ClassInfoArray", "nRead", "nTotal"]),
        #
        'DhcpSetSubnetDelayOffer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "TimeDelayInMilliseconds"]),
        #
        'DhcpGetSubnetDelayOffer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "TimeDelayInMilliseconds"]),
        #
        'DhcpGetMibInfoV5': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_MIB_INFO_V5", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "MibInfo"]),
        #
        'DhcpAddSecurityGroup': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pServer"]),
        #
        'DhcpV4GetOptionValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_OPTION_VALUE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "PolicyName", "VendorName", "ScopeInfo", "OptionValue"]),
        #
        'DhcpV4SetOptionValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionId", "PolicyName", "VendorName", "ScopeInfo", "OptionValue"]),
        #
        'DhcpV4SetOptionValues': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_VALUE_ARRAY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "PolicyName", "VendorName", "ScopeInfo", "OptionValues"]),
        #
        'DhcpV4RemoveOptionValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "OptionID", "PolicyName", "VendorName", "ScopeInfo"]),
        #
        'DhcpV4GetAllOptionValues': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_OPTION_SCOPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_ALL_OPTION_VALUES_PB", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "ScopeInfo", "Values"]),
        #
        'DhcpV4FailoverCreateRelationship': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_FAILOVER_RELATIONSHIP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "pRelationship"]),
        #
        'DhcpV4FailoverSetRelationship': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCP_FAILOVER_RELATIONSHIP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "Flags", "pRelationship"]),
        #
        'DhcpV4FailoverDeleteRelationship': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "pRelationshipName"]),
        #
        'DhcpV4FailoverGetRelationship': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_FAILOVER_RELATIONSHIP", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "pRelationshipName", "pRelationship"]),
        #
        'DhcpV4FailoverEnumRelationship': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_FAILOVER_RELATIONSHIP_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ResumeHandle", "PreferredMaximum", "pRelationship", "RelationshipRead", "RelationshipTotal"]),
        #
        'DhcpV4FailoverAddScopeToRelationship': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_FAILOVER_RELATIONSHIP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "pRelationship"]),
        #
        'DhcpV4FailoverDeleteScopeFromRelationship': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_FAILOVER_RELATIONSHIP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "pRelationship"]),
        #
        'DhcpV4FailoverGetScopeRelationship': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_FAILOVER_RELATIONSHIP", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ScopeId", "pRelationship"]),
        #
        'DhcpV4FailoverGetScopeStatistics': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_FAILOVER_STATISTICS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ScopeId", "pStats"]),
        #
        'DhcpV4FailoverGetClientInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_SEARCH_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCPV4_FAILOVER_CLIENT_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SearchInfo", "ClientInfo"]),
        #
        'DhcpV4FailoverGetSystemTime': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "pTime", "pMaxAllowedDeltaTime"]),
        #
        'DhcpV4FailoverGetAddressStatus': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "pStatus"]),
        #
        'DhcpV4FailoverTriggerAddrAllocation': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "pFailRelName"]),
        #
        'DhcpHlprCreateV4Policy': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DHCP_POL_LOGIC_OPER"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PolicyName", "fGlobalPolicy", "Subnet", "ProcessingOrder", "RootOperator", "Description", "Enabled", "Policy"]),
        #
        'DhcpHlprCreateV4PolicyEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DHCP_POL_LOGIC_OPER"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_POLICY_EX", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["PolicyName", "fGlobalPolicy", "Subnet", "ProcessingOrder", "RootOperator", "Description", "Enabled", "Policy"]),
        #
        'DhcpHlprAddV4PolicyExpr': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DHCP_POL_LOGIC_OPER"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Policy", "ParentExpr", "Operator", "ExprIndex"]),
        #
        'DhcpHlprAddV4PolicyCondition': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="DHCP_POL_ATTR_TYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="DHCP_POL_COMPARATOR"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Policy", "ParentExpr", "Type", "OptionID", "SubOptionID", "VendorName", "Operator", "Value", "ValueLength", "ConditionIndex"]),
        #
        'DhcpHlprAddV4PolicyRange': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCP_IP_RANGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Policy", "Range"]),
        #
        'DhcpHlprResetV4PolicyExpr': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Policy"]),
        #
        'DhcpHlprModifyV4PolicyExpr': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0), SimTypeInt(signed=False, label="DHCP_POL_LOGIC_OPER")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Policy", "Operator"]),
        #
        'DhcpHlprFreeV4Policy': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Policy"]),
        #
        'DhcpHlprFreeV4PolicyArray': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY_ARRAY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PolicyArray"]),
        #
        'DhcpHlprFreeV4PolicyEx': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY_EX", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PolicyEx"]),
        #
        'DhcpHlprFreeV4PolicyExArray': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY_EX_ARRAY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PolicyExArray"]),
        #
        'DhcpHlprFreeV4DhcpProperty': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_PROPERTY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Property"]),
        #
        'DhcpHlprFreeV4DhcpPropertyArray': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_PROPERTY_ARRAY", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["PropertyArray"]),
        #
        'DhcpHlprFindV4DhcpProperty': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_PROPERTY_ARRAY", SimStruct), offset=0), SimTypeInt(signed=False, label="DHCP_PROPERTY_ID"), SimTypeInt(signed=False, label="DHCP_PROPERTY_TYPE")], SimTypePointer(SimTypeRef("DHCP_PROPERTY", SimStruct), offset=0), arg_names=["PropertyArray", "ID", "Type"]),
        #
        'DhcpHlprIsV4PolicySingleUC': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Policy"]),
        #
        'DhcpV4QueryPolicyEnforcement': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "fGlobalPolicy", "SubnetAddress", "Enabled"]),
        #
        'DhcpV4SetPolicyEnforcement': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "fGlobalPolicy", "SubnetAddress", "Enable"]),
        #
        'DhcpHlprIsV4PolicyWellFormed': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPolicy"]),
        #
        'DhcpHlprIsV4PolicyValid': SimTypeFunction([SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPolicy"]),
        #
        'DhcpV4CreatePolicy': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "pPolicy"]),
        #
        'DhcpV4GetPolicy': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "fGlobalPolicy", "SubnetAddress", "PolicyName", "Policy"]),
        #
        'DhcpV4SetPolicy': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_POLICY", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "FieldsModified", "fGlobalPolicy", "SubnetAddress", "PolicyName", "Policy"]),
        #
        'DhcpV4DeletePolicy': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "fGlobalPolicy", "SubnetAddress", "PolicyName"]),
        #
        'DhcpV4EnumPolicies': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_POLICY_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ResumeHandle", "PreferredMaximum", "fGlobalPolicy", "SubnetAddress", "EnumInfo", "ElementsRead", "ElementsTotal"]),
        #
        'DhcpV4AddPolicyRange': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_IP_RANGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "PolicyName", "Range"]),
        #
        'DhcpV4RemovePolicyRange': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_IP_RANGE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "PolicyName", "Range"]),
        #
        'DhcpV6SetStatelessStoreParams': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DHCPV6_STATELESS_PARAMS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "fServerLevel", "SubnetAddress", "FieldModified", "Params"]),
        #
        'DhcpV6GetStatelessStoreParams': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypePointer(SimTypePointer(SimTypeRef("DHCPV6_STATELESS_PARAMS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "fServerLevel", "SubnetAddress", "Params"]),
        #
        'DhcpV6GetStatelessStatistics': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCPV6_STATELESS_STATS", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "StatelessStats"]),
        #
        'DhcpV4CreateClientInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_PB", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpV4EnumSubnetClients': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_PB_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ResumeHandle", "PreferredMaximum", "ClientInfo", "ClientsRead", "ClientsTotal"]),
        #
        'DhcpV4GetClientInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_SEARCH_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_PB", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SearchInfo", "ClientInfo"]),
        #
        'DhcpV6CreateClientInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_V6", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpV4GetFreeIPAddress': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_IP_ARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ScopeId", "StartIP", "EndIP", "NumFreeAddrReq", "IPAddrList"]),
        #
        'DhcpV6GetFreeIPAddress': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypeRef("DHCP_IPV6_ADDRESS", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCPV6_IP_ARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ScopeId", "StartIP", "EndIP", "NumFreeAddrReq", "IPAddrList"]),
        #
        'DhcpV4CreateClientInfoEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_EX", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ClientInfo"]),
        #
        'DhcpV4EnumSubnetClientsEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_EX_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SubnetAddress", "ResumeHandle", "PreferredMaximum", "ClientInfo", "ClientsRead", "ClientsTotal"]),
        #
        'DhcpV4GetClientInfoEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_SEARCH_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_CLIENT_INFO_EX", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "SearchInfo", "ClientInfo"]),
        #
        'DhcpV4CreatePolicyEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_POLICY_EX", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "PolicyEx"]),
        #
        'DhcpV4GetPolicyEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_POLICY_EX", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "GlobalPolicy", "SubnetAddress", "PolicyName", "Policy"]),
        #
        'DhcpV4SetPolicyEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCP_POLICY_EX", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "FieldsModified", "GlobalPolicy", "SubnetAddress", "PolicyName", "Policy"]),
        #
        'DhcpV4EnumPoliciesEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("DHCP_POLICY_EX_ARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerIpAddress", "ResumeHandle", "PreferredMaximum", "GlobalPolicy", "SubnetAddress", "EnumInfo", "ElementsRead", "ElementsTotal"]),
    }

lib.set_prototypes(prototypes)
