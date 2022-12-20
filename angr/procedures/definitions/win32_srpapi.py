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
lib.set_library_names("srpapi.dll")
prototypes = \
    {
        #
        'SrpCreateThreadNetworkContext': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"ThreadId": SimTypeInt(signed=False, label="UInt32"), "ThreadContext": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="HTHREAD_NETWORK_CONTEXT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["enterpriseId", "threadNetworkContext"]),
        #
        'SrpCloseThreadNetworkContext': SimTypeFunction([SimTypePointer(SimStruct({"ThreadId": SimTypeInt(signed=False, label="UInt32"), "ThreadContext": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="HTHREAD_NETWORK_CONTEXT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["threadNetworkContext"]),
        #
        'SrpSetTokenEnterpriseId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["tokenHandle", "enterpriseId"]),
        #
        'SrpGetEnterpriseIds': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["tokenHandle", "numberOfBytes", "enterpriseIds", "enterpriseIdCount"]),
        #
        'SrpEnablePermissiveModeFileEncryption': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["enterpriseId"]),
        #
        'SrpDisablePermissiveModeFileEncryption': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SrpGetEnterprisePolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="ENTERPRISE_DATA_POLICIES"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["tokenHandle", "policyFlags"]),
        #
        'SrpIsTokenService': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "IsTokenService"]),
        #
        'SrpDoesPolicyAllowAppExecution': SimTypeFunction([SimTypePointer(SimStruct({"reserved": SimTypeInt(signed=False, label="UInt32"), "processorArchitecture": SimTypeInt(signed=False, label="UInt32"), "version": SimStruct({"Anonymous": SimUnion({"Version": SimTypeLongLong(signed=False, label="UInt64"), "Anonymous": SimStruct({"Revision": SimTypeShort(signed=False, label="UInt16"), "Build": SimTypeShort(signed=False, label="UInt16"), "Minor": SimTypeShort(signed=False, label="UInt16"), "Major": SimTypeShort(signed=False, label="UInt16")}, name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="PACKAGE_VERSION", pack=False, align=None), "name": SimTypePointer(SimTypeChar(label="Char"), offset=0), "publisher": SimTypePointer(SimTypeChar(label="Char"), offset=0), "resourceId": SimTypePointer(SimTypeChar(label="Char"), offset=0), "publisherId": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="PACKAGE_ID", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageId", "isAllowed"]),
    }

lib.set_prototypes(prototypes)
