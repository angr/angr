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
lib.set_library_names("slcext.dll")
prototypes = \
    {
        #
        'SLActivateProduct': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "type": SimTypeInt(signed=False, label="SL_ACTIVATION_TYPE")}, name="SL_ACTIVATION_INFO_HEADER", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSLC", "pProductSkuId", "cbAppSpecificData", "pvAppSpecificData", "pActivationInfo", "pwszProxyServer", "wProxyPort"]),
        #
        'SLGetServerStatus': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszServerURL", "pwszAcquisitionType", "pwszProxyServer", "wProxyPort", "phrStatus"]),
        #
        'SLAcquireGenuineTicket': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppTicketBlob", "pcbTicketBlob", "pwszTemplateId", "pwszServerUrl", "pwszClientToken"]),
        #
        'SLGetReferralInformation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="SLREFERRALTYPE"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hSLC", "eReferralType", "pSkuOrAppId", "pwszValueName", "ppwszValue"]),
    }

lib.set_prototypes(prototypes)
