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
lib.set_library_names("tapi32.dll")
prototypes = \
    {
        #
        'lineAccept': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpsUserUserInfo", "dwSize"]),
        #
        'lineAddProvider': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszProviderFilename", "hwndOwner", "lpdwPermanentProviderID"]),
        #
        'lineAddProviderA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszProviderFilename", "hwndOwner", "lpdwPermanentProviderID"]),
        #
        'lineAddProviderW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszProviderFilename", "hwndOwner", "lpdwPermanentProviderID"]),
        #
        'lineAddToConference': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hConfCall", "hConsultCall"]),
        #
        'lineAgentSpecific': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "dwAgentExtensionIDIndex", "lpParams", "dwSize"]),
        #
        'lineAnswer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpsUserUserInfo", "dwSize"]),
        #
        'lineBlindTransfer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszDestAddress", "dwCountryCode"]),
        #
        'lineBlindTransferA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszDestAddress", "dwCountryCode"]),
        #
        'lineBlindTransferW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszDestAddressW", "dwCountryCode"]),
        #
        'lineClose': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine"]),
        #
        'lineCompleteCall': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpdwCompletionID", "dwCompletionMode", "dwMessageID"]),
        #
        'lineCompleteTransfer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "hConsultCall", "lphConfCall", "dwTransferMode"]),
        #
        'lineConfigDialog': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "hwndOwner", "lpszDeviceClass"]),
        #
        'lineConfigDialogA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "hwndOwner", "lpszDeviceClass"]),
        #
        'lineConfigDialogW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "hwndOwner", "lpszDeviceClass"]),
        #
        'lineConfigDialogEdit': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "hwndOwner", "lpszDeviceClass", "lpDeviceConfigIn", "dwSize", "lpDeviceConfigOut"]),
        #
        'lineConfigDialogEditA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "hwndOwner", "lpszDeviceClass", "lpDeviceConfigIn", "dwSize", "lpDeviceConfigOut"]),
        #
        'lineConfigDialogEditW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "hwndOwner", "lpszDeviceClass", "lpDeviceConfigIn", "dwSize", "lpDeviceConfigOut"]),
        #
        'lineConfigProvider': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndOwner", "dwPermanentProviderID"]),
        #
        'lineCreateAgentW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpszAgentID", "lpszAgentPIN", "lphAgent"]),
        #
        'lineCreateAgentA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpszAgentID", "lpszAgentPIN", "lphAgent"]),
        #
        'lineCreateAgentSessionW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "hAgent", "lpszAgentPIN", "dwWorkingAddressID", "lpGroupID", "lphAgentSession"]),
        #
        'lineCreateAgentSessionA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "hAgent", "lpszAgentPIN", "dwWorkingAddressID", "lpGroupID", "lphAgentSession"]),
        #
        'lineDeallocateCall': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall"]),
        #
        'lineDevSpecific': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "hCall", "lpParams", "dwSize"]),
        #
        'lineDevSpecificFeature': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwFeature", "lpParams", "dwSize"]),
        #
        'lineDial': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszDestAddress", "dwCountryCode"]),
        #
        'lineDialA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszDestAddress", "dwCountryCode"]),
        #
        'lineDialW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszDestAddress", "dwCountryCode"]),
        #
        'lineDrop': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpsUserUserInfo", "dwSize"]),
        #
        'lineForward': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEFORWARDLIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "bAllAddresses", "dwAddressID", "lpForwardList", "dwNumRingsNoAnswer", "lphConsultCall", "lpCallParams"]),
        #
        'lineForwardA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEFORWARDLIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "bAllAddresses", "dwAddressID", "lpForwardList", "dwNumRingsNoAnswer", "lphConsultCall", "lpCallParams"]),
        #
        'lineForwardW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEFORWARDLIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "bAllAddresses", "dwAddressID", "lpForwardList", "dwNumRingsNoAnswer", "lphConsultCall", "lpCallParams"]),
        #
        'lineGatherDigits': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwDigitModes", "lpsDigits", "dwNumDigits", "lpszTerminationDigits", "dwFirstDigitTimeout", "dwInterDigitTimeout"]),
        #
        'lineGatherDigitsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwDigitModes", "lpsDigits", "dwNumDigits", "lpszTerminationDigits", "dwFirstDigitTimeout", "dwInterDigitTimeout"]),
        #
        'lineGatherDigitsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwDigitModes", "lpsDigits", "dwNumDigits", "lpszTerminationDigits", "dwFirstDigitTimeout", "dwInterDigitTimeout"]),
        #
        'lineGenerateDigits': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwDigitMode", "lpszDigits", "dwDuration"]),
        #
        'lineGenerateDigitsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwDigitMode", "lpszDigits", "dwDuration"]),
        #
        'lineGenerateDigitsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwDigitMode", "lpszDigits", "dwDuration"]),
        #
        'lineGenerateTone': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEGENERATETONE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwToneMode", "dwDuration", "dwNumTones", "lpTones"]),
        #
        'lineGetAddressCaps': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEADDRESSCAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAddressID", "dwAPIVersion", "dwExtVersion", "lpAddressCaps"]),
        #
        'lineGetAddressCapsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEADDRESSCAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAddressID", "dwAPIVersion", "dwExtVersion", "lpAddressCaps"]),
        #
        'lineGetAddressCapsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEADDRESSCAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAddressID", "dwAPIVersion", "dwExtVersion", "lpAddressCaps"]),
        #
        'lineGetAddressID': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpdwAddressID", "dwAddressMode", "lpsAddress", "dwSize"]),
        #
        'lineGetAddressIDA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpdwAddressID", "dwAddressMode", "lpsAddress", "dwSize"]),
        #
        'lineGetAddressIDW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpdwAddressID", "dwAddressMode", "lpsAddress", "dwSize"]),
        #
        'lineGetAddressStatus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEADDRESSSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpAddressStatus"]),
        #
        'lineGetAddressStatusA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEADDRESSSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpAddressStatus"]),
        #
        'lineGetAddressStatusW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEADDRESSSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpAddressStatus"]),
        #
        'lineGetAgentActivityListA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTACTIVITYLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpAgentActivityList"]),
        #
        'lineGetAgentActivityListW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTACTIVITYLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpAgentActivityList"]),
        #
        'lineGetAgentCapsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTCAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAddressID", "dwAppAPIVersion", "lpAgentCaps"]),
        #
        'lineGetAgentCapsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTCAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAddressID", "dwAppAPIVersion", "lpAgentCaps"]),
        #
        'lineGetAgentGroupListA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTGROUPLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpAgentGroupList"]),
        #
        'lineGetAgentGroupListW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTGROUPLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpAgentGroupList"]),
        #
        'lineGetAgentInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "hAgent", "lpAgentInfo"]),
        #
        'lineGetAgentSessionInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTSESSIONINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "hAgentSession", "lpAgentSessionInfo"]),
        #
        'lineGetAgentSessionList': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTSESSIONLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "hAgent", "lpAgentSessionList"]),
        #
        'lineGetAgentStatusA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpAgentStatus"]),
        #
        'lineGetAgentStatusW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpAgentStatus"]),
        #
        'lineGetAppPriority': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEEXTENSIONID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszAppFilename", "dwMediaMode", "lpExtensionID", "dwRequestMode", "lpExtensionName", "lpdwPriority"]),
        #
        'lineGetAppPriorityA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEEXTENSIONID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszAppFilename", "dwMediaMode", "lpExtensionID", "dwRequestMode", "lpExtensionName", "lpdwPriority"]),
        #
        'lineGetAppPriorityW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEEXTENSIONID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszAppFilename", "dwMediaMode", "lpExtensionID", "dwRequestMode", "lpExtensionName", "lpdwPriority"]),
        #
        'lineGetCallInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpCallInfo"]),
        #
        'lineGetCallInfoA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpCallInfo"]),
        #
        'lineGetCallInfoW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpCallInfo"]),
        #
        'lineGetCallStatus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpCallStatus"]),
        #
        'lineGetConfRelatedCalls': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpCallList"]),
        #
        'lineGetCountry': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECOUNTRYLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwCountryID", "dwAPIVersion", "lpLineCountryList"]),
        #
        'lineGetCountryA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECOUNTRYLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwCountryID", "dwAPIVersion", "lpLineCountryList"]),
        #
        'lineGetCountryW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECOUNTRYLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwCountryID", "dwAPIVersion", "lpLineCountryList"]),
        #
        'lineGetDevCaps': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEDEVCAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPIVersion", "dwExtVersion", "lpLineDevCaps"]),
        #
        'lineGetDevCapsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEDEVCAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPIVersion", "dwExtVersion", "lpLineDevCaps"]),
        #
        'lineGetDevCapsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEDEVCAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPIVersion", "dwExtVersion", "lpLineDevCaps"]),
        #
        'lineGetDevConfig': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpDeviceConfig", "lpszDeviceClass"]),
        #
        'lineGetDevConfigA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpDeviceConfig", "lpszDeviceClass"]),
        #
        'lineGetDevConfigW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpDeviceConfig", "lpszDeviceClass"]),
        #
        'lineGetGroupListA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTGROUPLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpGroupList"]),
        #
        'lineGetGroupListW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTGROUPLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpGroupList"]),
        #
        'lineGetIcon': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpszDeviceClass", "lphIcon"]),
        #
        'lineGetIconA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpszDeviceClass", "lphIcon"]),
        #
        'lineGetIconW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpszDeviceClass", "lphIcon"]),
        #
        'lineGetID': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "hCall", "dwSelect", "lpDeviceID", "lpszDeviceClass"]),
        #
        'lineGetIDA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "hCall", "dwSelect", "lpDeviceID", "lpszDeviceClass"]),
        #
        'lineGetIDW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "hCall", "dwSelect", "lpDeviceID", "lpszDeviceClass"]),
        #
        'lineGetLineDevStatus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEDEVSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpLineDevStatus"]),
        #
        'lineGetLineDevStatusA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEDEVSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpLineDevStatus"]),
        #
        'lineGetLineDevStatusW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEDEVSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpLineDevStatus"]),
        #
        'lineGetMessage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEMESSAGE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "lpMessage", "dwTimeout"]),
        #
        'lineGetNewCalls': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "dwSelect", "lpCallList"]),
        #
        'lineGetNumRings': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpdwNumRings"]),
        #
        'lineGetProviderList': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEPROVIDERLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwAPIVersion", "lpProviderList"]),
        #
        'lineGetProviderListA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEPROVIDERLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwAPIVersion", "lpProviderList"]),
        #
        'lineGetProviderListW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEPROVIDERLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwAPIVersion", "lpProviderList"]),
        #
        'lineGetProxyStatus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEPROXYREQUESTLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAppAPIVersion", "lpLineProxyReqestList"]),
        #
        'lineGetQueueInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEQUEUEINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwQueueID", "lpLineQueueInfo"]),
        #
        'lineGetQueueListA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("LINEQUEUELIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpGroupID", "lpQueueList"]),
        #
        'lineGetQueueListW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("LINEQUEUELIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpGroupID", "lpQueueList"]),
        #
        'lineGetRequest': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwRequestMode", "lpRequestBuffer"]),
        #
        'lineGetRequestA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwRequestMode", "lpRequestBuffer"]),
        #
        'lineGetRequestW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwRequestMode", "lpRequestBuffer"]),
        #
        'lineGetStatusMessages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpdwLineStates", "lpdwAddressStates"]),
        #
        'lineGetTranslateCaps': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINETRANSLATECAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwAPIVersion", "lpTranslateCaps"]),
        #
        'lineGetTranslateCapsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINETRANSLATECAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwAPIVersion", "lpTranslateCaps"]),
        #
        'lineGetTranslateCapsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINETRANSLATECAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwAPIVersion", "lpTranslateCaps"]),
        #
        'lineHandoff': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszFileName", "dwMediaMode"]),
        #
        'lineHandoffA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszFileName", "dwMediaMode"]),
        #
        'lineHandoffW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszFileName", "dwMediaMode"]),
        #
        'lineHold': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall"]),
        #
        'lineInitialize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevice", "dwMessage", "dwInstance", "dwParam1", "dwParam2", "dwParam3"]), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lphLineApp", "hInstance", "lpfnCallback", "lpszAppName", "lpdwNumDevs"]),
        #
        'lineInitializeExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevice", "dwMessage", "dwInstance", "dwParam1", "dwParam2", "dwParam3"]), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINEINITIALIZEEXPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lphLineApp", "hInstance", "lpfnCallback", "lpszFriendlyAppName", "lpdwNumDevs", "lpdwAPIVersion", "lpLineInitializeExParams"]),
        #
        'lineInitializeExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevice", "dwMessage", "dwInstance", "dwParam1", "dwParam2", "dwParam3"]), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINEINITIALIZEEXPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lphLineApp", "hInstance", "lpfnCallback", "lpszFriendlyAppName", "lpdwNumDevs", "lpdwAPIVersion", "lpLineInitializeExParams"]),
        #
        'lineMakeCall': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lphCall", "lpszDestAddress", "dwCountryCode", "lpCallParams"]),
        #
        'lineMakeCallA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lphCall", "lpszDestAddress", "dwCountryCode", "lpCallParams"]),
        #
        'lineMakeCallW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lphCall", "lpszDestAddress", "dwCountryCode", "lpCallParams"]),
        #
        'lineMonitorDigits': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwDigitModes"]),
        #
        'lineMonitorMedia': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwMediaModes"]),
        #
        'lineMonitorTones': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEMONITORTONE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpToneList", "dwNumEntries"]),
        #
        'lineNegotiateAPIVersion': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINEEXTENSIONID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPILowVersion", "dwAPIHighVersion", "lpdwAPIVersion", "lpExtensionID"]),
        #
        'lineNegotiateExtVersion': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPIVersion", "dwExtLowVersion", "dwExtHighVersion", "lpdwExtVersion"]),
        #
        'lineOpen': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "lphLine", "dwAPIVersion", "dwExtVersion", "dwCallbackInstance", "dwPrivileges", "dwMediaModes", "lpCallParams"]),
        #
        'lineOpenA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "lphLine", "dwAPIVersion", "dwExtVersion", "dwCallbackInstance", "dwPrivileges", "dwMediaModes", "lpCallParams"]),
        #
        'lineOpenW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "lphLine", "dwAPIVersion", "dwExtVersion", "dwCallbackInstance", "dwPrivileges", "dwMediaModes", "lpCallParams"]),
        #
        'linePark': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwParkMode", "lpszDirAddress", "lpNonDirAddress"]),
        #
        'lineParkA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwParkMode", "lpszDirAddress", "lpNonDirAddress"]),
        #
        'lineParkW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwParkMode", "lpszDirAddress", "lpNonDirAddress"]),
        #
        'linePickup': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lphCall", "lpszDestAddress", "lpszGroupID"]),
        #
        'linePickupA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lphCall", "lpszDestAddress", "lpszGroupID"]),
        #
        'linePickupW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lphCall", "lpszDestAddress", "lpszGroupID"]),
        #
        'linePrepareAddToConference': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConfCall", "lphConsultCall", "lpCallParams"]),
        #
        'linePrepareAddToConferenceA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConfCall", "lphConsultCall", "lpCallParams"]),
        #
        'linePrepareAddToConferenceW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hConfCall", "lphConsultCall", "lpCallParams"]),
        #
        'lineProxyMessage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "hCall", "dwMsg", "dwParam1", "dwParam2", "dwParam3"]),
        #
        'lineProxyResponse': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEPROXYREQUEST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "lpProxyRequest", "dwResult"]),
        #
        'lineRedirect': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszDestAddress", "dwCountryCode"]),
        #
        'lineRedirectA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszDestAddress", "dwCountryCode"]),
        #
        'lineRedirectW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpszDestAddress", "dwCountryCode"]),
        #
        'lineRegisterRequestRecipient': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwRegistrationInstance", "dwRequestMode", "bEnable"]),
        #
        'lineReleaseUserUserInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall"]),
        #
        'lineRemoveFromConference': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall"]),
        #
        'lineRemoveProvider': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwPermanentProviderID", "hwndOwner"]),
        #
        'lineSecureCall': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall"]),
        #
        'lineSendUserUserInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpsUserUserInfo", "dwSize"]),
        #
        'lineSetAgentActivity': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "dwActivityID"]),
        #
        'lineSetAgentGroup': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEAGENTGROUPLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lpAgentGroupList"]),
        #
        'lineSetAgentMeasurementPeriod': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "hAgent", "dwMeasurementPeriod"]),
        #
        'lineSetAgentSessionState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "hAgentSession", "dwAgentSessionState", "dwNextAgentSessionState"]),
        #
        'lineSetAgentStateEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "hAgent", "dwAgentState", "dwNextAgentState"]),
        #
        'lineSetAgentState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "dwAgentState", "dwNextAgentState"]),
        #
        'lineSetAppPriority': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEEXTENSIONID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszAppFilename", "dwMediaMode", "lpExtensionID", "dwRequestMode", "lpszExtensionName", "dwPriority"]),
        #
        'lineSetAppPriorityA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEEXTENSIONID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszAppFilename", "dwMediaMode", "lpExtensionID", "dwRequestMode", "lpszExtensionName", "dwPriority"]),
        #
        'lineSetAppPriorityW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEEXTENSIONID", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszAppFilename", "dwMediaMode", "lpExtensionID", "dwRequestMode", "lpszExtensionName", "dwPriority"]),
        #
        'lineSetAppSpecific': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwAppSpecific"]),
        #
        'lineSetCallData': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpCallData", "dwSize"]),
        #
        'lineSetCallParams': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEDIALPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwBearerMode", "dwMinRate", "dwMaxRate", "lpDialParams"]),
        #
        'lineSetCallPrivilege': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwCallPrivilege"]),
        #
        'lineSetCallQualityOfService': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lpSendingFlowspec", "dwSendingFlowspecSize", "lpReceivingFlowspec", "dwReceivingFlowspecSize"]),
        #
        'lineSetCallTreatment': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwTreatment"]),
        #
        'lineSetCurrentLocation': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwLocation"]),
        #
        'lineSetDevConfig': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpDeviceConfig", "dwSize", "lpszDeviceClass"]),
        #
        'lineSetDevConfigA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpDeviceConfig", "dwSize", "lpszDeviceClass"]),
        #
        'lineSetDevConfigW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpDeviceConfig", "dwSize", "lpszDeviceClass"]),
        #
        'lineSetLineDevStatus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwStatusToChange", "fStatus"]),
        #
        'lineSetMediaControl': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEMEDIACONTROLDIGIT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEMEDIACONTROLMEDIA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEMEDIACONTROLTONE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINEMEDIACONTROLCALLSTATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "hCall", "dwSelect", "lpDigitList", "dwDigitNumEntries", "lpMediaList", "dwMediaNumEntries", "lpToneList", "dwToneNumEntries", "lpCallStateList", "dwCallStateNumEntries"]),
        #
        'lineSetMediaMode': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "dwMediaModes"]),
        #
        'lineSetQueueMeasurementPeriod': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwQueueID", "dwMeasurementPeriod"]),
        #
        'lineSetNumRings': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "dwNumRings"]),
        #
        'lineSetStatusMessages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwLineStates", "dwAddressStates"]),
        #
        'lineSetTerminal': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "hCall", "dwSelect", "dwTerminalModes", "dwTerminalID", "bEnable"]),
        #
        'lineSetTollList': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "lpszAddressIn", "dwTollListOption"]),
        #
        'lineSetTollListA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "lpszAddressIn", "dwTollListOption"]),
        #
        'lineSetTollListW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "lpszAddressInW", "dwTollListOption"]),
        #
        'lineSetupConference': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "hLine", "lphConfCall", "lphConsultCall", "dwNumParties", "lpCallParams"]),
        #
        'lineSetupConferenceA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "hLine", "lphConfCall", "lphConsultCall", "dwNumParties", "lpCallParams"]),
        #
        'lineSetupConferenceW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "hLine", "lphConfCall", "lphConsultCall", "dwNumParties", "lpCallParams"]),
        #
        'lineSetupTransfer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lphConsultCall", "lpCallParams"]),
        #
        'lineSetupTransferA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lphConsultCall", "lpCallParams"]),
        #
        'lineSetupTransferW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("LINECALLPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall", "lphConsultCall", "lpCallParams"]),
        #
        'lineShutdown': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp"]),
        #
        'lineSwapHold': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hActiveCall", "hHeldCall"]),
        #
        'lineTranslateAddress': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINETRANSLATEOUTPUT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPIVersion", "lpszAddressIn", "dwCard", "dwTranslateOptions", "lpTranslateOutput"]),
        #
        'lineTranslateAddressA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINETRANSLATEOUTPUT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPIVersion", "lpszAddressIn", "dwCard", "dwTranslateOptions", "lpTranslateOutput"]),
        #
        'lineTranslateAddressW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("LINETRANSLATEOUTPUT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPIVersion", "lpszAddressIn", "dwCard", "dwTranslateOptions", "lpTranslateOutput"]),
        #
        'lineTranslateDialog': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPIVersion", "hwndOwner", "lpszAddressIn"]),
        #
        'lineTranslateDialogA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPIVersion", "hwndOwner", "lpszAddressIn"]),
        #
        'lineTranslateDialogW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLineApp", "dwDeviceID", "dwAPIVersion", "hwndOwner", "lpszAddressIn"]),
        #
        'lineUncompleteCall': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwCompletionID"]),
        #
        'lineUnhold': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCall"]),
        #
        'lineUnpark': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lphCall", "lpszDestAddress"]),
        #
        'lineUnparkA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lphCall", "lpszDestAddress"]),
        #
        'lineUnparkW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLine", "dwAddressID", "lphCall", "lpszDestAddress"]),
        #
        'phoneClose': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone"]),
        #
        'phoneConfigDialog': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "hwndOwner", "lpszDeviceClass"]),
        #
        'phoneConfigDialogA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "hwndOwner", "lpszDeviceClass"]),
        #
        'phoneConfigDialogW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "hwndOwner", "lpszDeviceClass"]),
        #
        'phoneDevSpecific': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpParams", "dwSize"]),
        #
        'phoneGetButtonInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONEBUTTONINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwButtonLampID", "lpButtonInfo"]),
        #
        'phoneGetButtonInfoA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONEBUTTONINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwButtonLampID", "lpButtonInfo"]),
        #
        'phoneGetButtonInfoW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONEBUTTONINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwButtonLampID", "lpButtonInfo"]),
        #
        'phoneGetData': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwDataID", "lpData", "dwSize"]),
        #
        'phoneGetDevCaps': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONECAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhoneApp", "dwDeviceID", "dwAPIVersion", "dwExtVersion", "lpPhoneCaps"]),
        #
        'phoneGetDevCapsA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONECAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhoneApp", "dwDeviceID", "dwAPIVersion", "dwExtVersion", "lpPhoneCaps"]),
        #
        'phoneGetDevCapsW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONECAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhoneApp", "dwDeviceID", "dwAPIVersion", "dwExtVersion", "lpPhoneCaps"]),
        #
        'phoneGetDisplay': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpDisplay"]),
        #
        'phoneGetGain': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwHookSwitchDev", "lpdwGain"]),
        #
        'phoneGetHookSwitch': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpdwHookSwitchDevs"]),
        #
        'phoneGetIcon': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpszDeviceClass", "lphIcon"]),
        #
        'phoneGetIconA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpszDeviceClass", "lphIcon"]),
        #
        'phoneGetIconW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwDeviceID", "lpszDeviceClass", "lphIcon"]),
        #
        'phoneGetID': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpDeviceID", "lpszDeviceClass"]),
        #
        'phoneGetIDA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpDeviceID", "lpszDeviceClass"]),
        #
        'phoneGetIDW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("VARSTRING", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpDeviceID", "lpszDeviceClass"]),
        #
        'phoneGetLamp': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwButtonLampID", "lpdwLampMode"]),
        #
        'phoneGetMessage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONEMESSAGE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhoneApp", "lpMessage", "dwTimeout"]),
        #
        'phoneGetRing': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpdwRingMode", "lpdwVolume"]),
        #
        'phoneGetStatus': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONESTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpPhoneStatus"]),
        #
        'phoneGetStatusA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONESTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpPhoneStatus"]),
        #
        'phoneGetStatusW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONESTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpPhoneStatus"]),
        #
        'phoneGetStatusMessages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "lpdwPhoneStates", "lpdwButtonModes", "lpdwButtonStates"]),
        #
        'phoneGetVolume': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwHookSwitchDev", "lpdwVolume"]),
        #
        'phoneInitialize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevice", "dwMessage", "dwInstance", "dwParam1", "dwParam2", "dwParam3"]), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lphPhoneApp", "hInstance", "lpfnCallback", "lpszAppName", "lpdwNumDevs"]),
        #
        'phoneInitializeExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevice", "dwMessage", "dwInstance", "dwParam1", "dwParam2", "dwParam3"]), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PHONEINITIALIZEEXPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lphPhoneApp", "hInstance", "lpfnCallback", "lpszFriendlyAppName", "lpdwNumDevs", "lpdwAPIVersion", "lpPhoneInitializeExParams"]),
        #
        'phoneInitializeExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hDevice", "dwMessage", "dwInstance", "dwParam1", "dwParam2", "dwParam3"]), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PHONEINITIALIZEEXPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lphPhoneApp", "hInstance", "lpfnCallback", "lpszFriendlyAppName", "lpdwNumDevs", "lpdwAPIVersion", "lpPhoneInitializeExParams"]),
        #
        'phoneNegotiateAPIVersion': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PHONEEXTENSIONID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhoneApp", "dwDeviceID", "dwAPILowVersion", "dwAPIHighVersion", "lpdwAPIVersion", "lpExtensionID"]),
        #
        'phoneNegotiateExtVersion': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhoneApp", "dwDeviceID", "dwAPIVersion", "dwExtLowVersion", "dwExtHighVersion", "lpdwExtVersion"]),
        #
        'phoneOpen': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhoneApp", "dwDeviceID", "lphPhone", "dwAPIVersion", "dwExtVersion", "dwCallbackInstance", "dwPrivilege"]),
        #
        'phoneSetButtonInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONEBUTTONINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwButtonLampID", "lpButtonInfo"]),
        #
        'phoneSetButtonInfoA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONEBUTTONINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwButtonLampID", "lpButtonInfo"]),
        #
        'phoneSetButtonInfoW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PHONEBUTTONINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwButtonLampID", "lpButtonInfo"]),
        #
        'phoneSetData': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwDataID", "lpData", "dwSize"]),
        #
        'phoneSetDisplay': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwRow", "dwColumn", "lpsDisplay", "dwSize"]),
        #
        'phoneSetGain': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwHookSwitchDev", "dwGain"]),
        #
        'phoneSetHookSwitch': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwHookSwitchDevs", "dwHookSwitchMode"]),
        #
        'phoneSetLamp': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwButtonLampID", "dwLampMode"]),
        #
        'phoneSetRing': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwRingMode", "dwVolume"]),
        #
        'phoneSetStatusMessages': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwPhoneStates", "dwButtonModes", "dwButtonStates"]),
        #
        'phoneSetVolume': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhone", "dwHookSwitchDev", "dwVolume"]),
        #
        'phoneShutdown': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hPhoneApp"]),
        #
        'tapiGetLocationInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszCountryCode", "lpszCityCode"]),
        #
        'tapiGetLocationInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszCountryCode", "lpszCityCode"]),
        #
        'tapiGetLocationInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszCountryCodeW", "lpszCityCodeW"]),
        #
        'tapiRequestDrop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "wRequestID"]),
        #
        'tapiRequestMakeCall': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszDestAddress", "lpszAppName", "lpszCalledParty", "lpszComment"]),
        #
        'tapiRequestMakeCallA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszDestAddress", "lpszAppName", "lpszCalledParty", "lpszComment"]),
        #
        'tapiRequestMakeCallW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszDestAddress", "lpszAppName", "lpszCalledParty", "lpszComment"]),
        #
        'tapiRequestMediaCall': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "wRequestID", "lpszDeviceClass", "lpDeviceID", "dwSize", "dwSecure", "lpszDestAddress", "lpszAppName", "lpszCalledParty", "lpszComment"]),
        #
        'tapiRequestMediaCallA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "wRequestID", "lpszDeviceClass", "lpDeviceID", "dwSize", "dwSecure", "lpszDestAddress", "lpszAppName", "lpszCalledParty", "lpszComment"]),
        #
        'tapiRequestMediaCallW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "wRequestID", "lpszDeviceClass", "lpDeviceID", "dwSize", "dwSecure", "lpszDestAddress", "lpszAppName", "lpszCalledParty", "lpszComment"]),
    }

lib.set_prototypes(prototypes)
