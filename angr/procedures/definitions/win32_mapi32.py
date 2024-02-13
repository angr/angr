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
lib.set_library_names("mapi32.dll")
prototypes = \
    {
        #
        'OpenTnefStream': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="IStream"), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMessage"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeBottom(label="ITnef"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpvSupport", "lpStream", "lpszStreamName", "ulFlags", "lpMessage", "wKeyVal", "lppTNEF"]),
        #
        'OpenTnefStreamEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="IStream"), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMessage"), SimTypeShort(signed=False, label="UInt16"), SimTypeBottom(label="IAddrBook"), SimTypePointer(SimTypeBottom(label="ITnef"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpvSupport", "lpStream", "lpszStreamName", "ulFlags", "lpMessage", "wKeyVal", "lpAdressBook", "lppTNEF"]),
        #
        'GetTnefStreamCodepage': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpStream", "lpulCodepage", "lpulSubCodepage"]),
        #
        'OpenIMsgSession': SimTypeFunction([SimTypeBottom(label="IMalloc"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMalloc", "ulFlags", "lppMsgSess"]),
        #
        'CloseIMsgSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["lpMsgSess"]),
        #
        'OpenIMsgOnIStg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lpObject", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer"]), offset=0), SimTypeBottom(label="IMalloc"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeBottom(label="IStorage"), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMessage")], SimTypeBottom(label="Void"), arg_names=["ulCallerData", "lpMessage"]), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMessage"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMsgSess", "lpAllocateBuffer", "lpAllocateMore", "lpFreeBuffer", "lpMalloc", "lpMapiSup", "lpStg", "lpfMsgCallRelease", "ulCallerData", "ulFlags", "lppMsg"]),
        #
        'GetAttribIMsgOnIStg': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SPropTagArray", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SPropAttrArray", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpObject", "lpPropTagArray", "lppPropAttrArray"]),
        #
        'SetAttribIMsgOnIStg': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SPropTagArray", SimStruct), offset=0), SimTypePointer(SimTypeRef("SPropAttrArray", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SPropProblemArray", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpObject", "lpPropTags", "lpPropAttrs", "lppPropProblems"]),
        #
        'MapStorageSCode': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["StgSCode"]),
        #
        'CreateIProp': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lpObject", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="IPropData"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpInterface", "lpAllocateBuffer", "lpAllocateMore", "lpFreeBuffer", "lpvReserved", "lppPropData"]),
        #
        'MAPIInitIdle': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpvReserved"]),
        #
        'MAPIDeinitIdle': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'FtgRegisterIdleRoutine': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=True, label="Int16"), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["lpfnIdle", "lpvIdleParam", "priIdle", "csecIdle", "iroIdle"]),
        #
        'DeregisterIdleRoutine': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["ftg"]),
        #
        'EnableIdleRoutine': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["ftg", "fEnable"]),
        #
        'ChangeIdleRoutine': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=True, label="Int16"), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16")], SimTypeBottom(label="Void"), arg_names=["ftg", "lpfnIdle", "lpvIdleParam", "priIdle", "csecIdle", "iroIdle", "ircIdle"]),
        #
        'MAPIGetDefaultMalloc': SimTypeFunction([], SimTypeBottom(label="IMalloc")),
        #
        'OpenStreamOnFile': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAllocateBuffer", "lpFreeBuffer", "ulFlags", "lpszFileName", "lpszPrefix", "lppStream"]),
        #
        'PropCopyMore': SimTypeFunction([SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lpObject", "lppBuffer"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSPropValueDest", "lpSPropValueSrc", "lpfAllocMore", "lpvObject"]),
        #
        'UlPropSize': SimTypeFunction([SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpSPropValue"]),
        #
        'FEqualNames': SimTypeFunction([SimTypePointer(SimTypeRef("MAPINAMEID", SimStruct), offset=0), SimTypePointer(SimTypeRef("MAPINAMEID", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpName1", "lpName2"]),
        #
        'FPropContainsProp': SimTypeFunction([SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSPropValueDst", "lpSPropValueSrc", "ulFuzzyLevel"]),
        #
        'FPropCompareProp': SimTypeFunction([SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSPropValue1", "ulRelOp", "lpSPropValue2"]),
        #
        'LPropCompareProp': SimTypeFunction([SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpSPropValueA", "lpSPropValueB"]),
        #
        'HrAddColumns': SimTypeFunction([SimTypeBottom(label="IMAPITable"), SimTypePointer(SimTypeRef("SPropTagArray", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lptbl", "lpproptagColumnsNew", "lpAllocateBuffer", "lpFreeBuffer"]),
        #
        'HrAddColumnsEx': SimTypeFunction([SimTypeBottom(label="IMAPITable"), SimTypePointer(SimTypeRef("SPropTagArray", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lptbl", "lpproptagColumnsNew", "lpAllocateBuffer", "lpFreeBuffer", "lpfnFilterColumns"]),
        #
        'HrAllocAdviseSink': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("NOTIFICATION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpvContext", "cNotification", "lpNotifications"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="IMAPIAdviseSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpfnCallback", "lpvContext", "lppAdviseSink"]),
        #
        'HrThisThreadAdviseSink': SimTypeFunction([SimTypeBottom(label="IMAPIAdviseSink"), SimTypePointer(SimTypeBottom(label="IMAPIAdviseSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAdviseSink", "lppAdviseSink"]),
        #
        'HrDispatchNotifications': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ulFlags"]),
        #
        'BuildDisplayTable': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lpObject", "lppBuffer"]), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpBuffer"]), offset=0), SimTypeBottom(label="IMalloc"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DTPAGE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMAPITable"), offset=0), SimTypePointer(SimTypeBottom(label="ITableData"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpAllocateBuffer", "lpAllocateMore", "lpFreeBuffer", "lpMalloc", "hInstance", "cPages", "lpPage", "ulFlags", "lppTable", "lppTblData"]),
        #
        'ScCountNotifications': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("NOTIFICATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cNotifications", "lpNotifications", "lpcb"]),
        #
        'ScCopyNotifications': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("NOTIFICATION", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cNotification", "lpNotifications", "lpvDst", "lpcb"]),
        #
        'ScRelocNotifications': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("NOTIFICATION", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cNotification", "lpNotifications", "lpvBaseOld", "lpvBaseNew", "lpcb"]),
        #
        'ScCountProps': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cValues", "lpPropArray", "lpcb"]),
        #
        'LpValFindProp': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0)], SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), arg_names=["ulPropTag", "cValues", "lpPropArray"]),
        #
        'ScCopyProps': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cValues", "lpPropArray", "lpvDst", "lpcb"]),
        #
        'ScRelocProps': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cValues", "lpPropArray", "lpvBaseOld", "lpvBaseNew", "lpcb"]),
        #
        'ScDupPropset': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbSize", "lppBuffer"]), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cValues", "lpPropArray", "lpAllocateBuffer", "lppPropArray"]),
        #
        'UlAddRef': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpunk"]),
        #
        'UlRelease': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpunk"]),
        #
        'HrGetOneProp': SimTypeFunction([SimTypeBottom(label="IMAPIProp"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMapiProp", "ulPropTag", "lppProp"]),
        #
        'HrSetOneProp': SimTypeFunction([SimTypeBottom(label="IMAPIProp"), SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMapiProp", "lpProp"]),
        #
        'FPropExists': SimTypeFunction([SimTypeBottom(label="IMAPIProp"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMapiProp", "ulPropTag"]),
        #
        'PpropFindProp': SimTypeFunction([SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("SPropValue", SimStruct), offset=0), arg_names=["lpPropArray", "cValues", "ulPropTag"]),
        #
        'FreePadrlist': SimTypeFunction([SimTypePointer(SimTypeRef("ADRLIST", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpAdrlist"]),
        #
        'FreeProws': SimTypeFunction([SimTypePointer(SimTypeRef("SRowSet", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpRows"]),
        #
        'HrQueryAllRows': SimTypeFunction([SimTypeBottom(label="IMAPITable"), SimTypePointer(SimTypeRef("SPropTagArray", SimStruct), offset=0), SimTypePointer(SimTypeRef("SRestriction", SimStruct), offset=0), SimTypePointer(SimTypeRef("SSortOrderSet", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("SRowSet", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpTable", "lpPropTags", "lpRestriction", "lpSortOrderSet", "crowsMax", "lppRows"]),
        #
        'SzFindCh': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeChar(label="SByte"), offset=0), arg_names=["lpsz", "ch"]),
        #
        'SzFindLastCh': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypePointer(SimTypeChar(label="SByte"), offset=0), arg_names=["lpsz", "ch"]),
        #
        'SzFindSz': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypePointer(SimTypeChar(label="SByte"), offset=0), arg_names=["lpsz", "lpszKey"]),
        #
        'UFromSz': SimTypeFunction([SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpsz"]),
        #
        'ScUNCFromLocalPath': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszLocal", "lpszUNC", "cchUNC"]),
        #
        'ScLocalPathFromUNC': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszUNC", "lpszLocal", "cchLocal"]),
        #
        'FtAddFt': SimTypeFunction([SimTypeRef("FILETIME", SimStruct), SimTypeRef("FILETIME", SimStruct)], SimTypeRef("FILETIME", SimStruct), arg_names=["ftAddend1", "ftAddend2"]),
        #
        'FtMulDwDw': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeRef("FILETIME", SimStruct), arg_names=["ftMultiplicand", "ftMultiplier"]),
        #
        'FtMulDw': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeRef("FILETIME", SimStruct)], SimTypeRef("FILETIME", SimStruct), arg_names=["ftMultiplier", "ftMultiplicand"]),
        #
        'FtSubFt': SimTypeFunction([SimTypeRef("FILETIME", SimStruct), SimTypeRef("FILETIME", SimStruct)], SimTypeRef("FILETIME", SimStruct), arg_names=["ftMinuend", "ftSubtrahend"]),
        #
        'FtNegFt': SimTypeFunction([SimTypeRef("FILETIME", SimStruct)], SimTypeRef("FILETIME", SimStruct), arg_names=["ft"]),
        #
        'ScCreateConversationIndex': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbParent", "lpbParent", "lpcbConvIndex", "lppbConvIndex"]),
        #
        'WrapStoreEntryID': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="SByte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("ENTRYID", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ENTRYID", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ulFlags", "lpszDLLName", "cbOrigEntry", "lpOrigEntry", "lpcbWrappedEntry", "lppWrappedEntry"]),
        #
        'RTFSync': SimTypeFunction([SimTypeBottom(label="IMessage"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpMessage", "ulFlags", "lpfMessageUpdated"]),
        #
        'WrapCompressedRTFStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCompressedRTFStream", "ulFlags", "lpUncompressedRTFStream"]),
        #
        'HrIStorageFromStream': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IStorage"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpUnkIn", "lpInterface", "ulFlags", "lppStorageOut"]),
        #
        'ScInitMapiUtil': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ulFlags"]),
        #
        'DeinitMapiUtil': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'MAPIFreeBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pv"]),
    }

lib.set_prototypes(prototypes)
