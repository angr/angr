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
lib.set_library_names("winscard.dll")
prototypes = \
    {
        # 
        'SCardEstablishContext': SimTypeFunction([SimTypeInt(signed=False, label="SCARD_SCOPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwScope", "pvReserved1", "pvReserved2", "phContext"]),
        # 
        'SCardReleaseContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext"]),
        # 
        'SCardIsValidContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext"]),
        # 
        'SCardListReaderGroupsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "mszGroups", "pcchGroups"]),
        # 
        'SCardListReaderGroupsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "mszGroups", "pcchGroups"]),
        # 
        'SCardListReadersA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "mszGroups", "mszReaders", "pcchReaders"]),
        # 
        'SCardListReadersW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "mszGroups", "mszReaders", "pcchReaders"]),
        # 
        'SCardListCardsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "pbAtr", "rgquidInterfaces", "cguidInterfaceCount", "mszCards", "pcchCards"]),
        # 
        'SCardListCardsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "pbAtr", "rgquidInterfaces", "cguidInterfaceCount", "mszCards", "pcchCards"]),
        # 
        'SCardListInterfacesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCard", "pguidInterfaces", "pcguidInterfaces"]),
        # 
        'SCardListInterfacesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCard", "pguidInterfaces", "pcguidInterfaces"]),
        # 
        'SCardGetProviderIdA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCard", "pguidProviderId"]),
        # 
        'SCardGetProviderIdW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCard", "pguidProviderId"]),
        # 
        'SCardGetCardTypeProviderNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCardName", "dwProviderId", "szProvider", "pcchProvider"]),
        # 
        'SCardGetCardTypeProviderNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCardName", "dwProviderId", "szProvider", "pcchProvider"]),
        # 
        'SCardIntroduceReaderGroupA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szGroupName"]),
        # 
        'SCardIntroduceReaderGroupW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szGroupName"]),
        # 
        'SCardForgetReaderGroupA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szGroupName"]),
        # 
        'SCardForgetReaderGroupW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szGroupName"]),
        # 
        'SCardIntroduceReaderA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "szDeviceName"]),
        # 
        'SCardIntroduceReaderW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "szDeviceName"]),
        # 
        'SCardForgetReaderA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName"]),
        # 
        'SCardForgetReaderW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName"]),
        # 
        'SCardAddReaderToGroupA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "szGroupName"]),
        # 
        'SCardAddReaderToGroupW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "szGroupName"]),
        # 
        'SCardRemoveReaderFromGroupA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "szGroupName"]),
        # 
        'SCardRemoveReaderFromGroupW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "szGroupName"]),
        # 
        'SCardIntroduceCardTypeA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCardName", "pguidPrimaryProvider", "rgguidInterfaces", "dwInterfaceCount", "pbAtr", "pbAtrMask", "cbAtrLen"]),
        # 
        'SCardIntroduceCardTypeW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCardName", "pguidPrimaryProvider", "rgguidInterfaces", "dwInterfaceCount", "pbAtr", "pbAtrMask", "cbAtrLen"]),
        # 
        'SCardSetCardTypeProviderNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCardName", "dwProviderId", "szProvider"]),
        # 
        'SCardSetCardTypeProviderNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCardName", "dwProviderId", "szProvider"]),
        # 
        'SCardForgetCardTypeA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCardName"]),
        # 
        'SCardForgetCardTypeW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szCardName"]),
        # 
        'SCardFreeMemory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "pvMem"]),
        # 
        'SCardAccessStartedEvent': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        # 
        'SCardReleaseStartedEvent': SimTypeFunction([], SimTypeBottom(label="Void")),
        # 
        'SCardLocateCardsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"szReader": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwCurrentState": SimTypeInt(signed=False, label="SCARD_STATE"), "dwEventState": SimTypeInt(signed=False, label="SCARD_STATE"), "cbAtr": SimTypeInt(signed=False, label="UInt32"), "rgbAtr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 36)}, name="SCARD_READERSTATEA", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "mszCards", "rgReaderStates", "cReaders"]),
        # 
        'SCardLocateCardsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"szReader": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwCurrentState": SimTypeInt(signed=False, label="SCARD_STATE"), "dwEventState": SimTypeInt(signed=False, label="SCARD_STATE"), "cbAtr": SimTypeInt(signed=False, label="UInt32"), "rgbAtr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 36)}, name="SCARD_READERSTATEW", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "mszCards", "rgReaderStates", "cReaders"]),
        # 
        'SCardLocateCardsByATRA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimStruct({"cbAtr": SimTypeInt(signed=False, label="UInt32"), "rgbAtr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 36), "rgbMask": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 36)}, name="SCARD_ATRMASK", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"szReader": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwCurrentState": SimTypeInt(signed=False, label="SCARD_STATE"), "dwEventState": SimTypeInt(signed=False, label="SCARD_STATE"), "cbAtr": SimTypeInt(signed=False, label="UInt32"), "rgbAtr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 36)}, name="SCARD_READERSTATEA", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "rgAtrMasks", "cAtrs", "rgReaderStates", "cReaders"]),
        # 
        'SCardLocateCardsByATRW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimStruct({"cbAtr": SimTypeInt(signed=False, label="UInt32"), "rgbAtr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 36), "rgbMask": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 36)}, name="SCARD_ATRMASK", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"szReader": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwCurrentState": SimTypeInt(signed=False, label="SCARD_STATE"), "dwEventState": SimTypeInt(signed=False, label="SCARD_STATE"), "cbAtr": SimTypeInt(signed=False, label="UInt32"), "rgbAtr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 36)}, name="SCARD_READERSTATEW", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "rgAtrMasks", "cAtrs", "rgReaderStates", "cReaders"]),
        # 
        'SCardGetStatusChangeA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"szReader": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwCurrentState": SimTypeInt(signed=False, label="SCARD_STATE"), "dwEventState": SimTypeInt(signed=False, label="SCARD_STATE"), "cbAtr": SimTypeInt(signed=False, label="UInt32"), "rgbAtr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 36)}, name="SCARD_READERSTATEA", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "dwTimeout", "rgReaderStates", "cReaders"]),
        # 
        'SCardGetStatusChangeW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"szReader": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pvUserData": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "dwCurrentState": SimTypeInt(signed=False, label="SCARD_STATE"), "dwEventState": SimTypeInt(signed=False, label="SCARD_STATE"), "cbAtr": SimTypeInt(signed=False, label="UInt32"), "rgbAtr": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 36)}, name="SCARD_READERSTATEW", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "dwTimeout", "rgReaderStates", "cReaders"]),
        # 
        'SCardCancel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext"]),
        # 
        'SCardConnectA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReader", "dwShareMode", "dwPreferredProtocols", "phCard", "pdwActiveProtocol"]),
        # 
        'SCardConnectW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReader", "dwShareMode", "dwPreferredProtocols", "phCard", "pdwActiveProtocol"]),
        # 
        'SCardReconnect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "dwShareMode", "dwPreferredProtocols", "dwInitialization", "pdwActiveProtocol"]),
        # 
        'SCardDisconnect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "dwDisposition"]),
        # 
        'SCardBeginTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard"]),
        # 
        'SCardEndTransaction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "dwDisposition"]),
        # 
        'SCardState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "pdwState", "pdwProtocol", "pbAtr", "pcbAtrLen"]),
        # 
        'SCardStatusA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "mszReaderNames", "pcchReaderLen", "pdwState", "pdwProtocol", "pbAtr", "pcbAtrLen"]),
        # 
        'SCardStatusW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "mszReaderNames", "pcchReaderLen", "pdwState", "pdwProtocol", "pbAtr", "pcbAtrLen"]),
        # 
        'SCardTransmit': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimStruct({"dwProtocol": SimTypeInt(signed=False, label="UInt32"), "cbPciLength": SimTypeInt(signed=False, label="UInt32")}, name="SCARD_IO_REQUEST", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"dwProtocol": SimTypeInt(signed=False, label="UInt32"), "cbPciLength": SimTypeInt(signed=False, label="UInt32")}, name="SCARD_IO_REQUEST", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "pioSendPci", "pbSendBuffer", "cbSendLength", "pioRecvPci", "pbRecvBuffer", "pcbRecvLength"]),
        # 
        'SCardGetTransmitCount': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "pcTransmitCount"]),
        # 
        'SCardControl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "dwControlCode", "lpInBuffer", "cbInBufferSize", "lpOutBuffer", "cbOutBufferSize", "lpBytesReturned"]),
        # 
        'SCardGetAttrib': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "dwAttrId", "pbAttr", "pcbAttrLen"]),
        # 
        'SCardSetAttrib': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hCard", "dwAttrId", "pbAttr", "cbAttrLen"]),
        # 
        'SCardReadCacheA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "CardIdentifier", "FreshnessCounter", "LookupName", "Data", "DataLen"]),
        # 
        'SCardReadCacheW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "CardIdentifier", "FreshnessCounter", "LookupName", "Data", "DataLen"]),
        # 
        'SCardWriteCacheA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "CardIdentifier", "FreshnessCounter", "LookupName", "Data", "DataLen"]),
        # 
        'SCardWriteCacheW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "CardIdentifier", "FreshnessCounter", "LookupName", "Data", "DataLen"]),
        # 
        'SCardGetReaderIconA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "pbIcon", "pcbIcon"]),
        # 
        'SCardGetReaderIconW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "pbIcon", "pcbIcon"]),
        # 
        'SCardGetDeviceTypeIdA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "pdwDeviceTypeId"]),
        # 
        'SCardGetDeviceTypeIdW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "pdwDeviceTypeId"]),
        # 
        'SCardGetReaderDeviceInstanceIdA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "szDeviceInstanceId", "pcchDeviceInstanceId"]),
        # 
        'SCardGetReaderDeviceInstanceIdW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szReaderName", "szDeviceInstanceId", "pcchDeviceInstanceId"]),
        # 
        'SCardListReadersWithDeviceInstanceIdA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szDeviceInstanceId", "mszReaders", "pcchReaders"]),
        # 
        'SCardListReadersWithDeviceInstanceIdW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "szDeviceInstanceId", "mszReaders", "pcchReaders"]),
        # 
        'SCardAudit': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hContext", "dwEvent"]),
    }

lib.set_prototypes(prototypes)
