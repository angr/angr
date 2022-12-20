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
lib.set_library_names("inkobjcore.dll")
prototypes = \
    {
        #
        'CreateRecognizer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCLSID", "phrec"]),
        #
        'DestroyRecognizer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrec"]),
        #
        'GetRecoAttributes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwRecoCapabilityFlags": SimTypeInt(signed=False, label="UInt32"), "awcVendorName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 32), "awcFriendlyName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 64), "awLanguageId": SimTypeFixedSizeArray(SimTypeShort(signed=False, label="UInt16"), 64)}, name="RECO_ATTRS", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrec", "pRecoAttrs"]),
        #
        'CreateContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrec", "phrc"]),
        #
        'DestroyContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc"]),
        #
        'GetResultPropertyList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrec", "pPropertyCount", "pPropertyGuid"]),
        #
        'GetUnicodeRanges': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimStruct({"wcLow": SimTypeChar(label="Char"), "cChars": SimTypeShort(signed=False, label="UInt16")}, name="CHARACTER_RANGE", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrec", "pcRanges", "pcr"]),
        #
        'AddStroke': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"cbPacketSize": SimTypeInt(signed=False, label="UInt32"), "cPacketProperties": SimTypeInt(signed=False, label="UInt32"), "pPacketProperties": SimTypePointer(SimStruct({"guid": SimTypeBottom(label="Guid"), "PropertyMetrics": SimStruct({"nLogicalMin": SimTypeInt(signed=True, label="Int32"), "nLogicalMax": SimTypeInt(signed=True, label="Int32"), "Units": SimTypeInt(signed=False, label="PROPERTY_UNITS"), "fResolution": SimTypeFloat(size=32)}, name="PROPERTY_METRICS", pack=False, align=None)}, name="PACKET_PROPERTY", pack=False, align=None), offset=0), "cButtons": SimTypeInt(signed=False, label="UInt32"), "pguidButtons": SimTypePointer(SimTypeBottom(label="Guid"), offset=0)}, name="PACKET_DESCRIPTION", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"eM11": SimTypeFloat(size=32), "eM12": SimTypeFloat(size=32), "eM21": SimTypeFloat(size=32), "eM22": SimTypeFloat(size=32), "eDx": SimTypeFloat(size=32), "eDy": SimTypeFloat(size=32)}, name="XFORM", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "pPacketDesc", "cbPacket", "pPacket", "pXForm"]),
        #
        'GetBestResultString': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "pcSize", "pwcBestResult"]),
        #
        'SetGuide': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"xOrigin": SimTypeInt(signed=True, label="Int32"), "yOrigin": SimTypeInt(signed=True, label="Int32"), "cxBox": SimTypeInt(signed=True, label="Int32"), "cyBox": SimTypeInt(signed=True, label="Int32"), "cxBase": SimTypeInt(signed=True, label="Int32"), "cyBase": SimTypeInt(signed=True, label="Int32"), "cHorzBox": SimTypeInt(signed=True, label="Int32"), "cVertBox": SimTypeInt(signed=True, label="Int32"), "cyMid": SimTypeInt(signed=True, label="Int32")}, name="RECO_GUIDE", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "pGuide", "iIndex"]),
        #
        'AdviseInkChange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "bNewStroke"]),
        #
        'EndInkInput': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc"]),
        #
        'Process': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "pbPartialProcessing"]),
        #
        'SetFactoid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "cwcFactoid", "pwcFactoid"]),
        #
        'SetFlags': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "dwFlags"]),
        #
        'GetLatticePtr': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimStruct({"ulColumnCount": SimTypeInt(signed=False, label="UInt32"), "pLatticeColumns": SimTypePointer(SimStruct({"key": SimTypeInt(signed=False, label="UInt32"), "cpProp": SimStruct({"cProperties": SimTypeInt(signed=False, label="UInt32"), "apProps": SimTypePointer(SimTypePointer(SimStruct({"guidProperty": SimTypeBottom(label="Guid"), "cbPropertyValue": SimTypeShort(signed=False, label="UInt16"), "pPropertyValue": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="RECO_LATTICE_PROPERTY", pack=False, align=None), offset=0), offset=0)}, name="RECO_LATTICE_PROPERTIES", pack=False, align=None), "cStrokes": SimTypeInt(signed=False, label="UInt32"), "pStrokes": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "cLatticeElements": SimTypeInt(signed=False, label="UInt32"), "pLatticeElements": SimTypePointer(SimStruct({"score": SimTypeInt(signed=True, label="Int32"), "type": SimTypeShort(signed=False, label="UInt16"), "pData": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "ulNextColumn": SimTypeInt(signed=False, label="UInt32"), "ulStrokeNumber": SimTypeInt(signed=False, label="UInt32"), "epProp": SimStruct({"cProperties": SimTypeInt(signed=False, label="UInt32"), "apProps": SimTypePointer(SimTypePointer(SimStruct({"guidProperty": SimTypeBottom(label="Guid"), "cbPropertyValue": SimTypeShort(signed=False, label="UInt16"), "pPropertyValue": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="RECO_LATTICE_PROPERTY", pack=False, align=None), offset=0), offset=0)}, name="RECO_LATTICE_PROPERTIES", pack=False, align=None)}, name="RECO_LATTICE_ELEMENT", pack=False, align=None), offset=0)}, name="RECO_LATTICE_COLUMN", pack=False, align=None), offset=0), "ulPropertyCount": SimTypeInt(signed=False, label="UInt32"), "pGuidProperties": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "ulBestResultColumnCount": SimTypeInt(signed=False, label="UInt32"), "pulBestResultColumns": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "pulBestResultIndexes": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="RECO_LATTICE", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "ppLattice"]),
        #
        'SetTextContext': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "cwcBefore", "pwcBefore", "cwcAfter", "pwcAfter"]),
        #
        'SetEnabledUnicodeRanges': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"wcLow": SimTypeChar(label="Char"), "cChars": SimTypeShort(signed=False, label="UInt16")}, name="CHARACTER_RANGE", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "cRanges", "pcr"]),
        #
        'IsStringSupported': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "wcString", "pwcString"]),
        #
        'SetWordList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "hwl"]),
        #
        'GetRightSeparator': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "pcSize", "pwcRightSeparator"]),
        #
        'GetLeftSeparator': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrc", "pcSize", "pwcLeftSeparator"]),
        #
        'DestroyWordList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwl"]),
        #
        'AddWordsToWordList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwl", "pwcWords"]),
        #
        'MakeWordList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hrec", "pBuffer", "phwl"]),
        #
        'GetAllRecognizers': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["recognizerClsids", "count"]),
        #
        'LoadCachedAttributes': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypePointer(SimStruct({"dwRecoCapabilityFlags": SimTypeInt(signed=False, label="UInt32"), "awcVendorName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 32), "awcFriendlyName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 64), "awLanguageId": SimTypeFixedSizeArray(SimTypeShort(signed=False, label="UInt16"), 64)}, name="RECO_ATTRS", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsid", "pRecoAttributes"]),
    }

lib.set_prototypes(prototypes)
