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
lib.set_library_names("icmui.dll")
prototypes = \
    {
        #
        'SetupColorMatchingW': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwVersion": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hwndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "pSourceName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pDisplayName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pPrinterName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwRenderIntent": SimTypeInt(signed=False, label="UInt32"), "dwProofingIntent": SimTypeInt(signed=False, label="UInt32"), "pMonitorProfile": SimTypePointer(SimTypeChar(label="Char"), offset=0), "ccMonitorProfile": SimTypeInt(signed=False, label="UInt32"), "pPrinterProfile": SimTypePointer(SimTypeChar(label="Char"), offset=0), "ccPrinterProfile": SimTypeInt(signed=False, label="UInt32"), "pTargetProfile": SimTypePointer(SimTypeChar(label="Char"), offset=0), "ccTargetProfile": SimTypeInt(signed=False, label="UInt32"), "lpfnHook": SimTypeBottom(label="DLGPROC"), "lParam": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpfnApplyCallback": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="COLORMATCHSETUPW"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), "lParamApplyCallback": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="COLORMATCHSETUPW", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcms"]),
        #
        'SetupColorMatchingA': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwVersion": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "hwndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "pSourceName": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pDisplayName": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pPrinterName": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "dwRenderIntent": SimTypeInt(signed=False, label="UInt32"), "dwProofingIntent": SimTypeInt(signed=False, label="UInt32"), "pMonitorProfile": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "ccMonitorProfile": SimTypeInt(signed=False, label="UInt32"), "pPrinterProfile": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "ccPrinterProfile": SimTypeInt(signed=False, label="UInt32"), "pTargetProfile": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "ccTargetProfile": SimTypeInt(signed=False, label="UInt32"), "lpfnHook": SimTypeBottom(label="DLGPROC"), "lParam": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "lpfnApplyCallback": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="COLORMATCHSETUPA"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), "lParamApplyCallback": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="COLORMATCHSETUPA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcms"]),
    }

lib.set_prototypes(prototypes)
