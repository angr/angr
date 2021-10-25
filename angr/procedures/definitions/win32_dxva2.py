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
lib.set_library_names("dxva2.dll")
prototypes = \
    {
        # 
        'GetNumberOfPhysicalMonitorsFromHMONITOR': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "pdwNumberOfPhysicalMonitors"]),
        # 
        'GetNumberOfPhysicalMonitorsFromIDirect3DDevice9': SimTypeFunction([SimTypeBottom(label="IDirect3DDevice9"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDirect3DDevice9", "pdwNumberOfPhysicalMonitors"]),
        # 
        'GetPhysicalMonitorsFromHMONITOR': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"hPhysicalMonitor": SimTypeBottom(label="HANDLE"), "szPhysicalMonitorDescription": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 128)}, name="PHYSICAL_MONITOR", pack=False, align=None), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "dwPhysicalMonitorArraySize", "pPhysicalMonitorArray"]),
        # 
        'GetPhysicalMonitorsFromIDirect3DDevice9': SimTypeFunction([SimTypeBottom(label="IDirect3DDevice9"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"hPhysicalMonitor": SimTypeBottom(label="HANDLE"), "szPhysicalMonitorDescription": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 128)}, name="PHYSICAL_MONITOR", pack=False, align=None), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDirect3DDevice9", "dwPhysicalMonitorArraySize", "pPhysicalMonitorArray"]),
        # 
        'DestroyPhysicalMonitor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor"]),
        # 
        'DestroyPhysicalMonitors': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"hPhysicalMonitor": SimTypeBottom(label="HANDLE"), "szPhysicalMonitorDescription": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 128)}, name="PHYSICAL_MONITOR", pack=False, align=None), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwPhysicalMonitorArraySize", "pPhysicalMonitorArray"]),
        # 
        'GetVCPFeatureAndVCPFeatureReply': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="MC_VCP_CODE_TYPE"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "bVCPCode", "pvct", "pdwCurrentValue", "pdwMaximumValue"]),
        # 
        'SetVCPFeature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "bVCPCode", "dwNewValue"]),
        # 
        'SaveCurrentSettings': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor"]),
        # 
        'GetCapabilitiesStringLength': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "pdwCapabilitiesStringLengthInCharacters"]),
        # 
        'CapabilitiesRequestAndCapabilitiesReply': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "pszASCIICapabilitiesString", "dwCapabilitiesStringLengthInCharacters"]),
        # 
        'GetTimingReport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwHorizontalFrequencyInHZ": SimTypeInt(signed=False, label="UInt32"), "dwVerticalFrequencyInHZ": SimTypeInt(signed=False, label="UInt32"), "bTimingStatusByte": SimTypeChar(label="Byte")}, name="MC_TIMING_REPORT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "pmtrMonitorTimingReport"]),
        # 
        'GetMonitorCapabilities': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "pdwMonitorCapabilities", "pdwSupportedColorTemperatures"]),
        # 
        'SaveCurrentMonitorSettings': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor"]),
        # 
        'GetMonitorTechnologyType': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MC_DISPLAY_TECHNOLOGY_TYPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "pdtyDisplayTechnologyType"]),
        # 
        'GetMonitorBrightness': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "pdwMinimumBrightness", "pdwCurrentBrightness", "pdwMaximumBrightness"]),
        # 
        'GetMonitorContrast': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "pdwMinimumContrast", "pdwCurrentContrast", "pdwMaximumContrast"]),
        # 
        'GetMonitorColorTemperature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="MC_COLOR_TEMPERATURE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "pctCurrentColorTemperature"]),
        # 
        'GetMonitorRedGreenOrBlueDrive': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MC_DRIVE_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "dtDriveType", "pdwMinimumDrive", "pdwCurrentDrive", "pdwMaximumDrive"]),
        # 
        'GetMonitorRedGreenOrBlueGain': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MC_GAIN_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "gtGainType", "pdwMinimumGain", "pdwCurrentGain", "pdwMaximumGain"]),
        # 
        'SetMonitorBrightness': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "dwNewBrightness"]),
        # 
        'SetMonitorContrast': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "dwNewContrast"]),
        # 
        'SetMonitorColorTemperature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MC_COLOR_TEMPERATURE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "ctCurrentColorTemperature"]),
        # 
        'SetMonitorRedGreenOrBlueDrive': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MC_DRIVE_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "dtDriveType", "dwNewDrive"]),
        # 
        'SetMonitorRedGreenOrBlueGain': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MC_GAIN_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "gtGainType", "dwNewGain"]),
        # 
        'DegaussMonitor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor"]),
        # 
        'GetMonitorDisplayAreaSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MC_SIZE_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "stSizeType", "pdwMinimumWidthOrHeight", "pdwCurrentWidthOrHeight", "pdwMaximumWidthOrHeight"]),
        # 
        'GetMonitorDisplayAreaPosition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MC_POSITION_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "ptPositionType", "pdwMinimumPosition", "pdwCurrentPosition", "pdwMaximumPosition"]),
        # 
        'SetMonitorDisplayAreaSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MC_SIZE_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "stSizeType", "dwNewDisplayAreaWidthOrHeight"]),
        # 
        'SetMonitorDisplayAreaPosition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="MC_POSITION_TYPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "ptPositionType", "dwNewPosition"]),
        # 
        'RestoreMonitorFactoryColorDefaults': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor"]),
        # 
        'RestoreMonitorFactoryDefaults': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor"]),
        # 
        'DXVAHD_CreateDevice': SimTypeFunction([SimTypeBottom(label="IDirect3DDevice9Ex"), SimTypePointer(SimStruct({"InputFrameFormat": SimTypeInt(signed=False, label="DXVAHD_FRAME_FORMAT"), "InputFrameRate": SimStruct({"Numerator": SimTypeInt(signed=False, label="UInt32"), "Denominator": SimTypeInt(signed=False, label="UInt32")}, name="DXVAHD_RATIONAL", pack=False, align=None), "InputWidth": SimTypeInt(signed=False, label="UInt32"), "InputHeight": SimTypeInt(signed=False, label="UInt32"), "OutputFrameRate": SimStruct({"Numerator": SimTypeInt(signed=False, label="UInt32"), "Denominator": SimTypeInt(signed=False, label="UInt32")}, name="DXVAHD_RATIONAL", pack=False, align=None), "OutputWidth": SimTypeInt(signed=False, label="UInt32"), "OutputHeight": SimTypeInt(signed=False, label="UInt32")}, name="DXVAHD_CONTENT_DESC", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="DXVAHD_DEVICE_USAGE"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Size", "pCallbacks"]), offset=0), SimTypePointer(SimTypeBottom(label="IDXVAHD_Device"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pD3DDevice", "pContentDesc", "Usage", "pPlugin", "ppDevice"]),
        # 
        'DXVA2CreateDirect3DDeviceManager9': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="IDirect3DDeviceManager9"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pResetToken", "ppDeviceManager"]),
        # 
        'DXVA2CreateVideoService': SimTypeFunction([SimTypeBottom(label="IDirect3DDevice9"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDD", "riid", "ppService"]),
        # 
        'OPMGetVideoOutputsFromHMONITOR': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="OPM_VIDEO_OUTPUT_SEMANTICS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="IOPMVideoOutput"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hMonitor", "vos", "pulNumVideoOutputs", "pppOPMVideoOutputArray"]),
        # 
        'OPMGetVideoOutputForTarget': SimTypeFunction([SimTypePointer(SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=True, label="Int32")}, name="LUID", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="OPM_VIDEO_OUTPUT_SEMANTICS"), SimTypePointer(SimTypeBottom(label="IOPMVideoOutput"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapterLuid", "VidPnTarget", "vos", "ppOPMVideoOutput"]),
        # 
        'OPMGetVideoOutputsFromIDirect3DDevice9Object': SimTypeFunction([SimTypeBottom(label="IDirect3DDevice9"), SimTypeInt(signed=False, label="OPM_VIDEO_OUTPUT_SEMANTICS"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="IOPMVideoOutput"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDirect3DDevice9", "vos", "pulNumVideoOutputs", "pppOPMVideoOutputArray"]),
    }

lib.set_prototypes(prototypes)
