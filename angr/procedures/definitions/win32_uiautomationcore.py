# pylint:disable=line-too-long
from __future__ import annotations
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
lib.set_library_names("uiautomationcore.dll")
prototypes = \
    {
        #
        'UiaGetErrorDescription': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDescription"]),
        #
        'UiaHUiaNodeFromVariant': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvar", "phnode"]),
        #
        'UiaHPatternObjectFromVariant': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvar", "phobj"]),
        #
        'UiaHTextRangeFromVariant': SimTypeFunction([SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pvar", "phtextrange"]),
        #
        'UiaNodeRelease': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hnode"]),
        #
        'UiaGetPropertyValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hnode", "propertyId", "pValue"]),
        #
        'UiaGetPatternProvider': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hnode", "patternId", "phobj"]),
        #
        'UiaGetRuntimeId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hnode", "pruntimeId"]),
        #
        'UiaSetFocus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hnode"]),
        #
        'UiaNavigate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="NavigateDirection"), SimTypePointer(SimTypeRef("UiaCondition", SimStruct), offset=0), SimTypePointer(SimTypeRef("UiaCacheRequest", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hnode", "direction", "pCondition", "pRequest", "ppRequestedData", "ppTreeStructure"]),
        #
        'UiaGetUpdatedCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UiaCacheRequest", SimStruct), offset=0), SimTypeInt(signed=False, label="NormalizeState"), SimTypePointer(SimTypeRef("UiaCondition", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hnode", "pRequest", "normalizeState", "pNormalizeCondition", "ppRequestedData", "ppTreeStructure"]),
        #
        'UiaFind': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("UiaFindParams", SimStruct), offset=0), SimTypePointer(SimTypeRef("UiaCacheRequest", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hnode", "pParams", "pRequest", "ppRequestedData", "ppOffsets", "ppTreeStructures"]),
        #
        'UiaNodeFromPoint': SimTypeFunction([SimTypeFloat(size=64), SimTypeFloat(size=64), SimTypePointer(SimTypeRef("UiaCacheRequest", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["x", "y", "pRequest", "ppRequestedData", "ppTreeStructure"]),
        #
        'UiaNodeFromFocus': SimTypeFunction([SimTypePointer(SimTypeRef("UiaCacheRequest", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRequest", "ppRequestedData", "ppTreeStructure"]),
        #
        'UiaNodeFromHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "phnode"]),
        #
        'UiaNodeFromProvider': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProvider", "phnode"]),
        #
        'UiaGetRootNode': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phnode"]),
        #
        'UiaRegisterProviderCallback': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ProviderType")], SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), arg_names=["hwnd", "providerType"]), offset=0), offset=0)], SimTypeBottom(label="Void"), arg_names=["pCallback"]),
        #
        'UiaLookupId': SimTypeFunction([SimTypeInt(signed=False, label="AutomationIdentifierType"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["type", "pGuid"]),
        #
        'UiaGetReservedNotSupportedValue': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkNotSupportedValue"]),
        #
        'UiaGetReservedMixedAttributeValue': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkMixedAttributeValue"]),
        #
        'UiaClientsAreListening': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'UiaRaiseAutomationPropertyChangedEvent': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple"), SimTypeInt(signed=False, label="UIA_PROPERTY_ID"), SimTypeRef("VARIANT", SimStruct), SimTypeRef("VARIANT", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProvider", "id", "oldValue", "newValue"]),
        #
        'UiaRaiseAutomationEvent': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple"), SimTypeInt(signed=False, label="UIA_EVENT_ID")], SimTypeInt(signed=True, label="Int32"), arg_names=["pProvider", "id"]),
        #
        'UiaRaiseStructureChangedEvent': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple"), SimTypeInt(signed=False, label="StructureChangeType"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pProvider", "structureChangeType", "pRuntimeId", "cRuntimeIdLen"]),
        #
        'UiaRaiseAsyncContentLoadedEvent': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple"), SimTypeInt(signed=False, label="AsyncContentLoadedState"), SimTypeFloat(size=64)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProvider", "asyncContentLoadedState", "percentComplete"]),
        #
        'UiaRaiseTextEditTextChangedEvent': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple"), SimTypeInt(signed=False, label="TextEditChangeType"), SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProvider", "textEditChangeType", "pChangedData"]),
        #
        'UiaRaiseChangesEvent': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UiaChangeInfo", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProvider", "eventIdCount", "pUiaChanges"]),
        #
        'UiaRaiseNotificationEvent': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple"), SimTypeInt(signed=False, label="NotificationKind"), SimTypeInt(signed=False, label="NotificationProcessing"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["provider", "notificationKind", "notificationProcessing", "displayString", "activityId"]),
        #
        'UiaRaiseActiveTextPositionChangedEvent': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple"), SimTypeBottom(label="ITextRangeProvider")], SimTypeInt(signed=True, label="Int32"), arg_names=["provider", "textRange"]),
        #
        'UiaAddEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("UiaEventArgs", SimStruct), offset=0), SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pArgs", "pRequestedData", "pTreeStructure"]), offset=0), offset=0), SimTypeInt(signed=False, label="TreeScope"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("UiaCacheRequest", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hnode", "eventId", "pCallback", "scope", "pProperties", "cProperties", "pRequest", "phEvent"]),
        #
        'UiaRemoveEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent"]),
        #
        'UiaEventAddWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent", "hwnd"]),
        #
        'UiaEventRemoveWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent", "hwnd"]),
        #
        'DockPattern_SetDockPosition': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="DockPosition")], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "dockPosition"]),
        #
        'ExpandCollapsePattern_Collapse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'ExpandCollapsePattern_Expand': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'GridPattern_GetItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "row", "column", "pResult"]),
        #
        'InvokePattern_Invoke': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'MultipleViewPattern_GetViewName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "viewId", "ppStr"]),
        #
        'MultipleViewPattern_SetCurrentView': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "viewId"]),
        #
        'RangeValuePattern_SetValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeFloat(size=64)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "val"]),
        #
        'ScrollItemPattern_ScrollIntoView': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'ScrollPattern_Scroll': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="ScrollAmount"), SimTypeInt(signed=False, label="ScrollAmount")], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "horizontalAmount", "verticalAmount"]),
        #
        'ScrollPattern_SetScrollPercent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "horizontalPercent", "verticalPercent"]),
        #
        'SelectionItemPattern_AddToSelection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'SelectionItemPattern_RemoveFromSelection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'SelectionItemPattern_Select': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'TogglePattern_Toggle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'TransformPattern_Move': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "x", "y"]),
        #
        'TransformPattern_Resize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeFloat(size=64), SimTypeFloat(size=64)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "width", "height"]),
        #
        'TransformPattern_Rotate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeFloat(size=64)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "degrees"]),
        #
        'ValuePattern_SetValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "pVal"]),
        #
        'WindowPattern_Close': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'WindowPattern_SetWindowVisualState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="WindowVisualState")], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "state"]),
        #
        'WindowPattern_WaitForInputIdle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "milliseconds", "pResult"]),
        #
        'TextPattern_GetSelection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "pRetVal"]),
        #
        'TextPattern_GetVisibleRanges': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "pRetVal"]),
        #
        'TextPattern_RangeFromChild': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "hnodeChild", "pRetVal"]),
        #
        'TextPattern_RangeFromPoint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("UiaPoint", SimStruct), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "point", "pRetVal"]),
        #
        'TextPattern_get_DocumentRange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "pRetVal"]),
        #
        'TextPattern_get_SupportedTextSelection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="SupportedTextSelection"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "pRetVal"]),
        #
        'TextRange_Clone': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "pRetVal"]),
        #
        'TextRange_Compare': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "range", "pRetVal"]),
        #
        'TextRange_CompareEndpoints': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TextPatternRangeEndpoint"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TextPatternRangeEndpoint"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "endpoint", "targetRange", "targetEndpoint", "pRetVal"]),
        #
        'TextRange_ExpandToEnclosingUnit': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TextUnit")], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "unit"]),
        #
        'TextRange_GetAttributeValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "attributeId", "pRetVal"]),
        #
        'TextRange_FindAttribute': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeRef("VARIANT", SimStruct), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "attributeId", "val", "backward", "pRetVal"]),
        #
        'TextRange_FindText': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "text", "backward", "ignoreCase", "pRetVal"]),
        #
        'TextRange_GetBoundingRectangles': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "pRetVal"]),
        #
        'TextRange_GetEnclosingElement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "pRetVal"]),
        #
        'TextRange_GetText': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "maxLength", "pRetVal"]),
        #
        'TextRange_Move': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TextUnit"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "unit", "count", "pRetVal"]),
        #
        'TextRange_MoveEndpointByUnit': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TextPatternRangeEndpoint"), SimTypeInt(signed=False, label="TextUnit"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "endpoint", "unit", "count", "pRetVal"]),
        #
        'TextRange_MoveEndpointByRange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TextPatternRangeEndpoint"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="TextPatternRangeEndpoint")], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "endpoint", "targetRange", "targetEndpoint"]),
        #
        'TextRange_Select': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'TextRange_AddToSelection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'TextRange_RemoveFromSelection': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'TextRange_ScrollIntoView': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "alignToTop"]),
        #
        'TextRange_GetChildren': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SAFEARRAY", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "pRetVal"]),
        #
        'ItemContainerPattern_FindItemByProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeRef("VARIANT", SimStruct), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "hnodeStartAfter", "propertyId", "value", "pFound"]),
        #
        'LegacyIAccessiblePattern_Select': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "flagsSelect"]),
        #
        'LegacyIAccessiblePattern_DoDefaultAction': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'LegacyIAccessiblePattern_SetValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "szValue"]),
        #
        'LegacyIAccessiblePattern_GetIAccessible': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IAccessible"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "pAccessible"]),
        #
        'SynchronizedInputPattern_StartListening': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SynchronizedInputType")], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj", "inputType"]),
        #
        'SynchronizedInputPattern_Cancel': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'VirtualizedItemPattern_Realize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'UiaPatternRelease': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'UiaTextRangeRelease': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hobj"]),
        #
        'UiaReturnRawElementProvider': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IRawElementProviderSimple")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "wParam", "lParam", "el"]),
        #
        'UiaHostProviderFromHwnd': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IRawElementProviderSimple"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "ppProvider"]),
        #
        'UiaProviderForNonClient': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IRawElementProviderSimple"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "idObject", "idChild", "ppProvider"]),
        #
        'UiaIAccessibleFromProvider': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IAccessible"), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pProvider", "dwFlags", "ppAccessible", "pvarChild"]),
        #
        'UiaProviderFromIAccessible': SimTypeFunction([SimTypeBottom(label="IAccessible"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IRawElementProviderSimple"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAccessible", "idChild", "dwFlags", "ppProvider"]),
        #
        'UiaDisconnectAllProviders': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'UiaDisconnectProvider': SimTypeFunction([SimTypeBottom(label="IRawElementProviderSimple")], SimTypeInt(signed=True, label="Int32"), arg_names=["pProvider"]),
        #
        'UiaHasServerSideProvider': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd"]),
    }

lib.set_prototypes(prototypes)
