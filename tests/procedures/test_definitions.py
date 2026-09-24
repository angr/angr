from __future__ import annotations

import angr


def test_load_all_definitions_loads_windows_definitions():
    angr.procedures.definitions.load_all_definitions()

    kernel32 = angr.SIM_LIBRARIES["kernel32.dll"][0]
    ntoskrnl = angr.SIM_LIBRARIES["ntoskrnl.exe"][0]

    assert kernel32.has_prototype("CreateFileW")
    assert ntoskrnl.has_prototype("IoCreateDevice")
    assert kernel32.has_implementation("EncodePointer")
    assert ntoskrnl.has_implementation("__fastfail")
