# pylint:disable=missing-class-docstring,no-self-use,arguments-differ,unused-argument
import os

import angr

BIN_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries")


def test_hook_symbol() -> None:
    """
    Test the hook_symbol (and related functions) useing the inet_ntoa simprocedure for functionality
    """
    bin_path = os.path.join(BIN_PATH, "tests", "x86_64", "inet_ntoa")
    proj = angr.Project(bin_path, auto_load_libs=False, use_sim_procedures=True)

    assert proj.is_symbol_hooked("inet_ntoa")
    assert not proj.is_symbol_hooked("not_expected_to_exist")

    original_hook = proj.symbol_hooked_by("inet_ntoa")

    assert isinstance(original_hook, angr.SIM_PROCEDURES["posix"]["inet_ntoa"])

    # No intention to call this, just checking hooking
    class FakeInetNtoa(angr.SimProcedure):
        def run(self, in_addr):
            return None

    fake_inet_ntoa = FakeInetNtoa()

    # test not allowing replacement
    proj.hook_symbol("inet_ntoa", fake_inet_ntoa, replace=False)
    assert proj.symbol_hooked_by("inet_ntoa") == original_hook

    # test allowing replacement
    proj.hook_symbol("inet_ntoa", fake_inet_ntoa, replace=True)
    assert proj.symbol_hooked_by("inet_ntoa") != original_hook
    assert proj.symbol_hooked_by("inet_ntoa") == fake_inet_ntoa
