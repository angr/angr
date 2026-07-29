from __future__ import annotations

import angr
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeInt, SimTypePointer


def test_indirect_call_target_is_recovered_as_function_pointer():
    # long dispatch(callback, a, b, c) { return callback(a, b, c); }
    #
    # rcx is both the fourth SysV argument register and the indirect call's machine operand. It must not be
    # misidentified as a fourth callback argument whose value is callback itself.
    code = bytes.fromhex("4889c84889f94889f74889d64889c2ffd1c3")
    project = angr.load_shellcode(code, "amd64", load_address=0x400000)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True, force_complete_scan=False)
    function = cfg.functions[0x400000]
    project.analyses.CompleteCallingConventions(
        recover_variables=True,
        cfg=cfg.model,
        analyze_callsites=True,
    )

    decompilation = project.analyses.Decompiler(function, cfg=cfg.model, fail_fast=True)

    assert decompilation.codegen is not None
    assert function.prototype is not None
    callback_type = function.prototype.args[0]
    assert isinstance(callback_type, SimTypePointer)
    assert isinstance(callback_type.pts_to, SimTypeFunction)
    assert len(callback_type.pts_to.args) == 3
    assert "(*a0)(" in decompilation.codegen.text
    assert "return a0(a1, a2, a3);" in decompilation.codegen.text


def test_call_result_forwarded_through_return_is_used():
    # wrapper @ 0x400000: return leaf(arg);
    # leaf    @ 0x400010: return arg;
    code = bytes.fromhex("e80b000000c3") + b"\x90" * 10 + bytes.fromhex("89f8c3")
    project = angr.load_shellcode(code, "amd64", load_address=0x400000)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True, force_complete_scan=False)
    project.analyses.CompleteCallingConventions(
        recover_variables=True,
        cfg=cfg.model,
        analyze_callsites=True,
    )
    wrapper = cfg.functions[0x400000]
    leaf = cfg.functions[0x400010]

    assert wrapper.prototype is not None
    assert leaf.prototype is not None
    assert not isinstance(wrapper.prototype.returnty, SimTypeBottom)
    assert not isinstance(leaf.prototype.returnty, SimTypeBottom)

    decompilation = project.analyses.Decompiler(wrapper, cfg=cfg.model, fail_fast=True)

    assert decompilation.codegen is not None
    assert "return sub_400010(a0);" in decompilation.codegen.text


def test_guessed_plt_prototype_is_refreshed_from_target():
    # caller @ 0x400000: return stub(arg);
    # stub   @ 0x400010: jump real;
    # real   @ 0x400020: return arg;
    code = (
        bytes.fromhex("e80b000000c3")
        + b"\x90" * 10
        + bytes.fromhex("e90b000000")
        + b"\x90" * 11
        + bytes.fromhex("89f8c3")
    )
    project = angr.load_shellcode(code, "amd64", load_address=0x400000)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True, force_complete_scan=False)
    caller = cfg.functions[0x400000]
    stub = cfg.functions[0x400010]
    real = cfg.functions[0x400020]

    stub.is_plt = True
    stub.calling_convention = project.factory.cc()
    stub.prototype = SimTypeFunction([], SimTypeInt()).with_arch(project.arch)
    stub.prototype_source = PrototypeSource.CCA_LOW
    real.calling_convention = project.factory.cc()
    real.prototype = SimTypeFunction([SimTypeInt()], SimTypeInt()).with_arch(project.arch)
    real.prototype_source = PrototypeSource.CCA_DECOMPILER

    decompilation = project.analyses.Decompiler(caller, cfg=cfg.model, fail_fast=True)

    assert decompilation.codegen is not None
    assert stub.prototype is not None
    assert len(stub.prototype.args) == 1
    assert stub.prototype_source > PrototypeSource.CCA_LOW
    assert "return sub_400010(a0);" in decompilation.codegen.text


def test_imported_function_used_as_value_is_not_rendered_as_data():
    # Return the address of an imported function. The immediate is patched after CLE allocates the extern symbol.
    project = angr.load_shellcode(b"\x48\xb8" + b"\x00" * 8 + b"\xc3", "amd64", load_address=0x400000)
    symbol = project.loader.extern_object.make_extern("fgets")
    project.loader.memory.store(0x400002, symbol.rebased_addr.to_bytes(8, "little"))
    hook = angr.SIM_PROCEDURES["libc"]["fgets"]()
    project.hook(symbol.rebased_addr, hook)

    cfg = project.analyses.CFGFast(normalize=True, data_references=True, force_complete_scan=False)
    function = cfg.functions[0x400000]
    function.calling_convention = project.factory.cc()
    function.prototype = SimTypeFunction([], SimTypePointer(hook.prototype)).with_arch(project.arch)
    function.prototype_source = PrototypeSource.USER

    decompilation = project.analyses.Decompiler(function, cfg=cfg.model, fail_fast=True)

    assert decompilation.codegen is not None
    assert "return fgets;" in decompilation.codegen.text
    assert "extern char fgets;" not in decompilation.codegen.text
