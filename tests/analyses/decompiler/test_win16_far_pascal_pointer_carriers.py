from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import archinfo
import pytest

import angr
from angr.ailment import AILBlockViewer, Expr
from angr.analyses.decompiler.converted_pointers import normalize_converted_pointer_bindings
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CFunctionCall, CStructuredCodeWalker
from angr.calling_conventions import SimComboArg, SimStackArg
from angr.engines.pcode.cc import SimCCPCodeX86Win16FarPascal, SimCCPCodeX86Win16NearCdecl
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypeShort


class _AILCallCollector(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.calls: list[Expr.Call] = []

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        self.calls.append(expr)
        return super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


class _CCallCollector(CStructuredCodeWalker):
    def __init__(self):
        self.calls: list[CFunctionCall] = []

    def handle_CFunctionCall(self, obj):
        self.calls.append(obj)
        return super().handle_CFunctionCall(obj)


def _decompile_far_pascal_call(
    body: bytes,
    argument_types,
    callee_pop: int,
    *,
    caller_returns_value: bool = False,
    target_addr: int = 0x40,
    target_return_type=None,
    **decompiler_options,
):
    code = body + b"\x90" * (target_addr - len(body)) + bytes((0xCA, callee_pop, 0))
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    project = angr.load_shellcode(
        code,
        arch=arch,
        load_address=0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    project.simos.name = "Win16"
    cfg = project.analyses.CFGFast(
        function_starts=[0, target_addr],
        regions=[(0, len(code))],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=False,
    )

    caller = cfg.functions[0]
    caller.calling_convention = SimCCPCodeX86Win16NearCdecl(arch)
    caller_return_type = SimTypeShort(signed=False) if caller_returns_value else SimTypeBottom(label="void")
    caller.prototype = SimTypeFunction([], caller_return_type).with_arch(arch)
    caller.prototype_source = PrototypeSource.SIGNATURES

    target = cfg.functions[target_addr]
    target.name = "imported_far_pascal_api"
    target.calling_convention = SimCCPCodeX86Win16FarPascal(arch)
    target.prototype = SimTypeFunction(
        argument_types, target_return_type if target_return_type is not None else SimTypeBottom(label="void")
    ).with_arch(arch)
    target.prototype_source = PrototypeSource.SIGNATURES

    decompilation = project.analyses.Decompiler(
        caller,
        cfg=cfg.model,
        fail_fast=True,
        use_cache=False,
        update_cache=False,
        far_call_bindings={"external_targets": {target_addr: "host_far_pascal_api"}},
        register_state_bindings={"ss": "PBR_SS"},
        **decompiler_options,
    )
    assert decompilation.codegen is not None
    assert decompilation.codegen.cfunc is not None
    return project, target, decompilation


def _far_ail_call(decompilation):
    collector = _AILCallCollector()
    for block in decompilation.ail_graph:
        collector.walk(block)
    return next(call for call in collector.calls if call.transfer_kind == "far")


def _host_c_call(decompilation):
    collector = _CCallCollector()
    collector.handle(decompilation.codegen.cfunc)
    return next(call for call in collector.calls if call.callee_target == "host_far_pascal_api")


def test_cwd_keeps_integer_resource_selector_zero_in_far_pascal_call():
    # sub ax,ax; push ax; mov ax,7f00h; cwd; push dx; push ax; callf 0000:0040; ret
    # This is the source-free machine-code shape of LoadCursor(0, MAKEINTRESOURCE(7f00h)). CWD makes the selector
    # word zero; folding SUBPIECE must not accidentally reuse AX as both halves of the far-pointer carrier.
    body = bytes.fromhex("2bc050b8007f9952509a40000000c3")
    _, _, decompilation = _decompile_far_pascal_call(
        body,
        [SimTypeShort(signed=False), SimTypeLong(signed=False)],
        callee_pop=6,
    )

    text = decompilation.codegen.text
    assignments = dict(re.findall(r"^\s*(v\d+) = (0|0x[0-9a-f]+);", text, re.MULTILINE))
    call = re.search(
        r"host_far_pascal_api\((v\d+), \(unsigned long\)(v\d+) << 16 \| \(unsigned long\)(v\d+)\);",
        text,
    )
    assert call is not None, text
    instance, selector, offset = call.groups()
    assert assignments[instance] == "0"
    assert assignments[selector] == "0"
    assert assignments[offset] == "0x7f00"
    assert decompilation.codegen.unsupported_constructs == ()


def test_far_pascal_16_16_scalar_carrier_is_one_selector_offset_argument():
    # mov ax,1234h; push ss; push ax; callf 0000:0040; ret
    body = bytes.fromhex("b8341216509a40000000c3")
    _, target, decompilation = _decompile_far_pascal_call(body, [SimTypeLong(signed=False)], callee_pop=4)

    [location] = target.calling_convention.arg_locs(target.prototype)
    assert isinstance(location, SimComboArg)
    assert location.locations == [SimStackArg(4, 2), SimStackArg(6, 2)]

    ail_call = _far_ail_call(decompilation)
    assert ail_call.args is not None and len(ail_call.args) == 1
    [carrier] = ail_call.args
    assert isinstance(carrier, Expr.BinaryOp) and carrier.op == "Concat" and carrier.bits == 32
    assert [piece.bits for piece in carrier.operands] == [16, 16]
    assert all(isinstance(piece, Expr.VirtualVariable) and piece.was_stack for piece in carrier.operands)
    assert [piece.stack_offset for piece in carrier.operands] == [-2, -4]

    c_call = _host_c_call(decompilation)
    assert len(c_call.args) == 1
    [c_carrier] = c_call.args
    assert isinstance(c_carrier, CBinaryOp) and c_carrier.op == "Or"
    assert isinstance(c_carrier.lhs, CBinaryOp) and c_carrier.lhs.op == "Shl"
    call_line = next(line for line in decompilation.codegen.text.splitlines() if "host_far_pascal_api(" in line)
    assert call_line.count(",") == 0
    assert "(unsigned long)" in call_line and " << 16 | " in call_line
    assert "*((unsigned short *)&" not in call_line
    assert decompilation.codegen.unsupported_constructs == ()


def test_getmessage_shaped_far_pascal_call_keeps_long_plus_three_words_and_callee_cleanup():
    # The first declared argument is the 16:16 carrier. Pascal pushes arguments left-to-right, so SS:1234 is
    # followed by the three word arguments. There is deliberately no caller-side stack adjustment after CALLF.
    body = bytes.fromhex("b8341216506811116822226833339a40000000c3")
    project, target, decompilation = _decompile_far_pascal_call(
        body,
        [
            SimTypeLong(signed=False),
            SimTypeShort(signed=False),
            SimTypeShort(signed=False),
            SimTypeShort(signed=False),
        ],
        callee_pop=10,
    )

    locations = target.calling_convention.arg_locs(target.prototype)
    assert isinstance(locations[0], SimComboArg)
    assert locations[0].locations == [SimStackArg(10, 2), SimStackArg(12, 2)]
    assert locations[1:] == [SimStackArg(8, 2), SimStackArg(6, 2), SimStackArg(4, 2)]
    assert target.calling_convention.CALLEE_CLEANUP is True
    assert target.calling_convention.stack_space(locations) == 14
    facts = project.analyses.FunctionFactCollector(target)
    assert facts.return_address_size == 4
    assert facts.extra_pop == 10

    ail_call = _far_ail_call(decompilation)
    assert ail_call.args is not None and len(ail_call.args) == 4
    assert isinstance(ail_call.args[0], Expr.BinaryOp) and ail_call.args[0].op == "Concat"
    assert [argument.bits for argument in ail_call.args] == [32, 16, 16, 16]
    assert [piece.stack_offset for piece in ail_call.args[0].operands] == [-2, -4]
    assert [argument.stack_offset for argument in ail_call.args[1:]] == [-6, -8, -10]

    c_call = _host_c_call(decompilation)
    assert len(c_call.args) == 4
    assert isinstance(c_call.args[0], CBinaryOp) and c_call.args[0].op == "Or"
    call_line = next(line for line in decompilation.codegen.text.splitlines() if "host_far_pascal_api(" in line)
    assert call_line.count(",") == 3
    assert "(unsigned long)" in call_line and " << 16 | " in call_line
    assert decompilation.codegen.unsupported_constructs == ()


def test_bound_api_argument_preserves_clearly_guest_native_16_16_value():
    # A converted-pointer contract describes the API argument, not every caller. SS:1234 is a guest far value with
    # no native object-address provenance, so even at a bound site it remains the exact 32-bit machine carrier.
    body = bytes.fromhex("b8341216509a40000000c3")
    _, _, decompilation = _decompile_far_pascal_call(
        body,
        [SimTypeLong(signed=False)],
        callee_pop=4,
        converted_pointer_bindings={
            ("callsite_addr", 5): {
                0: {
                    "helper": "pbr_win16_active_borrow_native_pointer",
                    "span": 18,
                    "address_kind": "x86-protected-16:16",
                    "selector_register": "ss",
                    "contract": "test:MSG16",
                }
            }
        },
    )

    [argument] = _host_c_call(decompilation).args
    assert isinstance(argument, CBinaryOp) and argument.op == "Or"
    assert "pbr_win16_active_borrow_native_pointer(" not in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()


def test_unbound_native_stack_address_cannot_be_truncated_into_far_pointer_offset():
    # push bp; mov bp,sp; sub sp,10h; lea ax,[bp-10h]; push ss; push ax;
    # callf 0000:0040; mov sp,bp; pop bp; ret
    body = bytes.fromhex("558bec83ec108d46f016509a400000008be55dc3")
    _, _, decompilation = _decompile_far_pascal_call(body, [SimTypeLong(signed=False)], callee_pop=4)

    assert "host_far_pascal_api(" not in decompilation.codegen.text
    assert "pbr_win16_active_borrow_native_pointer(" not in decompilation.codegen.text
    diagnostic = next(
        item
        for item in decompilation.codegen.unsupported_constructs
        if item.kind == "native_stack_pointer_far_call_boundary"
    )
    assert diagnostic.operation == "native-stack-pointer-to-16:16-guest-far-pointer"
    assert diagnostic.count == 1
    assert diagnostic.locations[0].instruction_address == 11
    assert diagnostic.locations[0].block_address == 0


def test_exact_binding_borrows_a_coalesced_native_msg_frame_instead_of_truncating_its_address():
    # The two post-call loads keep both endpoints of the 18-byte MSG-shaped local live. They also prove that the
    # address-taken interval is real stack storage, while the binding supplies its authoritative service span.
    body = bytes.fromhex("558bec83ec128d46ee16506a006a006a009a400000008b46ee0346fe8be55dc3")
    _, _, decompilation = _decompile_far_pascal_call(
        body,
        [
            SimTypeLong(signed=False),
            SimTypeShort(signed=False),
            SimTypeShort(signed=False),
            SimTypeShort(signed=False),
        ],
        callee_pop=10,
        caller_returns_value=True,
        converted_pointer_bindings={
            ("callsite_addr", 17): {
                0: {
                    "helper": "pbr_win16_active_borrow_native_pointer",
                    "span": 18,
                    "address_kind": "x86-protected-16:16",
                    "selector_register": "ss",
                    "contract": "test:MSG16",
                }
            }
        },
    )

    host_call = _host_c_call(decompilation)
    assert len(host_call.args) == 4
    helper_call = host_call.args[0]
    assert isinstance(helper_call, CFunctionCall)
    assert helper_call.callee_target == "pbr_win16_active_borrow_native_pointer"
    assert len(helper_call.args) == 2
    assert isinstance(helper_call.args[1], CConstant) and helper_call.args[1].value == 18
    assert decompilation.codegen.text.count("pbr_win16_active_borrow_native_pointer(") == 1
    assert "[0], 18)" in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()


def test_registerclass_shaped_binding_borrows_exact_26_byte_local_frame():
    # push bp; mov bp,sp; sub sp,1ah; lea ax,[bp-1ah]; push ss; push ax;
    # callf 0000:0040; mov sp,bp; pop bp; ret
    body = bytes.fromhex("558bec83ec1a8d46e616509a400000008be55dc3")
    _, _, decompilation = _decompile_far_pascal_call(
        body,
        [SimTypeLong(signed=False)],
        callee_pop=4,
        converted_pointer_bindings={
            ("callsite_addr", 11): {
                0: {
                    "helper": "pbr_win16_active_borrow_native_pointer",
                    "span": 26,
                    "address_kind": "x86-protected-16:16",
                    "selector_register": "ss",
                    "contract": "test:WNDCLASS16",
                }
            }
        },
    )

    [argument] = _host_c_call(decompilation).args
    assert isinstance(argument, CFunctionCall)
    assert argument.callee_target == "pbr_win16_active_borrow_native_pointer"
    assert isinstance(argument.args[1], CConstant) and argument.args[1].value == 26
    assert "_Alignas(16) unsigned char" in decompilation.codegen.text
    assert "[26];" in decompilation.codegen.text
    assert "[0], 26)" in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()


def test_registerclass_shaped_binding_materializes_every_wndclass_word_at_its_exact_offset():
    # A source-free WNDCLASS16-shaped local occupies BP-2ch..BP-13h inside a larger frame. The three handle fields
    # deliberately receive far-call results, matching the stack/register equivalences created by real Win16 class
    # setup code; the other ten public-ABI words have unique constants. The last call borrows the entire aggregate.
    prefix = bytes.fromhex(
        "558bec83ec2c5756"
        "c746d44000"  # style
        "c746d63412"  # WndProc offset
        "c746d87856"  # WndProc selector
        "c746da2222"  # cbClsExtra
        "c746dc3333"  # cbWndExtra
        "c746de4444"  # hInstance
    )
    imported_call = bytes.fromhex("6a016a006811119a00020000")
    body = (
        prefix
        + imported_call
        + bytes.fromhex("8946e0")  # hIcon
        + imported_call
        + bytes.fromhex("8946e2")  # hCursor
        + imported_call
        + bytes.fromhex("8946e4")  # hbrBackground
        + bytes.fromhex(
            "c746e69999"  # menu-name offset
            "c746e8aaaa"  # menu-name selector
            "c746eabbbb"  # class-name offset
            "c746eccccc"  # class-name selector
            "6a018d46d41650"  # dummy first argument; then SS:BP-2c
        )
    )
    callsite = len(body)
    body += bytes.fromhex("9a000200008be55dc3")
    _, _, decompilation = _decompile_far_pascal_call(
        body,
        [SimTypeShort(signed=False), SimTypeLong(signed=False)],
        callee_pop=6,
        target_addr=0x200,
        target_return_type=SimTypeShort(signed=False),
        converted_pointer_bindings={
            ("callsite_addr", callsite): {
                1: {
                    "helper": "pbr_win16_active_borrow_native_pointer",
                    "span": 26,
                    "address_kind": "x86-protected-16:16",
                    "selector_register": "ss",
                    "contract": "test:WNDCLASS16",
                    "native_stack_offset": -0x2C,
                    "native_stack_evidence": "test:x86-lea-bp-push-ss-push-register-v1",
                }
            }
        },
    )

    text = decompilation.codegen.text
    frame_name = re.search(r"unsigned char (native_frame_[A-Za-z0-9_]+)\[26\]", text)
    assert frame_name is not None, text
    name = re.escape(frame_name.group(1))
    write_offsets = [0] if re.search(rf"\*\(\(unsigned short \*\){name}\) =", text) else []
    write_offsets.extend(
        int(match.group(1)) for match in re.finditer(rf"\*\(\(unsigned short \*\)&{name}\[(\d+)\]\) =", text)
    )
    assert sorted(write_offsets) == list(range(0, 26, 2)), text
    for offset, value in {
        0: 0x0040,
        2: 0x1234,
        4: 0x5678,
        6: 0x2222,
        8: 0x3333,
        10: 0x4444,
        18: 0x9999,
        20: 0xAAAA,
        22: 0xBBBB,
        24: 0xCCCC,
    }.items():
        rendered_offset = "" if offset == 0 else rf"&{name}\[{offset}\]"
        assert re.search(rf"\*\(\(unsigned short \*\){rendered_offset or name}\) = (?:0x{value:x}|{value});", text), (
            text
        )
    assert "[0], 26)" in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()


def test_sealed_machine_stack_offset_survives_an_intermediate_offset_register():
    # The exact machine proof is supplied by an independent caller-side decoder.  Moving the LEA result through DX
    # is enough for high-level variable recovery to lose the direct address expression on some pipelines, but it
    # does not change the BP-relative machine argument.
    body = bytes.fromhex("558bec83ec128d46ee8bd016529a400000008b46ee0346fe8be55dc3")
    _, _, decompilation = _decompile_far_pascal_call(
        body,
        [SimTypeLong(signed=False)],
        callee_pop=4,
        caller_returns_value=True,
        converted_pointer_bindings={
            ("callsite_addr", 13): {
                0: {
                    "helper": "pbr_win16_active_borrow_native_pointer",
                    "span": 18,
                    "address_kind": "x86-protected-16:16",
                    "selector_register": "ss",
                    "contract": "test:MSG16",
                    "native_stack_offset": -18,
                    "native_stack_evidence": "test:x86-lea-bp-push-ss-push-register-v1",
                }
            }
        },
    )

    [argument] = _host_c_call(decompilation).args
    assert isinstance(argument, CFunctionCall)
    assert argument.callee_target == "pbr_win16_active_borrow_native_pointer"
    assert "[0], 18)" in decompilation.codegen.text
    assert decompilation.codegen.unsupported_constructs == ()


def test_sealed_machine_stack_offset_must_still_fit_the_live_allocation():
    body = bytes.fromhex("558bec83ec128d46ee16509a400000008b46ee0346fe8be55dc3")
    _, _, decompilation = _decompile_far_pascal_call(
        body,
        [SimTypeLong(signed=False)],
        callee_pop=4,
        caller_returns_value=True,
        converted_pointer_bindings={
            ("callsite_addr", 11): {
                0: {
                    "helper": "pbr_win16_active_borrow_native_pointer",
                    "span": 18,
                    "address_kind": "x86-protected-16:16",
                    "selector_register": "ss",
                    "contract": "test:MSG16",
                    "native_stack_offset": -16,
                    "native_stack_evidence": "test:x86-lea-bp-push-ss-push-register-v1",
                }
            }
        },
    )

    assert "host_far_pascal_api(" not in decompilation.codegen.text
    diagnostic = next(
        item
        for item in decompilation.codegen.unsupported_constructs
        if item.kind == "converted_pointer_binding_failure"
    )
    assert diagnostic.operation == "prove-live-stack-allocation"


@pytest.mark.parametrize(
    ("body", "operation"),
    [
        # The 16-byte allocation cannot back a 26-byte service contract.
        (bytes.fromhex("558bec83ec108d46f016509a400000008be55dc3"), "prove-local-stack-storage"),
        # A native BP-relative object paired with DS is not a native stack pointer carrier.
        (bytes.fromhex("558bec83ec1a8d46e61e509a400000008be55dc3"), "prove-stack-selector"),
    ],
)
def test_bound_native_pointer_rejects_insufficient_storage_or_selector_mismatch(body, operation):
    _, _, decompilation = _decompile_far_pascal_call(
        body,
        [SimTypeLong(signed=False)],
        callee_pop=4,
        converted_pointer_bindings={
            ("callsite_addr", 11): {
                0: {
                    "helper": "pbr_win16_active_borrow_native_pointer",
                    "span": 26,
                    "address_kind": "x86-protected-16:16",
                    "selector_register": "ss",
                    "contract": "test:WNDCLASS16",
                }
            }
        },
    )

    assert "host_far_pascal_api(" not in decompilation.codegen.text
    diagnostic = next(
        item
        for item in decompilation.codegen.unsupported_constructs
        if item.kind == "converted_pointer_binding_failure"
    )
    assert diagnostic.operation == operation
    assert diagnostic.count == 1
    assert diagnostic.locations[0].instruction_address == 11


def test_converted_pointer_bindings_are_deterministic_and_roundtrip_in_cache_parameters():
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    raw = {
        ("callsite_addr", 0x1BE): {
            0: {
                "helper": "pbr_win16_active_borrow_native_pointer",
                "span": 18,
                "address_kind": "x86-protected-16:16",
                "selector_register": "ss",
                "contract": "win16:MSG16",
                "native_stack_offset": -18,
                "native_stack_evidence": "win16:x86-lea-bp-push-ss-push-register-v1",
            }
        },
        ("callsite_addr", 0x7F): {
            0: {
                "helper": "pbr_win16_active_borrow_native_pointer",
                "span": 26,
                "address_kind": "x86-protected-16:16",
                "selector_register": "ss",
                "contract": "win16:WNDCLASS16",
            }
        },
    }
    normalized = normalize_converted_pointer_bindings(arch, raw)
    assert [row[:2] for row in normalized] == [(0x7F, 0), (0x1BE, 0)]

    project = angr.load_shellcode(
        b"\xc3",
        arch=arch,
        load_address=0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    cache = DecompilationCache(0)
    cache.parameters = {"converted_pointer_bindings": normalized}
    parsed = DecompilationCache.parse(cache.serialize(), project=project, kb=project.kb)
    assert parsed.parameters["converted_pointer_bindings"] == normalized


@pytest.mark.parametrize(
    "bindings",
    [
        {("callee_name", "GetMessage"): {0: {}}},
        {("callsite_addr", 1): {0: {"helper": "borrow"}}},
        {
            ("callsite_addr", 1): {
                0: {
                    "helper": "borrow",
                    "span": 18,
                    "address_kind": "x86-protected-16:16",
                    "selector_register": "ds",
                    "contract": "test:MSG16",
                }
            }
        },
        {
            ("callsite_addr", 1): {
                0: {
                    "helper": "borrow",
                    "span": 18,
                    "address_kind": "x86-protected-16:16",
                    "selector_register": "ss",
                    "contract": "test:MSG16",
                    "native_stack_offset": -18,
                }
            }
        },
    ],
)
def test_converted_pointer_bindings_reject_implicit_or_incomplete_authority(bindings):
    arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
    with pytest.raises((TypeError, ValueError)):
        normalize_converted_pointer_bindings(arch, bindings)


def test_generated_msg_bridge_compiles_and_preserves_endpoint_aliasing(tmp_path):
    compiler = shutil.which("cc")
    if compiler is None:
        compiler = next((str(path) for path in Path("/nix/store").glob("*gcc-wrapper*/bin/gcc")), None)
    if compiler is None:
        pytest.skip("A native C compiler is not available")

    body = bytes.fromhex("558bec83ec128d46ee16506a006a006a009a400000008b46ee0346fe8be55dc3")
    _, _, decompilation = _decompile_far_pascal_call(
        body,
        [
            SimTypeLong(signed=False),
            SimTypeShort(signed=False),
            SimTypeShort(signed=False),
            SimTypeShort(signed=False),
        ],
        callee_pop=10,
        caller_returns_value=True,
        converted_pointer_bindings={
            ("callsite_addr", 17): {
                0: {
                    "helper": "pbr_win16_active_borrow_native_pointer",
                    "span": 18,
                    "address_kind": "x86-protected-16:16",
                    "selector_register": "ss",
                    "contract": "test:MSG16",
                }
            }
        },
    )
    decompilation.func.name = "recovered_main"
    decompilation.codegen.reload_function_metadata(decompilation.func)
    decompilation.codegen.regenerate_text()

    harness = (
        """
#include <stdint.h>
#define PBR_SS 0
static void *borrowed;
unsigned long long pbr_win16_active_borrow_native_pointer(void *pointer, unsigned int span) {
    borrowed = span == 18 ? pointer : 0;
    return (uintptr_t)borrowed;
}
void host_far_pascal_api(unsigned long long token, unsigned short a, unsigned short b, unsigned short c) {
    (void)a; (void)b; (void)c;
    if ((void *)(uintptr_t)token == borrowed) {
        ((unsigned short *)borrowed)[0] = 3;
        ((unsigned short *)borrowed)[8] = 4;
    }
}
"""
        + decompilation.codegen.text
        + """
int main(void) { return recovered_main() == 7 ? 0 : 1; }
"""
    )
    source = tmp_path / "converted_pointer.c"
    executable = tmp_path / "converted_pointer"
    source.write_text(harness)
    subprocess.run(
        [compiler, "-std=c11", "-Werror=implicit-function-declaration", str(source), "-o", str(executable)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run([str(executable)], check=True)
