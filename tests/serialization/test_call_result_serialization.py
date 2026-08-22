from __future__ import annotations

import archinfo

import angr
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstruct,
    CFakeVariable,
    CFunctionCall,
    CStructuredCodeGenerator,
    CStructuredCodeWalker,
    CTypeCast,
    MakeTypecastsImplicit,
)
from angr.analyses.decompiler.structured_codegen.c_serialize import parse_subtree, serialize_subtree
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort


class _AttachCodegen(CStructuredCodeWalker):
    def __init__(self, codegen):
        self.codegen = codegen

    def handle(self, obj):
        if isinstance(obj, CConstruct):
            obj.codegen = self.codegen
        return super().handle(obj)


def _codegen():
    arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
    project = angr.load_shellcode(
        b"\xc3",
        arch,
        0,
        0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    caller = project.kb.functions.function(addr=0, create=True)
    assert caller is not None
    caller.prototype = SimTypeFunction([], SimTypeShort(signed=False)).with_arch(arch)

    codegen = DummyStructuredCodeGenerator("pseudocode", expr_comments={}, stmt_comments={}, const_formats={})
    codegen.project = project
    codegen.kb = project.kb
    codegen._func = caller
    codegen._variables_in_use = {}
    codegen.use_compound_assignments = False
    codegen.show_casts = True
    codegen.prettify_thiscall = False
    codegen.cstyle_void_param = True
    return project, codegen


def _call_from_assignment(assignment: CAssignment) -> CFunctionCall:
    expression = assignment.rhs
    while isinstance(expression, CTypeCast):
        expression = expression.expr
    assert isinstance(expression, CFunctionCall)
    return expression


def _unsupported_summary(root: CConstruct):
    codegen = CStructuredCodeGenerator.__new__(CStructuredCodeGenerator)
    codegen.cfunc = root
    return [(item.kind, item.operation, item.count) for item in codegen.unsupported_constructs]


def test_pointer_call_assignment_cast_and_edge_prototype_survive_roundtrip():
    project, codegen = _codegen()
    pointer_type = SimTypePointer(SimTypeShort(signed=False)).with_arch(project.arch)
    source_prototype = SimTypeFunction([], pointer_type).with_arch(project.arch)
    call = CFunctionCall(
        "pointer_result",
        None,
        [],
        callsite_prototype=source_prototype,
        codegen=codegen,
    )

    assert call.callsite_prototype is not source_prototype
    source_prototype.returnty = None
    assert isinstance(call.prototype_returnty, SimTypePointer)

    lhs = CFakeVariable("word", SimTypeShort(signed=False).with_arch(project.arch), codegen=codegen)
    assignment = CAssignment(lhs, call, codegen=codegen)
    assignment = MakeTypecastsImplicit().handle(assignment)

    assert call.result_used is True
    assert isinstance(assignment.rhs, CTypeCast)
    assert assignment.c_repr().strip() == "word = (unsigned short)pointer_result();"

    restored = parse_subtree(serialize_subtree(assignment), project=project, kb=project.kb)
    assert isinstance(restored, CAssignment)
    _AttachCodegen(codegen).handle(restored)
    restored_call = _call_from_assignment(restored)

    assert restored_call.result_used is True
    assert isinstance(restored_call.prototype_returnty, SimTypePointer)
    assert restored.c_repr() == assignment.c_repr()


def test_tagged_void_call_conflict_survives_legacy_result_used_default():
    project, codegen = _codegen()
    callee = project.kb.functions.function(addr=0x100, name="returns_void", create=True)
    assert callee is not None
    callee.prototype = SimTypeFunction([], None).with_arch(project.arch)
    call = CFunctionCall(
        0x100,
        callee,
        [],
        callsite_prototype=callee.prototype,
        result_used=False,
        codegen=codegen,
    )
    assert call.callsite_prototype is not callee.prototype

    lhs = CFakeVariable("word", SimTypeShort(signed=False).with_arch(project.arch), codegen=codegen)
    assignment = CAssignment(lhs, call, codegen=codegen)

    assert call.result_used is True
    assert call.callsite_prototype is not None
    assert isinstance(call.callsite_prototype.returnty, SimTypeShort)
    assert callee.prototype.returnty is None
    assert "((unsigned short (*)(void))returns_void)()" in assignment.c_repr()
    assert _unsupported_summary(assignment) == [("void_call_value", "call-result-consumed", 1)]

    # Older protobufs decode the newly added scalar field as False. The private coercion tag is itself proof that this
    # call occupied a consumed scalar boundary, so the diagnostic must not disappear after such a cache round-trip.
    call.result_used = False
    assert _unsupported_summary(assignment) == [("void_call_value", "call-result-consumed", 1)]

    restored = parse_subtree(serialize_subtree(assignment), project=project, kb=project.kb)
    assert isinstance(restored, CAssignment)
    _AttachCodegen(codegen).handle(restored)
    restored_call = _call_from_assignment(restored)

    assert restored_call.result_used is False
    assert isinstance(restored_call.callsite_prototype.returnty, SimTypeShort)
    assert "((unsigned short (*)(void))returns_void)()" in restored.c_repr()
    assert _unsupported_summary(restored) == [("void_call_value", "call-result-consumed", 1)]
