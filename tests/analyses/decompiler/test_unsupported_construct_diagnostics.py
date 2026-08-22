from __future__ import annotations

from collections import OrderedDict

import archinfo

import angr
from angr import ailment
from angr.analyses.decompiler import UnsupportedConstruct, UnsupportedConstructLocation
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFakeVariable,
    CTypeCast,
    MakeTypecastsImplicit,
    c_variable_identifier,
    extract_terms,
)
from angr.analyses.decompiler.structurer_nodes import SequenceNode, SwitchCaseNode
from angr.analyses.decompiler.variable_map import VariableMap
from angr.sim_type import (
    SimTypeArray,
    SimTypeChar,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable


def _codegen(statements):
    arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
    project = angr.load_shellcode(
        b"\xc3",
        arch,
        0,
        0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    function = project.kb.functions.function(addr=0, create=True)
    assert function is not None
    function.prototype = SimTypeFunction([], SimTypeInt()).with_arch(arch)
    block = ailment.Block(0, 1, statements=statements)
    sequence = SequenceNode(0, nodes=[block])
    return project, function, project.analyses.CStructuredCodeGenerator(function, sequence)


def _dirty_statement(idx, operation, ins_addr, stmt_idx):
    tags = {"ins_addr": ins_addr, "vex_block_addr": 0x100, "vex_stmt_idx": stmt_idx}
    expression = ailment.Expr.DirtyExpression(
        idx,
        operation,
        [ailment.Expr.Const(idx + 1, idx, 16)],
        bits=16,
        **tags,
    )
    return ailment.Stmt.DirtyStatement(idx + 2, expression, **tags)


def test_unsupported_pcode_construct_diagnostics_are_structured_and_stable():
    nested_popcount = ailment.Expr.DirtyExpression(
        3,
        "POPCOUNT",
        [ailment.Expr.Const(4, 1, 16)],
        bits=16,
        ins_addr=0x102,
        vex_block_addr=0x100,
        vex_stmt_idx=1,
    )
    float_sqrt = ailment.Expr.DirtyExpression(
        6,
        "FLOAT_SQRT",
        [nested_popcount],
        bits=16,
        ins_addr=0x106,
        vex_block_addr=0x100,
        vex_stmt_idx=3,
    )
    project, function, codegen = _codegen(
        [
            _dirty_statement(0, "CALLOTHER", 0x100, 0),
            _dirty_statement(9, "CALLOTHER", 0x104, 2),
            ailment.Stmt.DirtyStatement(
                12,
                float_sqrt,
                ins_addr=0x106,
                vex_block_addr=0x100,
                vex_stmt_idx=3,
            ),
        ]
    )

    expected = (
        UnsupportedConstruct(
            kind="dirty_expression",
            operation="CALLOTHER",
            count=2,
            locations=(
                UnsupportedConstructLocation(0x100, 0x100, 0),
                UnsupportedConstructLocation(0x104, 0x100, 2),
            ),
        ),
        UnsupportedConstruct(
            kind="dirty_expression",
            operation="FLOAT_SQRT",
            count=1,
            locations=(UnsupportedConstructLocation(0x106, 0x100, 3),),
        ),
        UnsupportedConstruct(
            kind="dirty_expression",
            operation="POPCOUNT",
            count=1,
            locations=(UnsupportedConstructLocation(0x102, 0x100, 1),),
        ),
    )
    assert codegen.unsupported_constructs == expected

    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    assert restored.unsupported_constructs == expected


def test_ordinary_ail_has_no_unsupported_construct_diagnostics():
    _, _, codegen = _codegen(
        [
            ailment.Stmt.Return(
                0,
                [ailment.Expr.BinaryOp(1, "Add", [ailment.Expr.Const(2, 1, 16), ailment.Expr.Const(3, 2, 16)])],
                ins_addr=0,
            )
        ]
    )

    assert codegen.unsupported_constructs == ()


def test_virtual_variable_array_storage_uses_scalar_read_and_write_views():
    project, function, _ = _codegen([])
    word_type = SimTypeShort(signed=False).with_arch(project.arch)
    byte_type = SimTypeChar(signed=False).with_arch(project.arch)
    storage = SimStackVariable(-8, 8, ident="is_0", name="bytes")
    project.kb.dec_variables[function.addr].set_variable_type(
        storage,
        SimTypeArray(byte_type, 8).with_arch(project.arch),
    )
    function.prototype = SimTypeFunction([], word_type).with_arch(project.arch)

    write = ailment.Expr.VirtualVariable(
        1,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-6,
    )
    read = ailment.Expr.VirtualVariable(
        2,
        2,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-8,
    )
    variable_map = VariableMap()
    variable_map.set_variable(write, storage, offset=2)
    variable_map.set_variable(read, storage, offset=0)
    block = ailment.Block(
        0,
        1,
        statements=[
            ailment.Stmt.Assignment(3, write, ailment.Expr.Const(4, 0x1234, 16), ins_addr=0),
            ailment.Stmt.Return(5, [read], ins_addr=1),
        ],
    )

    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert "unsigned char bytes[8];" in codegen.text
    assert "*((unsigned short *)&bytes[2]) = 4660;" in codegen.text
    assert "return *((unsigned short *)bytes);" in codegen.text
    assert "return bytes;" not in codegen.text

    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    restored.regenerate_text()
    assert "*((unsigned short *)&bytes[2]) = 4660;" in restored.text
    assert "return *((unsigned short *)bytes);" in restored.text


def test_virtual_variable_pointer_value_preserves_pointer_semantics():
    project, function, _ = _codegen([])
    byte_type = SimTypeChar(signed=False).with_arch(project.arch)
    pointer_type = SimTypePointer(byte_type).with_arch(project.arch)
    storage = SimStackVariable(-2, 2, ident="is_0", name="pointer")
    project.kb.dec_variables[function.addr].set_variable_type(storage, pointer_type)
    function.prototype = SimTypeFunction([], pointer_type).with_arch(project.arch)

    read = ailment.Expr.VirtualVariable(
        1,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-2,
    )
    variable_map = VariableMap()
    variable_map.set_variable(read, storage)
    block = ailment.Block(
        0,
        1,
        statements=[ailment.Stmt.Return(2, [read], ins_addr=0)],
    )

    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert "unsigned char *pointer;" in codegen.text
    assert "return pointer;" in codegen.text
    assert "&pointer" not in codegen.text


def test_virtual_variable_mixed_width_scalar_uses_exact_storage_views():
    project, function, _ = _codegen([])
    word_type = SimTypeShort(signed=False).with_arch(project.arch)
    storage = SimStackVariable(-4, 4, ident="is_0", name="wide")
    project.kb.dec_variables[function.addr].set_variable_type(
        storage,
        SimTypeLong(signed=False).with_arch(project.arch),
    )
    function.prototype = SimTypeFunction([], word_type).with_arch(project.arch)

    write = ailment.Expr.VirtualVariable(
        1,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-2,
    )
    read = ailment.Expr.VirtualVariable(
        2,
        2,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-4,
    )
    variable_map = VariableMap()
    variable_map.set_variable(write, storage, offset=2)
    variable_map.set_variable(read, storage)
    block = ailment.Block(
        0,
        1,
        statements=[
            ailment.Stmt.Assignment(3, write, ailment.Expr.Const(4, 0x1234, 16), ins_addr=0),
            ailment.Stmt.Return(5, [read], ins_addr=1),
        ],
    )

    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert "unsigned long wide;" in codegen.text
    assert "*((unsigned short *)((char *)&wide + 2)) = 4660;" in codegen.text
    assert "return *((unsigned short *)&wide);" in codegen.text
    assert "return (unsigned short)wide;" not in codegen.text


def test_virtual_variable_access_widens_undersized_scalar_declaration():
    project, function, _ = _codegen([])
    byte_type = SimTypeChar(signed=False).with_arch(project.arch)
    word_type = SimTypeShort(signed=False).with_arch(project.arch)
    storage = SimStackVariable(-1, 1, ident="is_0", name="word")
    variable_manager = project.kb.dec_variables[function.addr]
    variable_manager.set_variable_type(storage, byte_type)
    function.prototype = SimTypeFunction([], word_type).with_arch(project.arch)

    write = ailment.Expr.VirtualVariable(
        1,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-1,
    )
    read = ailment.Expr.VirtualVariable(
        2,
        2,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-1,
    )
    variable_map = VariableMap()
    variable_map.set_variable(write, storage)
    variable_map.set_variable(read, storage)
    block = ailment.Block(
        0,
        1,
        statements=[
            ailment.Stmt.Assignment(3, write, ailment.Expr.Const(4, 0xBEEF, 16), ins_addr=0),
            ailment.Stmt.Return(5, [read], ins_addr=1),
        ],
    )

    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    # The C declaration owns the native storage. It must cover the exact AIL value width instead of permitting the
    # 16-bit lvalue view to overwrite an adjacent one-byte local.
    assert "unsigned short word;" in codegen.text
    assert "unsigned char word;" not in codegen.text
    assert "*((unsigned short *)&word)" not in codegen.text
    assert "word = 48879;" in codegen.text
    assert "return word;" in codegen.text

    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    restored.regenerate_text()
    assert "unsigned short word;" in restored.text
    assert "*((unsigned short *)&word)" not in restored.text


def test_virtual_variable_storage_views_survive_declaration_type_reload():
    project, function, _ = _codegen([])
    word_type = SimTypeShort(signed=False).with_arch(project.arch)
    byte_type = SimTypeChar(signed=False).with_arch(project.arch)
    long_type = SimTypeLong(signed=False).with_arch(project.arch)
    variable_manager = project.kb.dec_variables[function.addr]

    narrow = SimStackVariable(-2, 2, ident="is_0", name="narrow")
    bytes_ = SimStackVariable(-4, 2, ident="is_1", name="bytes")
    wide = SimStackVariable(-8, 4, ident="is_2", name="wide")
    variable_manager.set_variable_type(narrow, word_type)
    variable_manager.set_variable_type(bytes_, word_type)
    variable_manager.set_variable_type(wide, long_type)
    function.prototype = SimTypeFunction([], word_type).with_arch(project.arch)

    narrow_write = ailment.Expr.VirtualVariable(
        1,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-2,
    )
    bytes_read = ailment.Expr.VirtualVariable(
        2,
        2,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-4,
    )
    wide_write = ailment.Expr.VirtualVariable(
        3,
        3,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-6,
    )
    variable_map = VariableMap()
    variable_map.set_variable(narrow_write, narrow)
    variable_map.set_variable(bytes_read, bytes_)
    variable_map.set_variable(wide_write, wide, offset=2)
    block = ailment.Block(
        0,
        1,
        statements=[
            ailment.Stmt.Assignment(4, narrow_write, bytes_read, ins_addr=0),
            ailment.Stmt.Assignment(5, wide_write, ailment.Expr.Const(6, 0x1234, 16), ins_addr=1),
            ailment.Stmt.Return(7, [bytes_read], ins_addr=2),
        ],
    )
    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert "unsigned short narrow;" in codegen.text
    assert "unsigned short bytes;" in codegen.text
    assert "narrow = bytes;" in codegen.text

    # Model program-wide decompilation refining the declarations after this C
    # AST has already captured the exact AIL value accesses.
    variable_manager.set_variable_type(narrow, byte_type)
    variable_manager.set_variable_type(bytes_, SimTypeArray(byte_type, 2).with_arch(project.arch))
    variable_manager.set_variable_type(wide, SimTypeArray(byte_type, 4).with_arch(project.arch))
    codegen.reload_variable_types()
    codegen.regenerate_text()

    assert "unsigned short narrow;" in codegen.text
    assert "unsigned char bytes[2];" in codegen.text
    assert "unsigned char wide[4];" in codegen.text
    assert "narrow = *((unsigned short *)bytes);" in codegen.text
    assert "*((unsigned short *)&wide[2]) = 4660;" in codegen.text
    assert "return *((unsigned short *)bytes);" in codegen.text
    assert "narrow = bytes;" not in codegen.text

    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    restored.reload_variable_types()
    restored.regenerate_text()
    assert "narrow = *((unsigned short *)bytes);" in restored.text
    assert "*((unsigned short *)&wide[2]) = 4660;" in restored.text
    assert "return *((unsigned short *)bytes);" in restored.text


def test_store_codegen_preserves_ail_width():
    _, _, codegen = _codegen(
        [
            ailment.Stmt.Store(
                0,
                ailment.Expr.Const(1, 0x20, 16),
                ailment.Expr.Const(2, 0x12345678, 32),
                2,
                "Iend_LE",
            )
        ]
    )

    assert "*((unsigned short *)32) = 305419896;" in codegen.text


def test_wide_arithmetic_constant_is_not_guessed_to_be_a_function_pointer():
    project, function, _ = _codegen(
        [
            ailment.Stmt.Return(
                0,
                [ailment.Expr.Const(1, 0x10000, 32)],
                ins_addr=0,
            )
        ]
    )
    project.kb.functions.function(addr=0x10000, create=True)

    # Re-run code generation after installing the colliding function address.
    block = ailment.Block(
        0,
        1,
        statements=[
            ailment.Stmt.Return(
                0,
                [ailment.Expr.Const(1, 0x10000, 32)],
                ins_addr=0,
            )
        ],
    )
    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
    )

    assert "return 0x10000;" in codegen.text
    assert "sub_10000" not in codegen.text


def test_machine_word_zero_is_not_guessed_to_be_the_entry_function():
    _, _, codegen = _codegen(
        [
            ailment.Stmt.Return(
                0,
                [ailment.Expr.Const(1, 0, 16)],
                ins_addr=0,
            )
        ]
    )

    assert "return 0;" in codegen.text
    assert "return _start;" not in codegen.text


def test_raw_abi_function_name_is_rendered_as_a_c_identifier():
    project, function, _ = _codegen([])
    callee = project.kb.functions.function(
        addr=0x100,
        name="user!ordinal_18",
        create=True,
    )
    callee.prototype = SimTypeFunction([], SimTypeInt()).with_arch(project.arch)
    block = ailment.Block(
        0,
        1,
        statements=[
            ailment.Stmt.SideEffectStatement(
                0,
                ailment.Expr.Call(
                    1,
                    ailment.Expr.Const(2, 0x100, 16),
                    args=[],
                    bits=16,
                ),
                ins_addr=0,
            )
        ],
    )
    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
    )

    assert "user_x21_ordinal_18();" in codegen.text
    assert "user!ordinal_18" not in codegen.text


def test_integer_indirect_call_uses_the_callsite_function_pointer_type():
    project, function, _ = _codegen([])
    target = ailment.Expr.BinaryOp(
        1,
        "Add",
        [ailment.Expr.Const(2, 0x2000, 16), ailment.Expr.Const(3, 4, 16)],
    )
    call = ailment.Expr.Call(4, target, args=[], bits=16)
    variable_map = VariableMap()
    variable_map.set_prototype(call, SimTypeFunction([], SimTypeShort(signed=False)).with_arch(project.arch))
    block = ailment.Block(
        0,
        1,
        statements=[ailment.Stmt.SideEffectStatement(5, call, ins_addr=0)],
    )
    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert "((unsigned short (*)(void))(0x2000 + 4))();" in codegen.text
    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    assert "((unsigned short (*)(void))(0x2000 + 4))();" in restored.text


def test_callsite_pointer_argument_gets_an_explicit_machine_value_cast():
    project, function, _ = _codegen([])
    callee = project.kb.functions.function(addr=0x100, name="takes_pointer", create=True)
    assert callee is not None
    argument = ailment.Expr.Register(1, 0, 16)
    call = ailment.Expr.Call(
        2,
        ailment.Expr.Const(3, 0x100, 16),
        args=[argument],
        bits=16,
    )
    variable_map = VariableMap()
    variable_map.set_prototype(
        call,
        SimTypeFunction(
            [SimTypePointer(SimTypeShort(signed=False))],
            SimTypeShort(signed=False),
        ).with_arch(project.arch),
    )
    block = ailment.Block(
        0,
        1,
        statements=[ailment.Stmt.SideEffectStatement(4, call, ins_addr=0)],
    )

    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert "takes_pointer((unsigned short *)reg0<16>);" in codegen.text


def test_callsite_integer_prototype_wins_over_colliding_function_address():
    project, function, _ = _codegen([])
    call = ailment.Expr.Call(
        1,
        "memset",
        args=[
            ailment.Expr.Const(2, 0x20, 16),
            ailment.Expr.Const(3, 0, 16),
            ailment.Expr.Const(4, 2, 16),
        ],
        bits=16,
    )
    variable_map = VariableMap()
    variable_map.set_prototype(
        call,
        SimTypeFunction(
            [
                SimTypePointer(SimTypeShort(signed=False)),
                SimTypeInt(signed=True),
                SimTypeShort(signed=False),
            ],
            SimTypePointer(SimTypeShort(signed=False)),
        ).with_arch(project.arch),
    )
    block = ailment.Block(
        0,
        1,
        statements=[ailment.Stmt.SideEffectStatement(5, call, ins_addr=0)],
    )

    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert "memset((unsigned short *)0x20, 0, 2);" in codegen.text
    assert "sub_0" not in codegen.text.split("memset", 1)[1]


def test_consuming_a_void_call_result_is_structured_unsupported():
    project, function, _ = _codegen([])
    call = ailment.Expr.Call(1, ailment.Expr.Const(2, 0x100, 16), args=[], bits=16)
    variable_map = VariableMap()
    variable_map.set_prototype(call, SimTypeFunction([], None).with_arch(project.arch))
    block = ailment.Block(
        0,
        1,
        statements=[ailment.Stmt.Return(3, [call], ins_addr=0)],
    )
    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert [(item.kind, item.operation, item.count) for item in codegen.unsupported_constructs] == [
        ("void_call_value", "call-result-consumed", 1)
    ]
    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    assert restored.unsupported_constructs == codegen.unsupported_constructs


def test_return_value_is_coerced_to_the_recovered_function_type():
    project, function, _ = _codegen([])
    return_type = SimTypePointer(SimTypeShort(signed=False)).with_arch(project.arch)
    function.prototype = SimTypeFunction([], return_type).with_arch(project.arch)
    block = ailment.Block(
        0,
        1,
        statements=[ailment.Stmt.Return(0, [ailment.Expr.Const(1, 1006, 16)], ins_addr=0)],
    )

    codegen = project.analyses.CStructuredCodeGenerator(function, SequenceNode(0, nodes=[block]))

    assert "return (unsigned short *)1006;" in codegen.text


def test_assignment_coerces_incompatible_scalar_pointer_types():
    project, _, codegen = _codegen([])
    pointer_to_int = SimTypePointer(SimTypeInt()).with_arch(project.arch)
    pointer_to_short = SimTypePointer(SimTypeShort()).with_arch(project.arch)
    lhs = CFakeVariable("dst", pointer_to_short, codegen=codegen)
    rhs = CFakeVariable("src", pointer_to_int, codegen=codegen)

    assignment = CAssignment(lhs, rhs, codegen=codegen)

    assert "".join(chunk for chunk, _ in assignment.c_repr_chunks()).strip() == "dst = (short *)src;"


def test_named_void_callee_with_consumed_result_uses_explicit_callsite_abi():
    project, function, _ = _codegen([])
    callee = project.kb.functions.function(addr=0x100, name="returns_void", create=True)
    assert callee is not None
    callee.prototype = SimTypeFunction([], None).with_arch(project.arch)
    call = ailment.Expr.Call(1, ailment.Expr.Const(2, 0x100, 16), args=[], bits=16)
    variable_map = VariableMap()
    variable_map.set_prototype(call, SimTypeFunction([], None).with_arch(project.arch))
    block = ailment.Block(
        0,
        1,
        statements=[ailment.Stmt.Return(3, [call], ins_addr=0)],
    )

    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert "return ((unsigned short (*)(void))returns_void)();" in codegen.text
    assert [(item.kind, item.operation, item.count) for item in codegen.unsupported_constructs] == [
        ("void_call_value", "call-result-consumed", 1)
    ]
    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    assert "return ((unsigned short (*)(void))returns_void)();" in restored.text
    assert restored.unsupported_constructs == codegen.unsupported_constructs


def test_internal_variable_names_are_valid_c_identifiers():
    unnamed = SimStackVariable(8, 1, ident="is_3", region=0x110196)
    named = SimStackVariable(-10, 2, name="s_-10")

    unnamed_identifier = c_variable_identifier(unnamed)
    assert "<" not in unnamed_identifier
    assert " " not in unnamed_identifier
    assert unnamed_identifier.startswith("_x3c_0x110196")
    assert c_variable_identifier(named) == "s__x2d_10"


def test_function_argument_name_is_consistent_between_signature_and_body():
    project, function, _ = _codegen([])
    function.prototype = SimTypeFunction(
        [SimTypeShort()],
        SimTypeShort(),
        arg_names=["public_arg"],
    ).with_arch(project.arch)

    argument = SimStackVariable(4, 2, ident="is_1", region=function.addr)
    unified_argument = SimStackVariable(
        4,
        2,
        ident="is_u",
        region=function.addr,
        name="recovered_arg",
    )
    variable_manager = project.kb.dec_variables[function.addr]
    variable_manager.set_unified_variable(argument, unified_argument)
    variable_manager.set_variable_type(argument, SimTypeShort().with_arch(project.arch))

    argument_use = ailment.Expr.VirtualVariable(
        1,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=4,
    )
    variable_map = VariableMap()
    variable_map.set_variable(argument_use, argument)
    block = ailment.Block(
        0,
        1,
        statements=[ailment.Stmt.Return(2, [argument_use], ins_addr=0)],
    )
    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        func_args=[argument],
        variable_map=variable_map,
    )

    assert "short _start(short public_arg)" in codegen.text
    assert "return public_arg;" in codegen.text
    assert "recovered_arg" not in codegen.text

    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    restored.regenerate_text()
    assert "return public_arg;" in restored.text


def test_equal_stack_variables_share_the_declared_identifier():
    project, function, _ = _codegen([])
    first_region_variable = SimStackVariable(
        -2,
        2,
        ident="is_1",
        region=0x100,
        name="first_region_name",
    )
    second_region_variable = SimStackVariable(
        -2,
        2,
        ident="is_1",
        region=0x200,
        name="second_region_name",
    )
    assert first_region_variable == second_region_variable

    variable_manager = project.kb.dec_variables[function.addr]
    variable_manager.set_variable_type(first_region_variable, SimTypeShort().with_arch(project.arch))

    first_use = ailment.Expr.VirtualVariable(
        1,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-2,
    )
    second_use = ailment.Expr.VirtualVariable(
        2,
        2,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-2,
    )
    variable_map = VariableMap()
    variable_map.set_variable(first_use, first_region_variable)
    variable_map.set_variable(second_use, second_region_variable)
    block = ailment.Block(
        0,
        1,
        statements=[
            ailment.Stmt.Return(
                3,
                [ailment.Expr.BinaryOp(4, "Add", [first_use, second_use])],
                ins_addr=0,
            )
        ],
    )
    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        variable_map=variable_map,
    )

    assert "short second_region_name;" in codegen.text
    assert "return second_region_name + second_region_name;" in codegen.text
    assert "first_region_name" not in codegen.text

    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    restored.regenerate_text()
    assert "return second_region_name + second_region_name;" in restored.text


def test_cloned_ail_labels_have_one_c_declaration():
    project, function, _ = _codegen([])
    jump = ailment.Stmt.Jump(
        1,
        ailment.Expr.Const(2, 0x100, 16),
        target_idx=0,
        ins_addr=0x90,
    )
    first_label = ailment.Stmt.Label(3, "LABEL_100", ins_addr=0x100, block_idx=0)
    cloned_label = ailment.Stmt.Label(4, "LABEL_100", ins_addr=0x100, block_idx=0)
    block = ailment.Block(0, 1, statements=[jump, first_label, cloned_label])

    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
    )

    assert "goto LABEL_100;" in codegen.text
    assert codegen.text.count("LABEL_100:") == 1

    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    restored.regenerate_text()
    assert restored.text.count("LABEL_100:") == 1


def test_computed_goto_is_reported_as_structured_unsupported():
    target = ailment.Expr.Register(1, 0, 16)
    _, _, codegen = _codegen([ailment.Stmt.Jump(2, target, ins_addr=0x10)])

    assert any(
        construct.kind == "indirect_goto" and construct.operation == "computed-target"
        for construct in codegen.unsupported_constructs
    )


def test_concat_and_insert_are_lowered_to_c_bit_operations():
    concat = ailment.Expr.BinaryOp(
        1,
        "Concat",
        [
            ailment.Expr.Const(2, 0x12, 8),
            ailment.Expr.Const(3, 0x34, 8),
        ],
        signed=False,
        bits=16,
    )
    insert = ailment.Expr.Insert(
        4,
        ailment.Expr.Const(5, 0xABCD, 16),
        ailment.Expr.Const(6, 0, 16),
        ailment.Expr.Const(7, 0x12, 8),
        "Iend_LE",
    )
    _, _, codegen = _codegen(
        [
            ailment.Stmt.Return(0, [concat], ins_addr=0),
            ailment.Stmt.Return(1, [insert], ins_addr=1),
        ]
    )

    assert "CONCAT" not in codegen.text
    assert "_INSERT" not in codegen.text
    assert "<< 8" in codegen.text
    assert "& 0xff00" in codegen.text
    assert codegen.unsupported_constructs == ()


def test_oversized_insert_is_truncated_to_the_destination_width():
    insert = ailment.Expr.Insert(
        1,
        ailment.Expr.Const(2, 0xABCD, 16),
        ailment.Expr.Const(3, 0, 64),
        ailment.Expr.Const(4, 0x12345678, 32),
        "Iend_LE",
    )
    _, _, codegen = _codegen([ailment.Stmt.Return(0, [insert], ins_addr=0)])

    assert "unsupported instruction" not in codegen.text
    assert "& 0xffff" in codegen.text
    assert codegen.unsupported_constructs == ()


def test_scalar_extract_uses_bit_operations_instead_of_addressing_an_rvalue():
    value = ailment.Expr.BinaryOp(
        1,
        "Add",
        [ailment.Expr.Const(2, 0x1200, 16), ailment.Expr.Const(3, 0x34, 16)],
        signed=False,
        bits=16,
    )
    extract = ailment.Expr.Extract(4, 8, value, ailment.Expr.Const(5, 1, 64), "Iend_LE")
    _, _, codegen = _codegen([ailment.Stmt.Return(0, [extract], ins_addr=0)])

    assert "&(" not in codegen.text
    assert ">> 8" in codegen.text
    assert codegen.unsupported_constructs == ()


def test_pointer_bitwise_operation_keeps_required_integer_cast():
    project, _, codegen = _codegen([])
    pointer_type = SimTypePointer(SimTypeChar()).with_arch(project.arch)
    integer_type = SimTypeShort(signed=False).with_arch(project.arch)
    pointer = CFakeVariable("ptr", pointer_type, codegen=codegen)
    required_cast = CTypeCast(pointer_type, integer_type, pointer, codegen=codegen)
    expression = CBinaryOp(
        "And",
        required_cast,
        CConstant(0xFF, integer_type, codegen=codegen),
        codegen=codegen,
    )
    simplified = MakeTypecastsImplicit().handle(expression)

    assert simplified.lhs is required_cast
    assert "".join(chunk for chunk, _ in simplified.c_repr_chunks()) == "(unsigned short)ptr & 0xff"


def test_address_term_recovery_preserves_width_changing_pointer_cast():
    project, _, codegen = _codegen([])
    pointer_type = SimTypePointer(SimTypeChar()).with_arch(project.arch)
    byte_type = SimTypeChar(signed=False).with_arch(project.arch)
    pointer = CFakeVariable("ptr", pointer_type, codegen=codegen)
    narrowing_cast = CTypeCast(pointer_type, byte_type, pointer, codegen=codegen)

    constant, terms = extract_terms(narrowing_cast)

    assert constant == 0
    assert terms == [(1, narrowing_cast)]


def test_fallback_address_renders_pointer_stride_as_an_integer():
    project, _, codegen = _codegen([])
    pointer_type = SimTypePointer(SimTypeShort(signed=False)).with_arch(project.arch)
    integer_type = SimTypeInt(signed=False).with_arch(project.arch)
    pointer = CFakeVariable("index", pointer_type, codegen=codegen)
    address = CBinaryOp(
        "Add",
        CConstant(0x100, integer_type, codegen=codegen),
        CBinaryOp(
            "Mul",
            CConstant(2, integer_type, codegen=codegen),
            pointer,
            codegen=codegen,
        ),
        codegen=codegen,
    )

    access = codegen._access(  # pylint:disable=protected-access
        address,
        SimTypeShort(signed=False).with_arch(project.arch),
        True,
    )
    rendered = "".join(chunk for chunk, _ in access.c_repr_chunks())

    assert "(unsigned short *)0x2" not in rendered
    assert "2 * (unsigned int)index" in rendered


def test_pointer_typed_switch_selector_is_coerced_to_its_ail_width():
    project, function, _ = _codegen([])
    selector_variable = SimStackVariable(-2, 2, ident="is_selector", name="selector", region=function.addr)
    variable_manager = project.kb.dec_variables[function.addr]
    variable_manager.set_variable_type(
        selector_variable,
        SimTypePointer(SimTypeShort(signed=False)).with_arch(project.arch),
    )
    selector = ailment.Expr.VirtualVariable(
        1,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.STACK,
        oident=-2,
    )
    variable_map = VariableMap()
    variable_map.set_variable(selector, selector_variable)
    case = SequenceNode(
        0x10,
        nodes=[ailment.Block(0x10, 1, statements=[])],
    )
    switch = SwitchCaseNode(selector, OrderedDict([(0, case)]), None, addr=0)

    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[switch]),
        variable_map=variable_map,
    )

    assert "switch ((unsigned short)selector)" in codegen.text
    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    restored.regenerate_text()
    assert "switch ((unsigned short)selector)" in restored.text


def test_collapsed_expression_is_reported_as_unsupported():
    project, function, _ = _codegen([])
    expression = ailment.Expr.Const(1, 1, 16)
    for idx in range(2, 7):
        expression = ailment.Expr.BinaryOp(
            idx,
            "Add",
            [expression, ailment.Expr.Const(idx + 10, idx, 16)],
            signed=False,
            bits=16,
        )
    block = ailment.Block(0, 1, statements=[ailment.Stmt.Return(0, [expression], ins_addr=0)])
    codegen = project.analyses.CStructuredCodeGenerator(
        function,
        SequenceNode(0, nodes=[block]),
        binop_depth_cutoff=2,
    )

    assert "..." in codegen.text
    assert any(item.kind == "collapsed_expression" for item in codegen.unsupported_constructs)


def test_unmapped_register_virtual_variable_remains_explicit():
    stack_pointer = ailment.Expr.VirtualVariable(
        0,
        1,
        16,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=16,
        reg_name="SP",
        ins_addr=0x100,
    )
    _, _, codegen = _codegen(
        [
            ailment.Stmt.Assignment(
                0,
                stack_pointer,
                ailment.Expr.Const(1, 0x1234, 16),
                ins_addr=0x100,
            )
        ]
    )

    assert codegen.unsupported_constructs == ()
    assert "sp = 4660;" in codegen.text
