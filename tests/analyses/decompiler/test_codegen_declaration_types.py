from __future__ import annotations

import angr
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CFakeVariable,
    CFunction,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable


class _VariableManager:
    def __init__(self, types):
        self.types = types

    def get_variable_type(self, variable):
        return self.types[variable]


def _codegen():
    project = angr.load_shellcode(b"\xc3", arch="x86")
    codegen = DummyStructuredCodeGenerator("pseudocode", expr_comments={}, stmt_comments={}, const_formats={})
    codegen.project = project
    codegen.cfunc = None
    codegen.display_vvar_ids = False
    codegen.show_casts = True
    codegen.use_compound_assignments = False
    return project, codegen


def _render(construct):
    return "".join(text for text, _ in construct.c_repr_chunks())


def test_assignment_rechecks_the_type_of_a_rendered_unified_variable():
    project, codegen = _codegen()
    short_type = SimTypeShort().with_arch(project.arch)
    int_type = SimTypeInt().with_arch(project.arch)
    short_pointer = SimTypePointer(short_type).with_arch(project.arch)

    # This models a narrow access that was unified into a wider stack declaration. Before CFunction selects the
    # declaration, both sides appear to be short pointers and assignment construction therefore needs no cast.
    access = SimStackVariable(-4, 2, ident="is_0")
    declaration = SimStackVariable(-4, 4, ident="is_u", name="stack_int")
    variable = CVariable(
        access,
        unified_variable=declaration,
        variable_type=short_type,
        codegen=codegen,
    )
    reference = CUnaryOp("Reference", variable, codegen=codegen)
    destination = CUnaryOp(
        "Dereference",
        CFakeVariable(
            "slot_pointer",
            SimTypePointer(short_pointer).with_arch(project.arch),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    assignment = CAssignment(destination, reference, codegen=codegen)
    assert assignment.rhs is reference

    function = CFunction(
        0,
        "example",
        SimTypeFunction([], int_type).with_arch(project.arch),
        [],
        CStatements([], codegen=codegen),
        {access: variable},
        _VariableManager({access: int_type}),
        codegen=codegen,
    )
    codegen.cfunc = function

    assert variable.name == "stack_int"
    assert variable.type == int_type
    assert reference.type == SimTypePointer(int_type).with_arch(project.arch)
    declaration_text = "".join(text for text, _ in function.variable_list_repr_chunks())
    assert "int stack_int;" in declaration_text
    assert _render(assignment).strip() == "*(slot_pointer) = (short *)&stack_int;"


def test_assignment_does_not_add_a_cast_when_the_declaration_type_agrees():
    project, codegen = _codegen()
    short_type = SimTypeShort().with_arch(project.arch)
    short_pointer = SimTypePointer(short_type).with_arch(project.arch)
    access = SimStackVariable(-2, 2, ident="is_0")
    declaration = SimStackVariable(-2, 2, ident="is_u", name="stack_short")
    variable = CVariable(
        access,
        unified_variable=declaration,
        variable_type=short_type,
        codegen=codegen,
    )
    reference = CUnaryOp("Reference", variable, codegen=codegen)
    destination = CFakeVariable("destination", short_pointer, codegen=codegen)
    assignment = CAssignment(destination, reference, codegen=codegen)

    function = CFunction(
        0,
        "example",
        SimTypeFunction([], short_type).with_arch(project.arch),
        [],
        CStatements([], codegen=codegen),
        {access: variable},
        _VariableManager({access: short_type}),
        codegen=codegen,
    )
    codegen.cfunc = function

    assert _render(assignment).strip() == "destination = &stack_short;"
    assert assignment.rhs is reference


def test_reference_to_a_casted_lvalue_casts_its_address_instead():
    project, codegen = _codegen()
    int_type = SimTypeInt().with_arch(project.arch)
    short_type = SimTypeShort().with_arch(project.arch)
    slot = CFakeVariable("stack_slot", int_type, codegen=codegen)
    cast = CTypeCast(int_type, short_type, slot, codegen=codegen)
    reference = CUnaryOp("Reference", cast, codegen=codegen)

    rendered = _render(reference)
    assert rendered == "(short *)&stack_slot"
    assert "&(short)" not in rendered
    assert reference.type == SimTypePointer(short_type).with_arch(project.arch)


def test_assignment_through_a_casted_storage_view_is_a_valid_lvalue():
    project, codegen = _codegen()
    int_type = SimTypeInt().with_arch(project.arch)
    short_type = SimTypeShort().with_arch(project.arch)
    slot = CFakeVariable("stack_slot", int_type, codegen=codegen)
    value = CFakeVariable("value", short_type, codegen=codegen)
    assignment = CAssignment(
        CTypeCast(int_type, short_type, slot, codegen=codegen),
        value,
        codegen=codegen,
    )

    rendered = _render(assignment).strip()
    assert rendered == "*((short *)&stack_slot) = value;"
    assert "(short)stack_slot =" not in rendered
