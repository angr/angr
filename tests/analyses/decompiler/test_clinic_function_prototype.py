from __future__ import annotations

import logging
import os
import unittest
from typing import cast

import archinfo

import angr
from angr import ailment
from angr.analyses import Decompiler
from angr.analyses.decompiler.c_prototype import c_function_type_with_array_return_decay
from angr.analyses.decompiler.structured_codegen.c import CArrayTypeLength, CStructuredCodeGenerator
from angr.calling_conventions import SimRegArg, default_cc
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeArray, SimTypeChar, SimTypeFunction, SimTypeInt, SimTypePointer
from angr.sim_variable import SimRegisterVariable
from tests.common import bin_location


class TestClinicFunctionPrototype(unittest.TestCase):
    """Tests for keeping the C prototype view separate from the shared function prototype."""

    def test_c_array_return_decay_is_local_and_only_applies_once(self):
        arch = archinfo.ArchAMD64()
        argument_type = SimTypeArray(SimTypeInt(), 2, qualifier=("volatile",))
        inner_return_type = SimTypeArray(SimTypeChar(), 4, qualifier=("volatile",))
        return_type = SimTypeArray(inner_return_type, 8, qualifier=("const",))
        prototype = cast(
            SimTypeFunction,
            SimTypeFunction(
                [argument_type], return_type, label="array_return", arg_names=("items",), variadic=True
            ).with_arch(arch),
        )
        original_return_type = prototype.returnty
        self.assertIsInstance(original_return_type, SimTypeArray)
        original_return_type = cast(SimTypeArray, original_return_type)
        original_inner_return_type = original_return_type.elem_type
        self.assertIsInstance(original_inner_return_type, SimTypeArray)

        c_prototype = c_function_type_with_array_return_decay(prototype, arch)

        self.assertIsNot(c_prototype, prototype)
        self.assertIs(c_prototype.args, prototype.args)
        self.assertIs(c_prototype.args[0], prototype.args[0])
        self.assertEqual(c_prototype.label, prototype.label)
        self.assertEqual(c_prototype.arg_names, prototype.arg_names)
        self.assertTrue(c_prototype.variadic)
        self.assertIsInstance(c_prototype.returnty, SimTypePointer)
        c_return_type = cast(SimTypePointer, c_prototype.returnty)
        self.assertIsInstance(c_return_type.pts_to, SimTypeArray)
        pointed_to = cast(SimTypeArray, c_return_type.pts_to)
        self.assertEqual(pointed_to.length, 4)
        self.assertEqual(set(pointed_to.qualifier or ()), {"const", "volatile"})
        self.assertFalse(pointed_to.elem_type.qualifier)

        self.assertIs(prototype.returnty, original_return_type)
        self.assertIs(original_return_type.elem_type, original_inner_return_type)
        self.assertEqual(original_return_type.qualifier, ("const",))
        self.assertEqual(original_inner_return_type.qualifier, ("volatile",))
        self.assertIs(c_function_type_with_array_return_decay(c_prototype, arch), c_prototype)

    def test_non_array_return_keeps_the_original_prototype(self):
        prototype = SimTypeFunction([SimTypeArray(SimTypeChar(), 3)], SimTypeInt(signed=False))

        self.assertIs(c_function_type_with_array_return_decay(prototype, archinfo.ArchAMD64()), prototype)

    def test_c_array_return_view_does_not_mutate_shared_prototype(self):
        for flavors in (("pseudocode", "rust"), ("rust", "pseudocode")):
            with self.subTest(flavors=flavors):
                project = angr.Project(
                    os.path.join(bin_location, "tests", "x86_64", "fauxware"),
                    auto_load_libs=False,
                )
                cfg = project.analyses.CFGFast(normalize=True, data_references=True)
                function = cast(Function, cfg.functions["authenticate"])

                inner_return_type = SimTypeArray(SimTypeChar(), 4, qualifier=("volatile",))
                return_type = SimTypeArray(inner_return_type, 8, qualifier=("const",))
                prototype = cast(
                    SimTypeFunction,
                    SimTypeFunction(
                        [SimTypePointer(SimTypeChar()), SimTypePointer(SimTypeChar())],
                        return_type,
                        arg_names=("username", "password"),
                    ).with_arch(project.arch),
                )
                function.prototype = prototype
                function.prototype_source = PrototypeSource.USER
                calling_convention = default_cc(project.arch.name)
                if calling_convention is None:
                    self.fail(f"No default calling convention for {project.arch.name}")
                function.calling_convention = calling_convention(project.arch)

                for flavor in flavors:
                    if flavor == "pseudocode":
                        log_context = self.assertNoLogs("angr.analyses.decompiler.return_maker", level=logging.WARNING)
                        with log_context:
                            decompilation = project.analyses[Decompiler].prep(fail_fast=True)(
                                function,
                                cfg=cfg.model,
                                flavor=flavor,
                            )
                    else:
                        decompilation = project.analyses[Decompiler].prep(fail_fast=True)(
                            function,
                            cfg=cfg.model,
                            flavor=flavor,
                        )

                    codegen = decompilation.codegen
                    if codegen is None or codegen.text is None:
                        self.fail("Decompiler did not produce source text")
                    text = codegen.text
                    self.assertIs(function.prototype, prototype)
                    self.assertIs(function.prototype_source, PrototypeSource.USER)
                    self.assertIs(function.prototype.returnty, prototype.returnty)
                    self.assertIs(function.prototype.args, prototype.args)

                    clinic = decompilation.clinic
                    if clinic is None:
                        self.fail("Decompiler did not produce a Clinic result")
                    assert clinic is not None and clinic.arg_list is not None
                    expected_prototype = (
                        c_function_type_with_array_return_decay(prototype, project.arch)
                        if flavor == "pseudocode"
                        else prototype
                    )
                    expected_arg_locs = function.calling_convention.arg_locs(expected_prototype)
                    self.assertTrue(all(isinstance(arg_loc, SimRegArg) for arg_loc in expected_arg_locs))
                    self.assertTrue(all(isinstance(arg, SimRegisterVariable) for arg in clinic.arg_list))
                    self.assertEqual(
                        [cast(SimRegisterVariable, arg).reg for arg in clinic.arg_list],
                        [project.arch.registers[cast(SimRegArg, arg_loc).reg_name][0] for arg_loc in expected_arg_locs],
                    )

                    if flavor == "rust":
                        self.assertIn("[8][4]", text)
                        continue

                    self.assertIsInstance(codegen, CStructuredCodeGenerator)
                    c_codegen = cast(CStructuredCodeGenerator, codegen)
                    c_function = c_codegen.cfunc
                    if c_function is None:
                        self.fail("C code generator did not produce a function")
                    self.assertIs(c_function.functy.args, prototype.args)
                    self.assertIsInstance(c_function.functy.returnty, SimTypePointer)
                    c_return_type = cast(SimTypePointer, c_function.functy.returnty)
                    self.assertIsInstance(c_return_type.pts_to, SimTypeArray)
                    pointed_to = cast(SimTypeArray, c_return_type.pts_to)
                    self.assertEqual(pointed_to.length, 4)
                    self.assertEqual(set(pointed_to.qualifier or ()), {"const", "volatile"})
                    self.assertIn(
                        "const volatile char (*authenticate(char *username, char *password))[4]",
                        text,
                    )

                    chunks = list(c_function.full_c_repr_chunks())
                    self.assertTrue(any(text == "authenticate" and owner is c_function for text, owner in chunks))
                    self.assertTrue(
                        any(
                            text == ")[4]" and isinstance(owner, CArrayTypeLength) and owner.text == ")[4]"
                            for text, owner in chunks
                        )
                    )
                    self.assertTrue(
                        any(text.endswith("char (*") and owner is c_function.functy.returnty for text, owner in chunks)
                    )

    def test_c_array_return_callee_uses_local_callsite_prototype(self):
        project = angr.Project(
            os.path.join(bin_location, "tests", "x86_64", "fauxware"),
            auto_load_libs=False,
        )
        cfg = project.analyses.CFGFast(normalize=True, data_references=True)
        callee = cast(Function, cfg.functions["authenticate"])
        prototype = cast(
            SimTypeFunction,
            SimTypeFunction(
                [SimTypePointer(SimTypeChar()), SimTypePointer(SimTypeChar())],
                SimTypeArray(SimTypeArray(SimTypeChar(), 4), 8),
            ).with_arch(project.arch),
        )
        callee.prototype = prototype
        callee.prototype_source = PrototypeSource.USER
        calling_convention = default_cc(project.arch.name)
        if calling_convention is None:
            self.fail(f"No default calling convention for {project.arch.name}")
        callee.calling_convention = calling_convention(project.arch)

        caller = cast(Function, cfg.functions["main"])
        decompilation = project.analyses[Decompiler].prep(fail_fast=True)(
            caller,
            cfg=cfg.model,
            flavor="pseudocode",
        )
        clinic = decompilation.clinic
        if clinic is None:
            self.fail("Decompiler did not produce a Clinic result")
        assert clinic is not None and clinic.graph is not None

        call = None
        for block in clinic.graph.nodes():
            for statement in block.statements:
                candidate = None
                if isinstance(statement, ailment.Stmt.SideEffectStatement):
                    candidate = statement.expr
                elif isinstance(statement, ailment.Stmt.Assignment):
                    candidate = statement.src
                    if isinstance(candidate, ailment.Expr.Convert):
                        candidate = candidate.operand
                if (
                    isinstance(candidate, ailment.Expr.Call)
                    and isinstance(candidate.target, ailment.Expr.Const)
                    and candidate.target.value == callee.addr
                ):
                    call = candidate
                    break
            if call is not None:
                break

        if call is None:
            self.fail("Decompiler did not retain the call to authenticate")
        callsite_prototype = clinic.variable_map.prototype(call)
        self.assertIsNotNone(callsite_prototype)
        assert callsite_prototype is not None
        self.assertIsInstance(callsite_prototype.returnty, SimTypePointer)
        self.assertIsInstance(callee.prototype.returnty, SimTypeArray)
        self.assertIs(callee.prototype_source, PrototypeSource.USER)
        codegen = decompilation.codegen
        if codegen is None or codegen.text is None:
            self.fail("Decompiler did not produce source text")
        assert codegen is not None and codegen.text is not None
        self.assertIn("authenticate(", codegen.text)


if __name__ == "__main__":
    unittest.main()
