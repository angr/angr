#!/usr/bin/env python3
"""Unit tests for ``FunctionPrototypeInference``'s pure prototype helpers.

The pass itself drives a heavy ``RustCallingConvention`` analysis on a real
``Project``. Its prototype-precision predicates, however, are pure functions
of ``RustSimTypeFunction`` shape and can be tested in isolation.
"""

from __future__ import annotations

from collections import OrderedDict

from angr.rust.optimization_passes.function_prototype_inference import FunctionPrototypeInference
from angr.rust.sim_type import (
    EnumVariant,
    RustSimEnum,
    RustSimStruct,
    RustSimTypeFunction,
    RustSimTypeInt,
    RustSimTypeOption,
    RustSimTypeResult,
)


def _u32() -> RustSimTypeInt:
    return RustSimTypeInt(32, signed=False)


def _u64() -> RustSimTypeInt:
    return RustSimTypeInt(64, signed=False)


def _two_field_struct(name: str = "S") -> RustSimStruct:
    return RustSimStruct(OrderedDict({"a": _u64(), "b": _u64()}), name=name, pack=True)


def _result_returning_proto() -> RustSimTypeFunction:
    return RustSimTypeFunction([], RustSimTypeResult(_u64(), 0, 0, _u64(), 1, 0))


def _option_returning_proto() -> RustSimTypeFunction:
    return RustSimTypeFunction([], RustSimTypeOption(0, 0, _u64(), 1, 0))


def _struct_returning_proto() -> RustSimTypeFunction:
    return RustSimTypeFunction([], _two_field_struct())


def _scalar_returning_proto() -> RustSimTypeFunction:
    return RustSimTypeFunction([], _u32())


def test_return_type_returns_none_for_non_rust_prototype():
    # The pass's predicates only fire on RustSimTypeFunction; non-Rust prototypes
    # must return None so callers can early-exit the inference path.
    assert FunctionPrototypeInference._return_type(None) is None
    assert FunctionPrototypeInference._return_type("not a prototype") is None


def test_return_type_extracts_from_normalized_function_prototype():
    proto = _scalar_returning_proto()
    assert FunctionPrototypeInference._return_type(proto) is proto.normalize().returnty


def test_can_refine_call_prototype_accepts_struct_return():
    # Composite (struct) returns are refinable — the inference pass may discover
    # they're actually enum-typed (Result/Option) at the callsite.
    assert FunctionPrototypeInference._can_refine_call_prototype(_struct_returning_proto()) is True


def test_can_refine_call_prototype_rejects_scalar_return():
    # Scalar returns are not "composite" and therefore not refinable.
    assert FunctionPrototypeInference._can_refine_call_prototype(_scalar_returning_proto()) is False


def test_can_refine_call_prototype_rejects_already_enum_return():
    # If the return is already an enum (Result/Option), there's nothing left to refine.
    assert FunctionPrototypeInference._can_refine_call_prototype(_result_returning_proto()) is False
    assert FunctionPrototypeInference._can_refine_call_prototype(_option_returning_proto()) is False


def test_should_refine_requires_both_callsite_hint_and_refinable_prototype():
    # No hint ⇒ no refinement, regardless of prototype shape.
    assert FunctionPrototypeInference._should_refine_call_prototype(_struct_returning_proto(), None) is False
    # Hint + refinable ⇒ refine.
    assert FunctionPrototypeInference._should_refine_call_prototype(_struct_returning_proto(), (0, True)) is True
    # Hint but not refinable ⇒ no refinement.
    assert FunctionPrototypeInference._should_refine_call_prototype(_scalar_returning_proto(), (0, True)) is False


def test_is_more_precise_prototype_treats_none_current_as_less_precise():
    # When there's no current prototype, any candidate is "more precise" iff non-None.
    assert FunctionPrototypeInference._is_more_precise_prototype(_struct_returning_proto(), None) is True
    assert FunctionPrototypeInference._is_more_precise_prototype(None, None) is False


def test_is_more_precise_prototype_returns_false_when_candidate_is_none():
    assert FunctionPrototypeInference._is_more_precise_prototype(None, _struct_returning_proto()) is False


def test_is_more_precise_prototype_promotes_struct_to_enum():
    # Result<u64, u64> is more precise than struct{a, b} for the same callsite.
    assert (
        FunctionPrototypeInference._is_more_precise_prototype(_result_returning_proto(), _struct_returning_proto())
        is True
    )


def test_is_more_precise_prototype_does_not_demote_enum_to_struct():
    # The opposite direction must NOT be a precision improvement.
    assert (
        FunctionPrototypeInference._is_more_precise_prototype(_struct_returning_proto(), _result_returning_proto())
        is False
    )


def test_is_more_precise_prototype_rejects_enum_to_enum_swap():
    # Enum-to-enum is not a precision improvement under this metric.
    custom_enum = RustSimEnum("MyEnum", [EnumVariant.from_no_data("A", 0, 1)])
    custom_proto = RustSimTypeFunction([], custom_enum)
    assert FunctionPrototypeInference._is_more_precise_prototype(custom_proto, _result_returning_proto()) is False
