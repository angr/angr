# pylint:disable=missing-class-docstring
from __future__ import annotations

from pydantic import BaseModel


class VariableRename(BaseModel):
    old_name: str
    new_name: str


class VariableNameSuggestions(BaseModel):
    renames: list[VariableRename]


class FunctionNameSuggestion(BaseModel):
    function_name: str


class VariableTypeChange(BaseModel):
    variable_name: str
    new_type: str


class VariableTypeSuggestions(BaseModel):
    type_changes: list[VariableTypeChange]
