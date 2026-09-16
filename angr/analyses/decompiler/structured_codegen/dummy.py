from __future__ import annotations

from angr.protos import codegen_pb2
from angr.serializable import Serializable

from .base import BaseStructuredCodeGenerator
from .c_serialize import _parse_const_formats, _parse_notes, _serialize_const_formats, _serialize_notes


class DummyStructuredCodeGenerator(BaseStructuredCodeGenerator, Serializable):
    """
    A dummy structured code generator that only stores user-specified information.
    """

    def __init__(self, flavor: str, expr_comments=None, stmt_comments=None, configuration=None, const_formats=None):
        super().__init__(flavor)
        self.expr_comments = expr_comments
        self.stmt_comments = stmt_comments
        self.configuration = configuration
        self.const_formats = const_formats

    #
    # Serialization: a Codegen message with no AST. `configuration` is not serialized; nothing populates it.
    #

    @classmethod
    def _get_cmsg(cls):
        return codegen_pb2.Codegen()

    def serialize_to_cmessage(self):
        msg = self._get_cmsg()
        if self.flavor is not None:
            msg.flavor = self.flavor
        if self.expr_comments:
            for k, v in self.expr_comments.items():
                msg.expr_comments[k] = v
        if self.stmt_comments:
            for k, v in self.stmt_comments.items():
                msg.stmt_comments[k] = v
        _serialize_notes(self.notes, msg.notes_json)
        _serialize_const_formats(self.const_formats, msg.const_formats)
        return msg

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        codegen = cls(
            cmsg.flavor if cmsg.HasField("flavor") else None,
            expr_comments=dict(cmsg.expr_comments) or None,
            stmt_comments=dict(cmsg.stmt_comments) or None,
            const_formats=_parse_const_formats(cmsg.const_formats) or None,
        )
        codegen.notes = _parse_notes(cmsg.notes_json)
        return codegen
