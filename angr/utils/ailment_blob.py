"""
Helpers for the AilmentBlob bridging encoding.

AilmentBlob is the wrapper message used in protobuf to carry ailment-typed state that cannot yet be serialized natively
because the ailment data classes are being ported to Rust separately. During the bridging period, the payload is a
Python pickle blob (``format_version=1``). Once the Rust port lands, ``format_version=2`` will switch to a
serde-derived encoding without breaking the schema.
"""

from __future__ import annotations
import pickle
from typing import Any

from angr.protos import ailment_blob_pb2

_PICKLE_FORMAT_VERSION = 1


def pack(value: Any) -> ailment_blob_pb2.AilmentBlob:
    """Wrap a Python value into an AilmentBlob using the current bridging encoding (Python pickle)."""
    return ailment_blob_pb2.AilmentBlob(
        format_version=_PICKLE_FORMAT_VERSION,
        data=pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL),
    )


def unpack(blob: ailment_blob_pb2.AilmentBlob) -> Any:
    """Unwrap an AilmentBlob back into a Python value. Currently only the pickle format is recognized."""
    if blob.format_version != _PICKLE_FORMAT_VERSION:
        raise ValueError(
            f"Unsupported AilmentBlob format_version {blob.format_version}; "
            f"this build understands only version {_PICKLE_FORMAT_VERSION} (pickle)"
        )
    return pickle.loads(blob.data)
