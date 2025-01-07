# Generating proto files
#
#  $ cd angr  # you would expect angr/protos to exist after this
#  $ protoc -I=. --python_out=. angr/protos/*.proto
from __future__ import annotations

from . import primitives_pb2
from . import function_pb2
from . import cfg_pb2
from . import xrefs_pb2
from . import variables_pb2

__all__ = (
    "cfg_pb2",
    "function_pb2",
    "primitives_pb2",
    "variables_pb2",
    "xrefs_pb2",
)
