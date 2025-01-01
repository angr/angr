# Generating proto files
#
#  $ cd angr
#  $ protoc -I=. --python_out=. protos/*.proto
#  $ sed -i -e 's/from protos import/from . import/g' protos/*_pb2.py
#
# https://github.com/protocolbuffers/protobuf/issues/1491
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
