# The *_pb2.py modules in this package are generated from the .proto sources at build/install time (see
# build_protos() in setup.py) and are not committed. After editing a .proto, regenerate manually with
#
#  $ cd angr  # the repository root; you would expect angr/protos to exist after this
#  $ python -m grpc_tools.protoc -I. --python_out=. angr/protos/*.proto
#
# (grpcio-tools is a build dependency; installs with --no-build-isolation need it installed in the environment.)
from __future__ import annotations

from . import cfg_pb2, function_pb2, primitives_pb2, variables_pb2, xrefs_pb2

__all__ = (
    "cfg_pb2",
    "function_pb2",
    "primitives_pb2",
    "variables_pb2",
    "xrefs_pb2",
)
