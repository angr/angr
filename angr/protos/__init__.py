# Generating proto files
#
#  $ cd angr
#  $ protoc -I=. --python_out=. protos/xxx.proto
#
# Then you need to manually fix all _pb2 imports to be relative because of this unresolved issue:
# https://github.com/protocolbuffers/protobuf/issues/1491
from __future__ import annotations

from . import primitives_pb2
from . import function_pb2
from . import cfg_pb2
from . import xrefs_pb2
from . import variables_pb2
