#!/usr/bin/env python
"""
This module handles constraint generation.
"""

import logging
logging.getLogger("simuvex").addHandler(logging.NullHandler())

# pylint: disable=W0401

from .s_state import SimState
#from .s_unicorn import SimUnicorn
from .s_procedure import SimProcedure
from .procedures import SimProcedures
from .s_cc import SimCC, DefaultCC
from .s_slicer import SimSlicer

from . import procedures
from . import storage
from . import concretization_strategies
from . import s_options
from . import s_type_backend

from .engines import SimEngine, SimSuccessors, SimEngineVEX, SimEngineProcedure, SimEngineUnicorn
from .engines.vex.statements import SimIRStmt
from .engines.vex.irop import operations, all_operations, unsupported as unsupported_operations, unclassified as unclassified_operations

from .plugins import *
from .s_errors import *
from .s_action import *
from .s_pcap import *
from .s_variable import *

options = s_options
o = s_options
