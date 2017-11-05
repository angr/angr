import logging
import os

l = logging.getLogger("angr.procedures.procedure_dict")

from ..misc import autoimport
from ..sim_procedure import SimProcedure

# Import all classes under the current directory, and group them based on
# lib names.
SIM_PROCEDURES = {}
path = os.path.dirname(os.path.abspath(__file__))
skip_dirs = ['__pycache__', 'definitions']

for pkg_name, package in autoimport.auto_import_packages('angr.procedures', path, skip_dirs):
    SIM_PROCEDURES[pkg_name] = {}
    for _, mod in autoimport.filter_module(package, type_req=type(os)):
        for name, proc in autoimport.filter_module(mod, type_req=type, subclass_req=SimProcedure):
            SIM_PROCEDURES[pkg_name][name] = proc

class _SimProcedures(object):
    def __getitem__(self, k):
        l.critical("the SimProcedures dictionary is DEPRECATED. Please use the angr.SIM_PROCEDURES global dict instead.")
        return SIM_PROCEDURES[k]

    def __setitem__(self, k, v):
        l.critical("the SimProcedures dictionary is DEPRECATED. Please use the angr.SIM_PROCEDURES global dict instead.")
        SIM_PROCEDURES[k] = v
SimProcedures = _SimProcedures()
