import logging
import os

l = logging.getLogger(name=__name__)

from ..misc import autoimport
from ..sim_procedure import SimProcedure

# Import all classes under the current directory, and group them based on
# lib names.
SIM_PROCEDURES = {}
path = os.path.dirname(os.path.abspath(__file__))
skip_dirs = ['definitions']

for pkg_name, package in autoimport.auto_import_packages('angr.procedures', path, skip_dirs):
    for _, mod in autoimport.filter_module(package, type_req=type(os)):
        for name, proc in autoimport.filter_module(mod, type_req=type, subclass_req=SimProcedure):
            if hasattr(proc, "__provides__"):
                for custom_pkg_name, custom_func_name in proc.__provides__:
                    if custom_pkg_name not in SIM_PROCEDURES:
                        SIM_PROCEDURES[custom_pkg_name] = { }
                    SIM_PROCEDURES[custom_pkg_name][custom_func_name] = proc
            else:
                if pkg_name not in SIM_PROCEDURES:
                    SIM_PROCEDURES[pkg_name] = { }
                SIM_PROCEDURES[pkg_name][name] = proc
                if hasattr(proc, "ALT_NAMES") and proc.ALT_NAMES:
                    for altname in proc.ALT_NAMES:
                        SIM_PROCEDURES[pkg_name][altname] = proc
                if name == 'UnresolvableJumpTarget':
                    SIM_PROCEDURES[pkg_name]['UnresolvableTarget'] = proc


class _SimProcedures:
    def __getitem__(self, k):
        l.critical("the SimProcedures dictionary is DEPRECATED. Please use the angr.SIM_PROCEDURES global dict instead.")
        return SIM_PROCEDURES[k]

    def __setitem__(self, k, v):
        l.critical("the SimProcedures dictionary is DEPRECATED. Please use the angr.SIM_PROCEDURES global dict instead.")
        SIM_PROCEDURES[k] = v

SimProcedures = _SimProcedures()
