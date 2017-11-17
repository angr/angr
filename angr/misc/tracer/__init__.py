import logging

from ...procedures.tracer import *

from ... import SIM_LIBRARIES
from ...project import Project
from ...errors import TracerEnvironmentError

l = logging.getLogger("angr.misc.tracer")

def make_tracer_project(binary, simprocedures=None, hooks=None, exclude_sim_procedures_list=(), **kwargs):
    """
    Returns a Project specifically configured for maximum tracing correctness.
    :param binary                     : The path to the main executable object to analyze, or a CLE Loader object.
    :param simprocedures              : Dictionary of replacement SimProcedures for library calls.
    :param hooks                      : Dictionary of of hooks to add for user functions.
    :param exclude_sim_procedures_list: What SimProcedures to hook or not at load time. Defaults to
                                        ["malloc","free","calloc","realloc"].
    :param kwargs                     : Any additional keyword arguments that will be passed to the
                                        Project constructor.
    """
#   exclude_sim_procedures_list = exclude_sim_procedures_list or ('malloc', 'free', 'calloc', 'realloc')
    simprocedures = {} if simprocedures is None else simprocedures
    hooks = {} if hooks is None else hooks

    project = Project(binary,
                      exclude_sim_procedures_list=exclude_sim_procedures_list,
                      **kwargs)

    os = project.loader.main_object.os
    if os == 'cgc':
        # FixedRandom, FixedInReceive, and FixedOutTransmit always are applied as defaults
        print project._simos.syscall_library.procedures
        project._simos.syscall_library.procedures.update(TRACER_CGC_SYSCALLS)
        print project._simos.syscall_library.procedures
#       SIM_LIBRARIES['cgcabi'].add('random', FixedRandom)
#       SIM_LIBRARIES['cgcabi'].add('receive', FixedInReceive)
#       SIM_LIBRARIES['cgcabi'].add('transmit', FixedOutTransmit)

        for symbol in simprocedures:
            SIM_LIBRARIES['cgcabi'].add(symbol, simprocedures[symbol])

    elif os.startswith('UNIX'):
        for symbol in simprocedures:
            project.hook_symbol(symbol, simprocedures[symbol])
        
    else:
        error_msg = "Binary running on the unsupported OS \"%s\" is trying to use tracer." % os
        error_msg += "Tracer only currently supports CGC and Unix binaries."
        l.error(error_msg)
        raise TracerEnvironmentError(error_msg)
    
    for addr, proc in hooks.items():
        project.hook(addr, proc)
        l.debug("Hooking %#x -> %s", addr, proc.display_name)
    
    return project
