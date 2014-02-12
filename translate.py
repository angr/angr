'''This module handles irsb generation.'''

import os

# importing stuff into the module namespace
from simuvex.s_value import ConcretizingException
from simuvex.s_irsb import SimIRSB, SimIRSBError
from simuvex.s_irstmt import SimIRStmt
from simuvex.s_exit import SimExit
from simuvex.s_state import SimState
from simuvex.s_memory import SimMemoryError
from angr.errors import AngrException

# to make the stupid thing stop complaining
SimIRStmt, ConcretizingException

import logging
l = logging.getLogger("sliceit.translate")


def handle_exit_concrete(project, concrete_start, current_exit):
    # irsb = pyvex.IRSB(bytes = bytes, mem_addr = concrete_start, arch=current_exit.state.arch.vex_arch)
    irsb = project.block(concrete_start)
    sirsb = SimIRSB(irsb, SimState(), mode='static')
    return sirsb


def concretize_exit(current_exit, fallback_state):
    sat_level = "constrained"

    # get the concrete value
    # TODO: deal with possibility of multiple exits
    l.debug("Concretizing start value...")

    #exit_state = current_exit.state

    # TODO: partial constraining
    # if not current_exit.reachable():
    #	l.warning("UNSAT exit condition. Falling back to fallback state.")
    #	sat_level = "fallback"
    #	current_exit.state = fallback_state

    # if not current_exit.reachable():
    #	l.warning("UNSAT exit condition. Falling back to unconstrained state.")
    #	sat_level = "unconstrained"
    #	current_exit.state = exit_state.copy_after()
    #	current_exit.state.clear_constraints()

    if not current_exit.reachable():
        l.warning("UNSAT exit condition with fallback state. Aborting.")
        # return "unsat", None

    # now figure out how many values the exit has
    try:
        l.debug(
            "Constraints_after: %s" %
            current_exit.state.constraints_after())
        l.debug("Name of exit state: %s" % current_exit.state.id)
        concrete_starts = [current_exit.concretize()]
    except ConcretizingException:
        import ipdb
        ipdb.set_trace()
        max_multiple = 256
        concrete_starts = current_exit.concretize_n(max_multiple)

        l.debug("Got %d possibilities for exit." % len(concrete_starts))
        l.debug("Concretized starts: %s" % concrete_starts)
        if len(concrete_starts) == max_multiple:
            l.warning(
                "Exit concretized into the maximum number of targets. Ignoring.")
            concrete_starts = []

    return sat_level, concrete_starts


def handle_exit(project, current_exit, fallback_state):
    sirsb = None

    l.debug("... processing block")
    # Here it might raise exception inside pysex if we encounter
    # some instructions that VEX doesn't understand.
    # Let's catch it here to minimize its influences, so the
    # whole function that we have analyzed up to now will still be preserved.
    concrete_start = current_exit.concretize()
    if concrete_start is not None:
        l.debug("Concrete_start = 0x%x" % concrete_start)
        try:
            sirsb = handle_exit_concrete(project, concrete_start, current_exit)
        except SimIRSBError:
            l.warning(
                "SimIRSB error caught. Skipping this one.",
                exc_info=True)
        except SimMemoryError:
            l.warning(
                "Constraints are not satisfiable. This exit should not be taken.")
    else:
        l.debug("concrete_start is None!")

    return sirsb


def translate_bytes(project, entry, initial_state=None, arch="AMD64"):
    l.debug("Translating %x..." % (entry))

    # take an initial exit
    if initial_state:
        l.debug("Received initial state.")

    entry_state = initial_state if initial_state else SimState(arch=arch)
    entry_point = SimExit(addr=entry, state=entry_state, static=True)

    try:
        sirsb = handle_exit(project, entry_point, entry_state)
    except AngrException:
        sirsb = None

    return sirsb
