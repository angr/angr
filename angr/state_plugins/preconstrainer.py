import logging

from .plugin import SimStatePlugin
from .. import sim_options as o
from ..storage.file import SimDialogue


l = logging.getLogger("angr.state_plugins.preconstrainer")


class SimStatePreconstrainer(SimStatePlugin):
    """
    This state plugin handles preconstraints for tracer (or maybe for something else as well).
    """

    def __init__(self, input_content=None, magic_content=None, preconstrain_input=True,
                 preconstrain_flag=True, constrained_addrs=None):
        """
        :param input_content     : Concrete input to feed to binary.
        :param magic_content     : CGC magic flag page.
        :param preconstrain_input: Should the path be preconstrained to the provided input?
        :param preconstrain_flag : Should the path have the CGC flag page preconstrained?
        :param constrained_addrs : Addresses which have had constraints applied to them and should not be removed.
        """
        SimStatePlugin.__init__(self)

        self.input_content = input_content
        self._magic_content = magic_content
        self._preconstrain_input = preconstrain_input
        self._preconstrain_flag = preconstrain_flag
        # map of variable string names to preconstraints, for re-applying constraints.
        self.variable_map = {}
        self.preconstraints = []
        self._constrained_addrs = [] if constrained_addrs is None else constrained_addrs
        self.address_concretization = []

    def merge(self, others, merge_conditions, common_ancestor=None):
        l.warning("Merging is not implemented for preconstrainer!")
        return False

    def widen(self, others):
        l.warning("Widening is not implemented for preconstrainer!")
        return False

    def copy(self):
        c = SimStatePreconstrainer(input_content=self.input_content,
                                   magic_content=self._magic_content,
                                   preconstrain_input=self._preconstrain_input,
                                   preconstrain_flag=self._preconstrain_flag,
                                   constrained_addrs=self._constrained_addrs)

        c.variable_map = dict(self.variable_map)
        c.preconstraints = list(self.preconstraints)
        c.address_concretization = list(self.address_concretization)

        return c

    def _preconstrain(self, b, v):
        b_bvv = self.state.se.BVV(b)
        c = (v == b_bvv)
        # add the constraint for reconstraining later
        self.variable_map[list(v.variables)[0]] = c
        self.preconstraints.append(c)
        if o.REPLACEMENT_SOLVER in self.state.options:
            self.state.se._solver.add_replacement(v, b_bvv, invalidate_cache=False)

    def preconstrain_state(self):
        """
        Preconstrain the entry state to the input.
        """

        if not self._preconstrain_input:
            return

        l.debug("Preconstrain input is %r", self.input_content)

        repair_entry_state_opts = False
        if o.TRACK_ACTION_HISTORY in self.state.options:
            repair_entry_state_opts = True
            self.state.options -= {o.TRACK_ACTION_HISTORY}

        stdin = self.state.posix.get_file(0)
        if type(self.input_content) is str: # not a PoV, just raw input
            for b in self.input_content:
                self._preconstrain(b, stdin.read_from(1))

        elif type(self.input_content.getattr('stdin', None)) is SimDialogue: # a PoV, need to navigate the dialogue
            for write in self.input_content.writes:
                for b in write:
                    self._preconstrain(b, stdin.read_from(1))
        else:
            l.error("Preconstrainer currently only supports a string or a TracerPoV as input content.")
            return

        stdin.seek(0)

        if repair_entry_state_opts:
            self.state.options |= {o.TRACK_ACTION_HISTORY}

        # add the preconstraints to the actual constraints on the state if we aren't replacing
        if o.REPLACEMENT_SOLVER not in self.state.options:
            self.state.add_constraints(*self.preconstraints)

    def preconstrain_flag_page(self):
        """
        Preconstrain the data in the flag page.
        """

        if not self._preconstrain_flag:
            return

        if self._magic_content is None:
            e_msg = "Trying to preconstrain flag page without CGC magic content. "
            e_msg += "You should have set record_magic flag for Runner dynamic tracing. "
            e_msg += "For now, nothing will happen."
            l.warning(e_msg)
            return

        for b in range(0x1000):
            self._preconstrain(self._magic_content[b], self.state.cgc.flag_bytes[b])

    def remove_preconstraints(self, to_composite_solver=True, simplify=True):
        if not (self._preconstrain_input or self._preconstrain_flag):
            return

        # cache key set creation
        precon_cache_keys = set()

        for con in self.preconstraints:
            precon_cache_keys.add(con.cache_key)

        # if we used the replacement solver we didn't add constraints we need to remove so keep all constraints
        if o.REPLACEMENT_SOLVER in self.state.options:
            new_constraints = self.state.se.constraints
        else:
            new_constraints = filter(lambda x: x.cache_key not in precon_cache_keys, self.state.se.constraints)


        if self.state.has_plugin("zen_plugin"):
            new_constraints = self.state.get_plugin("zen_plugin").filter_constraints(new_constraints)

        if to_composite_solver:
            self.state.options.discard(o.REPLACEMENT_SOLVER)
            self.state.options.add(o.COMPOSITE_SOLVER)

        self.state.release_plugin('solver_engine')
        self.state.add_constraints(*new_constraints)

        l.debug("downsizing unpreconstrained state")
        self.state.downsize()

        if simplify:
            l.debug("simplifying solver")
            self.state.se.simplify()
            l.debug("simplification done")

        self.state.se._solver.result = None

    def reconstrain(self):
        """
        Re-apply preconstraints to improve solver time, hopefully these
        constraints still allow us to do meaningful things to state.
        """

        # test all solver splits
        subsolvers = self.state.se._solver.split()

        for solver in subsolvers:
            solver.timeout = 1000 * 10  # 10 seconds
            if not solver.satisfiable():
                for var in solver.variables:
                    if var in self.variable_map:
                        self.state.add_constraints(self.variable_map[var])
                    else:
                        l.warning("var %s not found in self.variable_map", var)


SimStatePlugin.register_default('preconstrainer', SimStatePreconstrainer)
