import logging
import angr

from .plugin import SimStatePlugin
from .. import sim_options as o

l = logging.getLogger("angr.state_plugins.preconstrainer")

class SimStatePreconstrainer(SimStatePlugin):
    """
    This state plugin handles preconstraints for tracer (or maybe for something else as well).
    """

    def __init__(self, input_content, magic_content=None, preconstrain_input=True, preconstrain_flag=True):
        SimStatePlugin.__init__(self)

        self._input_content = input_content
        self._magic_content = magic_content
        self._preconstrain_input = preconstrain_input
        self._preconstrain_flag = preconstrain_flag
        # map of variable string names to preconstraints, for re-applying
        # constraints
        self._variable_map = {}
        self.preconstraints = []
        self._constrained_addrs = []
        self._address_concretization = []

    def merge(self, others, merge_conditions, common_ancestor=None):
        l.warning("Merging is not implemented for preconstrainer!")
        return False

    def widen(self, others):
        l.warning("Widening is not implemented for preconstrainer!")
        return False

    def copy(self):
        c = SimStatePreconstrainer(input_content=self._input_content,
                                   magic_content=self._magic_content,
                                   preconstrain_input=self._preconstrain_input,
                                   preconstrain_flag=self._preconstrain_flag)
                                   
        c._variable_map = dict(self._variable_map)
        c.preconstraints = list(self.preconstraints)
        c._constrained_addrs = list(self._constrained_addrs)
        c._address_concretization = list(self._address_concretization)

        return c

    def _preconstrain(self, b, v):
        b_bvv = self.state.se.BVV(b)
        c = (v == b_bvv)
        # add the constraint for reconstraining later
        self._variable_map[list(v.variables)[0]] = c
        self.preconstraints.append(c)
        if o.REPLACEMENT_SOLVER in self.state.options:
            self.state.se._solver.add_replacement(v, b_bvv, invalidate_cache=False)

    def preconstrain_state(self):
        """
        Preconstrain the entry state to the input.
        """

        if not self._preconstrain_input:
            return

        if self._input_content is None:
            l.warning("Trying to preconstrain state without any input content.  Nothing will happen.")
            return

        l.debug("Preconstrain input is %r", self._input_content)
        repair_entry_state_opts = False
        if o.TRACK_ACTION_HISTORY in self.state.options:
            repair_entry_state_opts = True
            self.state.options -= {o.TRACK_ACTION_HISTORY}

        stdin = self.state.posix.get_file(0)
        if type(self._input_content) == str: # not a PoV, just raw input
            for b in self._input_content:
                self._preconstrain(b, stdin.read_from(1))

        elif type(self._input_content) == angr.misc.tracer.TracerPoV:  # a PoV, need to navigate the dialogue
            for write in self._input_content.writes:
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
            self.add_constraints(*self.preconstraints)

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
                    if var in self._variable_map:
                        state.add_constraints(self._variable_map[var])
                    else:
                        l.warning("var %s not found in self._variable_map", var)

    def grab_concretization_results(self):
        """
        Grabs the concretized result so we can add the constraint ourselves.
        """

        # only grab ones that match the constrained addrs
        if self._add_constraints():
            addr = self.state.inspect.address_concretization_expr
            result = self.state.inspect.address_concretization_result
            if result is None:
                l.warning("addr concretization result is None")
                return
            self._address_concretization.append((addr, result))

    def dont_add_constraints(self):
        """
        Obnoxious way to handle this, should ONLY be called from tracer.
        """

        # for each constrained addrs check to see if the variables match,
        # if so keep the constraints
        if self.state.has_plugin('inspector'):
            self.state.inspect.address_concretization_add_constraints = self._add_constraints()

    def _add_constraints(self):
        if self.state.has_plugin('inspector'):
            variables = self.state.inspect.address_concretization_expr.variables
            hit_indices = self._to_indices(variables)

            for action in self._constrained_addrs:
                var_indices = self._to_indices(action.addr.variables)
                if var_indices == hit_indices:
                    return True
        return False

    @staticmethod
    def _to_indices(variables):
        variables = [v for v in variables if v.startswith("file_/dev/stdin")]
        indices = map(lambda y: int(y.split("_")[3], 16), variables)
        return sorted(indices)

SimStatePlugin.register_default('preconstrainer', SimStatePreconstrainer)
