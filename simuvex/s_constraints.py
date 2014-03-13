#!/usr/bin/env python

import symexec as se
from .s_state import SimStatePlugin

import logging
l = logging.getLogger("simuvex.constraints")

import itertools
from copy import copy

symbolic_count = itertools.count()

class SimConstraints(SimStatePlugin):
    def __init__(self, combined_solver=None):
        SimStatePlugin.__init__(self)
        self.variables_to_solvers = { }
        self.unconstrained = set()
        self.cache = { }
        self.variables = { }
        self._combined_solver = combined_solver

        self.stack = [ ]

    @property
    def combined_solver(self):
        if self._combined_solver is None:
            self._combined_solver = se.Solver()
            for n,c in self.cache.iteritems():
                self.combined_solver.add(self.variables[n] == c)
        return self._combined_solver

    @property
    def solvers(self):
        seen_solvers = set()
        solver_list = [ ]
        for s in self.variables_to_solvers.itervalues():
            if id(s) in seen_solvers: continue
            seen_solvers.add(id(s))
            solver_list.append(s)
        return solver_list

    def simplify(self):
        for s in self.solvers:
            s.simplify()

            if o.SPLIT_CONSTRAINTS in self.state.options:
                split = s.split()
                if len(split) > 1:
                    for s in split:
                        for v in s.variables:
                            self.variables_to_solvers[v] = s

    def _eval_variable(self, name):
        if name in self.cache:
            return self.cache[name]

        if name in self.variables_to_solvers:
            v = self.variables_to_solvers[name].eval(self.variables[name])
        else:
            l.warning("Assuming %s is unconstrained.", name)
            v = 0
        self.cache[name] = v
        return v

    def eval(self, e):
        if not se.is_symbolic(e): return se.concretize_constant(e)

        constituents = se.utils.variable_constituents(e)
        for c in constituents:
            v = self._eval_variable(c)
            self.combined_solver.add(self.variables[c] == v)

        return self.combined_solver.eval(e)

    def satisfiable(self):
        return all([ s.check() == se.sat for s in self.solvers ])

    def check(self):
        return se.sat if self.satisfiable() else se.unsat

    # for now
    def push(self):
        l.debug("PUSHING with %d solvers.", len(self.solvers))
        for s in self.solvers: s.push()
        self.stack.append((copy(self.variables_to_solvers), copy(self.unconstrained), copy(self.cache), copy(self.variables)))
        self.combined_solver.push()
    def pop(self):
        l.debug("POPING with %d solvers.", len(self.solvers))
        self.variables_to_solvers, self.unconstrained, self.cache, self.variables = self.stack.pop()
        if self._combined_solver is not None: self.combined_solver.pop()
        for s in self.solvers: s.pop()

    def new_symbolic(self, name, size):
        fullname = "%s_%d_%d" % (name, symbolic_count.next(), size)
        l.debug("Creating symbolic variable named %s", fullname)
        self.unconstrained.add(fullname)
        self.cache[fullname] = 0
        v = se.BitVec(fullname, size)
        self.variables[fullname] = v
        return v

    def add(self, *constraints):
        if len(constraints) == 0:
            return

        # first, flatten the constraints
        split = se.split_constraints(constraints)

        l.debug("%s, solvers before: %d", self, len(self.solvers))
        for names, set_constraints in split:
            l.debug("Checking %d constraints", len(set_constraints))
            seen_solvers = set()
            existing_solvers = [ ]

            for n in names:
                self.unconstrained.discard(n)

                if n not in self.variables_to_solvers: continue
                s = self.variables_to_solvers[n]

                if id(s) in seen_solvers: continue
                seen_solvers.add(id(s))
                existing_solvers.append(s)

            # totally unrelated to existing constraints
            if len(existing_solvers) == 0:
                l.debug("... got a new set of constraints!")
                new_solver = se.Solver()
                new_solver.add(*set_constraints)

            # fits within an existing solver
            elif len(existing_solvers) == 1:
                # TODO: split
                l.debug("... constraints fit into an existing solver.")
                new_solver = existing_solvers[0]
                new_solver.add(*set_constraints)

            # have to merge two solvers
            else:
                l.debug("... merging %d solvers.", len(existing_solvers))
                new_solver = se.Solver()
                for e in existing_solvers:
                    new_solver.add(*e.constraints)

            for n in names:
                self.variables_to_solvers[n] = new_solver

            # invalidate the solution cache
            for n in new_solver.variables:
                self.cache.pop(n, None)
                self._combined_solver = None
        l.debug("Solvers after: %d", len(self.solvers))

    def copy(self):
        c = SimConstraints(combined_solver=self.combined_solver.branch())
        for s in self.solvers:
            c_s = s.branch()
            for v in c_s.variables:
                c.variables_to_solvers[v] = c_s
        c.variables = copy(self.variables)
        return c

    def merge(self, others, merge_flag, flag_values): # pylint: disable=W0613
        raise Exception("merge() not implement for %s", self.__class__.__name__)

SimStatePlugin.register_default('constraints', SimConstraints)

import simuvex.s_options as o
