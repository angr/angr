import logging

import simuvex
from angr import Surveyor

l = logging.getLogger("angr.surveyors.executor")

class Executor(Surveyor):
    '''
    This class handles pure concrete execution related issues.
    No state splitting is ever allowed.
    '''
    def __init__(self, project, start, final_addr=None, \
                 max_run=500):
        if simuvex.o.SYMBOLIC in start.state.options:
            raise Exception("Executor doesn't support symbolic execution.")
        Surveyor.__init__(self, project, start=start)
        self._project = project
        self._final_addr = final_addr
        self._max_run = 5000
        self._done = False
        self._error_occured = False
        self._run_counter = 0

    @property
    def done(self):
        if len(self.active) > 1:
            raise Exception("We have more than one path in concrete mode." + \
                            " Something is wrong.")
        elif len(self.active) == 0:
            return True
        else:
            path = self.active[0]
            if path.last_run is not None and \
                    path.last_run.addr == self._final_addr:
                self.deadended.append(self.active[0])
                self.active = []
                return True
        return False

    @property
    def error_occured(self):
        if len(self.active) == 0:
            # The path ends before get to the target
            return True
        elif self._run_counter > self._max_run:
            return True
        return False

    @property
    def last_state(self):
        if self.done or self.error_occured:
            return None
        return self.active[0].last_run.state

    def tick(self):
        Surveyor.tick(self)
        self._run_counter += 1
        l.debug("Running %d run...", self._run_counter)

    def run(self):
        while not (self.done or self.error_occured):
            self.tick()
        return self
