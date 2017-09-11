import os
import logging

import angr

from .tracerpov import TracerPoV

l = logging.getLogger("angr.misc.tracer.runner")

class Runner(object):
    """
    Base class of trace sources for angr Tracer exploration technique.
    """

    def __init__(self, project=None, binary=None, input=None, record_trace=False,
                 record_core=False, use_tiny_core=False, trace_source_path=None,
                 argv=None):
        """
        :param project          : The original project.
        :param binary           : Path to the binary to be traced.
        :param input            : Concrete input to feed to binary.
        :param record_trace     : Whether or not to record the basic block trace.
        :param record_core      : Whether or not to record the core file in case of crash.
        :param use_tiny_core    : Use minimal core loading.
        :param trace_source_path: Path to the trace source to be used.
        :param argv             : Optionally specify argv params (i,e,: ['./calc', 'parm1']).
                                  Defaults to binary name with no params.
        """
        if project is None and binary is None:
            raise ValueError("Must specify project or binary.")

        self._is_multicb = False

        if project is None:
            if isinstance(binary, basestring):
                self._binaries = [binary]
            elif isinstance(binary, (list, tuple)):
                if not multicb_available:
                    raise ValueError("Multicb tracing is disabled")
                self._is_multicb = True
                self._binaries = binary
            else:
                raise ValueError("Expected list or string for binary, got {} instead".format(type(binary)))
            self._p = angr.Project(self._binaries[0])
        else:
            self._p = project
            self._binaries = [project.filename]

        # Hack for architecture and OS.
        self.os = self._p.loader.main_object.os
        self.base_addr = self._p.loader.main_object.min_addr
        self.rebase = False

        self.input = input

        self._record_trace = record_trace
        self._record_core = record_core

        self.argv = argv

        # Basic block trace.
        self.trace = [ ]

        # In case of crash and record_core is set.
        self.crashed_binary = 0
        self.reg_vals = None
        self._state = None
        self.memory = None
        self._use_tiny_core = use_tiny_core

        self.trace_source = None
        self._trace_source_path = trace_source_path

        # Does the input cause a crash?
        self.crash_mode = False
        # If the input causes a crash, what address does it crash at?
        self.crash_addr = None

        self.stdout = None


### SETUP

    def _setup(self):
        """
        Make sure the environment is sane and we have everything we need to do
        a trace.
        """
        raise NotImplementedError('_setup() is not implemented.')


### DYNAMIC TRACING

    def _run(self, stdout_file=None):
        """
        Accumulate a basic block trace.
        """
        raise NotImplementedError('_run() is not implemented.')
