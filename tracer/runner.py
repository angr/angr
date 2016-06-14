import os
import angr
import time
import shutil
import signal
import socket
import logging
import resource
import tempfile
import subprocess

from .tracerpov import TracerPoV
from .tracer import TracerEnvironmentError, TracerInstallError

l = logging.getLogger("tracer.Runner")


class Runner(object):
    """
    Trace an angr path with a concrete input
    """

    def __init__(self, binary, input=None, pov_file=None, record_trace=False, record_stdout=False):
        """
        :param binary: path to the binary to be traced
        :param input: concrete input string to feed to binary
        :param pov_file: CGC PoV describing the input to trace
        :param record_trace: whether or not to record the basic block trace
        """

        self.binary = binary
        self.input = input
        self.pov_file = pov_file
        self._record_trace = record_trace
        self.trace = None
        self.reg_vals = None
        self._state = None
        self.memory = None

        if self.pov_file is None and self.input is None:
            raise ValueError("must specify input or pov_file")

        if self.pov_file is not None and self.input is not None:
            raise ValueError("cannot specify both a pov_file and an input")

        # a PoV was provided
        if self.pov_file is not None:
            self.pov_file = TracerPoV(self.pov_file)
            self.pov = True
        else:
            self.pov = False

        self.base = os.path.join(os.path.dirname(__file__), "..", "..")

        self.tracer_qemu = None
        self.tracer_qemu_path = None

        self._setup()

        l.debug("accumulating basic block trace...")
        l.debug("self.tracer_qemu_path: %s", self.tracer_qemu_path)

        # does the input cause a crash?
        self.crash_mode = False
        # if the input causes a crash, what address does it crash at?
        self.crash_addr = None

        self.stdout = None

        if record_stdout:
            tmp = tempfile.mktemp(prefix="stdout_" + os.path.basename(binary))
            # will set crash_mode correctly
            self.dynamic_trace(stdout_file=tmp)
            with open(tmp, "rb") as f:
                self.stdout = f.read()
            os.remove(tmp)
        else:
            # will set crash_mode correctly
            self.dynamic_trace()


### SETUP

    def _setup(self):
        """
        make sure the environment is sane and we have everything we need to do a trace
        """
        # check the binary
        if not os.access(self.binary, os.X_OK):
            if os.path.isfile(self.binary):
                l.error("\"%s\" binary is not executable", self.binary)
                raise TracerEnvironmentError
            else:
                l.error("\"%s\" binary does not exist", self.binary)
                raise TracerEnvironmentError

        # hack for the OS
        with open(self.binary, "rb") as f:
            header = f.read(4)
            header = header[1:]
        if header == "CGC":
            self.os = "cgc"
        else:
            self.os = None

        if self.os != "cgc":
            l.error("\"%s\" runs on an OS not supported by the runner (only cgc at the moment)", self.binary)
            raise TracerEnvironmentError

        # try to find the install base
        self.base = os.path.dirname(__file__)
        self._adjust_base()

        try:
            self._check_qemu_install()
        except TracerEnvironmentError:
            self.base = os.path.join(self.base, "..", "..")
            self._check_qemu_install()

        return True

    def _adjust_base(self):
        """
        adjust self.base to point to the directory containing bin, there should always be a directory
        containing bin below base intially
        """

        while "bin" not in os.listdir(self.base) and os.path.abspath(self.base) != "/":
            self.base = os.path.join(self.base, "..")

        if os.path.abspath(self.base) == "/":
            raise TracerInstallError("could not find tracer install directory")

    def _check_qemu_install(self):
        """
        check the install location of qemu
        """

        if self.os == "cgc":
            self.tracer_qemu = "tracer-qemu-cgc"

        self.tracer_qemu_path = os.path.join(self.base, "bin", self.tracer_qemu)

        if not os.access(self.tracer_qemu_path, os.X_OK):
            if os.path.isfile(self.tracer_qemu_path):
                l.error("%s is not executable" % self.tracer_qemu)
                raise TracerEnvironmentError
            else:
                l.error("\"%s\" does not exist", self.tracer_qemu_path)
                raise TracerEnvironmentError

### DYNAMIC TRACING

    def dynamic_trace(self, stdout_file=None):
        # allow cores to be dumped
        saved_limit = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE,
                           (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

        binary_name = os.path.basename(self.binary)
        binary_replacement = tempfile.mktemp(prefix=binary_name)
        shutil.copy(self.binary, binary_replacement)
        binary_back = self.binary
        self.binary = binary_replacement

        # some hacks to guarantee the coredump file has a unique filename
        return_dir = os.getcwd()
        os.chdir('/dev/shm')

        # get the dynamic trace
        self._run_trace(stdout_file=stdout_file)

        # restore the resource limit now that the binary has run
        resource.setrlimit(resource.RLIMIT_CORE, saved_limit)

        if self.crash_mode:
            # find core file
            unique_prefix = "qemu_{}".format(os.path.basename(binary_replacement))
            core_files = filter(
                    lambda x: x.startswith(unique_prefix) and x.endswith('.core'),
                    os.listdir('.')
                    )

            a_mesg = "No core files found for binary, this shouldn't happen"
            assert len(core_files) > 0, a_mesg
            a_mesg = "Multiple core files found for binary, this shouldn't happen"
            assert len(core_files) < 2, a_mesg
            core_file = core_files[0]
            self._load_core_values(core_file)
            os.remove(core_file)

        # undo stuff
        self.binary = binary_back
        os.remove(binary_replacement)
        os.chdir(return_dir)

    def _run_trace(self, stdout_file=None):
        """
        accumulate a basic block trace using qemu
        """

        logname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-log-")
        if self._record_trace:
            args = [self.tracer_qemu_path, "-d", "exec", "-D", logname, self.binary]
        else:
            args = [self.tracer_qemu_path, self.binary]

        with open('/dev/null', 'wb') as devnull:
            stdout_f = devnull
            if stdout_file is not None:
                stdout_f = open(stdout_file, 'wb')

            # we assume qemu with always exit and won't block
            if self.pov_file is None:
                l.info("tracing as raw input")
                p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=stdout_f, stderr=devnull)
                _, _ = p.communicate(self.input)
            else:
                l.info("tracing as pov file")
                in_s, out_s = socket.socketpair()
                p = subprocess.Popen(args, stdin=in_s, stdout=stdout_f, stderr=devnull)

                for write in self.pov_file.writes:
                    out_s.send(write)
                    time.sleep(.01)

            ret = p.wait()
            # did a crash occur?
            if ret < 0:
                if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
                    l.info("input caused a crash (signal %d) during dynamic tracing", abs(ret))
                    l.info("entering crash mode")
                    self.crash_mode = True

            if stdout_file is not None:
                stdout_f.close()

        if self._record_trace:
            trace = open(logname).read()
            addrs = [int(v.split('[')[1].split(']')[0], 16)
                     for v in trace.split('\n')
                     if v.startswith('Trace')]

            # grab the faulting address
            if self.crash_mode:
                self.crash_addr = int(trace.split('\n')[-2].split('[')[1].split(']')[0], 16)

            os.remove(logname)
            self.trace = addrs
            l.debug("trace consists of %d basic blocks", len(self.trace))

    def _load_core_values(self, core_file):
        p = angr.Project(core_file)
        self.reg_vals = {reg:val for (reg, val) in p.loader.main_bin.initial_register_values()}
        self._state = p.factory.entry_state()
        self.memory = self._state.memory
