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
import contextlib
import shellphish_qemu

from .tracerpov import TracerPoV
from .tracer import TracerEnvironmentError, TracerInstallError
from .tinycore import TinyCore

l = logging.getLogger("tracer.Runner")

multicb_available = True

try:
    import shellphish_afl
except ImportError:
    l.warning("Unable to import shellphish_afl, multicb tracing will be disabled")
    multicb_available = False

class Runner(object):
    """
    Trace an angr path with a concrete input
    """

    def __init__(self, binary, input=None, pov_file=None, record_trace=False, record_stdout=False, record_magic=False,
                 seed=None, memory_limit="8G", bitflip=False, report_bad_args=False, use_tiny_core=False, qemu=None):
        """
        :param binary: path to the binary to be traced
        :param input: concrete input string to feed to binary
        :param pov_file: CGC PoV describing the input to trace
        :param record_trace: whether or not to record the basic block trace
        :param report_bad_arg: enable CGC QEMU's report bad args option
        :param use_tiny_core: Use minimal core loading
        """

        if isinstance(binary, basestring):
            self.is_multicb = False
            self.binaries = [binary]
        elif isinstance(binary, (list, tuple)):
            if not multicb_available:
                raise ValueError("Multicb tracing is disabled")
            self.is_multicb = True
            self.binaries = binary

        else:
            raise ValueError("Expected list or string for binary, got {} instead".format(type(binary)))

        self.input = input
        self.pov_file = pov_file
        self._record_magic = record_magic
        self._record_trace = record_trace

        if record_trace and self.is_multicb:
            l.warning("record_trace specified with multicb, no trace will be recorded")

        self.trace = [ ]
        self.crashed_binary = 0
        self.reg_vals = None
        self._state = None
        self.memory = None
        self.seed = seed
        self.memory_limit = memory_limit
        self.bitflip = bitflip

        if self.bitflip and self.is_multicb:
            raise ValueError("Cannot perform bitflip with MultiCB")

        self.report_bad_args = report_bad_args
        self.use_tiny_core = use_tiny_core

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
        self.forced_qemu = qemu

        self.fakeforksrv_path = os.path.join(shellphish_afl.afl_dir('multi-cgc'), "run_via_fakeforksrv")

        self._setup()

        l.debug("accumulating basic block trace...")
        l.debug("self.tracer_qemu_path: %s", self.tracer_qemu_path)

        # does the input cause a crash?
        self.crash_mode = False
        # if the input causes a crash, what address does it crash at?
        self.crash_addr = None

        self.stdout = None
        self.magic = None

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

    @staticmethod
    def _memory_limit_to_int(ms):

        if not isinstance(ms, str):
            raise ValueError("memory_limit must be a string such as \"8G\"")

        if ms.endswith('k'):
            return int(ms[:-1]) * 1024
        elif ms.endswith('M'):
            return int(ms[:-1]) * 1024 * 1024
        elif ms.endswith('G'):
            return int(ms[:-1]) * 1024 * 1024 * 1024

        raise ValueError("unrecognized size, should be 'k', 'M', or 'G'")

    def _setup(self):
        """
        make sure the environment is sane and we have everything we need to do a trace
        """
        # check the binary
        for binary in self.binaries:
            if not os.access(binary, os.X_OK):
                if os.path.isfile(binary):
                    error_msg = "\"%s\" binary is not executable" % binary
                    l.error(error_msg)
                    raise TracerEnvironmentError(error_msg)
                else:
                    error_msg = "\"%s\" binary does not exist" % binary
                    l.error(error_msg)
                    raise TracerEnvironmentError(error_msg)

        if self.is_multicb:
            if not os.access(self.fakeforksrv_path, os.X_OK):
                error_msg = "fakeforksrv path %s is not executable" % self.fakeforksrv_path
                l.error(error_msg)
                raise TracerEnvironmentError(error_msg)

        # hack for the OS
        with open(self.binaries[0], "rb") as f:
            header = f.read(4)
            header = header[1:]
        if header == "CGC":
            self.os = "cgc"
        else:
            self.os = None

        if self.os != "cgc":
            error_msg = "\"%s\" runs on an OS not supported by the runner (only cgc at the moment)" % self.binaries[0]
            l.error(error_msg)
            raise TracerEnvironmentError(error_msg)

        # try to find the install base
        self.base = shellphish_qemu.qemu_base()
        self._check_qemu_install()
        if self.forced_qemu != None:
            self.tracer_qemu_path = self.forced_qemu
        return True

    def _check_qemu_install(self):
        """
        check the install location of qemu
        """

        if self.os == "cgc":
            self.tracer_qemu = "shellphish-qemu-cgc-%s" % ("tracer" if self._record_trace else "base")

        self.tracer_qemu_path = shellphish_qemu.qemu_path(self.tracer_qemu)

        if not os.access(self.tracer_qemu_path, os.X_OK):
            if os.path.isfile(self.tracer_qemu_path):
                error_msg = "%s is not executable" % self.tracer_qemu
                l.error(error_msg)
                raise TracerEnvironmentError(error_msg)
            else:
                error_msg = "\"%s\" does not exist" % self.tracer_qemu_path
                l.error(error_msg)
                raise TracerEnvironmentError(error_msg)

### DYNAMIC TRACING

    # create a tmp dir in /dev/shm, chdir into it, set rlimit, save the current self.binary
    # at the end, it restores everything
    @contextlib.contextmanager
    def _setup_env(self):
        prefix = "/tmp/tracer_"
        curdir = os.getcwd()
        tmpdir = tempfile.mkdtemp(prefix=prefix)
        # allow cores to be dumped
        saved_limit = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        binaries_old = [ ]
        for binary in self.binaries:
            binaries_old.append(binary)

        binary_replacements = [ ]
        for i, binary in enumerate(self.binaries):
            binary_replacements.append(os.path.join(tmpdir,"binary_replacement_%d" % i))

        for binary_o, binary_r in zip(binaries_old, binary_replacements):
            shutil.copy(binary_o, binary_r)

        self.binaries = binary_replacements
        os.chdir(tmpdir)
        try:
            yield (tmpdir,binary_replacements)
        finally:
            assert tmpdir.startswith(prefix)
            shutil.rmtree(tmpdir)
            os.chdir(curdir)
            resource.setrlimit(resource.RLIMIT_CORE, saved_limit)
            self.binaries = binaries_old

    def dynamic_trace(self, stdout_file=None):

        with self._setup_env() as (tmpdir,binary_replacement_fname):
            # get the dynamic trace
            self._run_trace(stdout_file=stdout_file)

            if self.crash_mode:

                # find core file
                binary_common_prefix = "_".join(os.path.basename(binary_replacement_fname[0]).split("_")[:2])
                unique_prefix = "qemu_{}".format(os.path.basename(binary_common_prefix))
                core_files = filter(
                        lambda x: x.startswith(unique_prefix) and x.endswith('.core'),
                        os.listdir('.')
                        )


                a_mesg = "No core files found for binary, this shouldn't happen"
                assert len(core_files) > 0, a_mesg
                a_mesg = "Multiple core files found for binary, this shouldn't happen"
                assert len(core_files) < 2, a_mesg
                core_file = core_files[0]

                # get crashed binary
                self.crashed_binary = int(core_file.split("_")[3])

                a_mesg = "Empty core file generated"
                assert os.path.getsize(core_file) > 0, a_mesg
                if self.use_tiny_core:
                    self._load_tiny_core(core_file)
                else:
                    self._load_core_values(core_file)

    def _run_trace(self, stdout_file=None):

        if len(self.binaries) > 1:
            self._run_multicb_trace(stdout_file)
        else:
            self._run_singlecb_trace(stdout_file)

    def _run_multicb_trace(self, stdout_file=None):

        args = [self.fakeforksrv_path]
        args += self.binaries

        stderr_file = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-multicb-stderr-")

        saved_afl_path = os.environ.get('AFL_PATH', None)
        with open('/dev/null', 'wb') as devnull:
            os.environ['AFL_PATH'] = shellphish_afl.afl_dir('multi-cgc')

            stdout_f = devnull
            if stdout_file is not None:
                stdout_f = open(stdout_file, 'wb')

            stderr_f = open(stderr_file, 'wb')

            p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=stdout_f, stderr=stderr_f, close_fds=True)
            _, _ = p.communicate(self.input)

            ret = p.wait()
            self.returncode = p.returncode

            if stdout_file is not None:
                stdout_f.close()

            stderr_f.close()

        if saved_afl_path:
            os.environ['AFL_PATH'] = saved_afl_path

        with open(stderr_file, 'r') as f:
            buf = f.read()
            for line in buf.split("\n"):
                if "signaled" in line:
                    self.crash_mode = bool(int(line.split(":")[-1]))

    def _run_singlecb_trace(self, stdout_file=None):
        """
        accumulate a basic block trace using qemu
        """

        logname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-log-")
        args = [self.tracer_qemu_path]
        if self.seed is not None:
            args.append("-seed")
            args.append(str(self.seed))
        mname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-magic-")
        if self._record_magic:
            args += ["-magicdump", mname]

        if self._record_trace:
            args += ["-d", "exec", "-D", logname]
        else:
            args += ["-enable_double_empty_exiting"]

        if self.report_bad_args:
            args += ["-report_bad_args"]

        args += ["-m", self.memory_limit]

        args += [self.binaries[0]]
        if self.bitflip:
            args = [args[0]] + ["-bitflip"] + args[1:]

        with open('/dev/null', 'wb') as devnull:
            stdout_f = devnull
            if stdout_file is not None:
                stdout_f = open(stdout_file, 'wb')

            # we assume qemu with always exit and won't block
            if self.pov_file is None:
                l.debug("tracing as raw input")
                l.debug(" ".join(args))
                p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=stdout_f, stderr=devnull)
                _, _ = p.communicate(self.input)
            else:
                l.debug("tracing as pov file")
                in_s, out_s = socket.socketpair()
                p = subprocess.Popen(args, stdin=in_s, stdout=stdout_f, stderr=devnull)

                for write in self.pov_file.writes:
                    out_s.send(write)
                    time.sleep(.01)

            ret = p.wait()
            self.returncode = p.returncode
            # did a crash occur?
            if ret < 0:
                if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
                    l.info("input caused a crash (signal %d) during dynamic tracing", abs(ret))
                    l.debug("entering crash mode")
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

        if self._record_magic:
            magic = open(mname).read()
            self.magic = magic
            os.remove(mname)

    def _load_core_values(self, core_file):
        p = angr.Project(core_file)
        self.reg_vals = {reg:val for (reg, val) in p.loader.main_bin.initial_register_values()}
        self._state = p.factory.entry_state()
        self.memory = self._state.memory

    def _load_tiny_core(self, core_file):
        tc = TinyCore(core_file)
        self.reg_vals = tc.registers
        self.memory = None
