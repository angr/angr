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

from .tracerpov import TracerPoV
from .tinycore import TinyCore
from .runner import Runner
from ...errors import TracerEnvironmentError

l = logging.getLogger("angr.misc.tracer.qemu_runner")

try:
    import shellphish_qemu
except ImportError:
    raise ImportError("Unable to import shellphish_qemu, which is required by QEMURunner. Please install it before proceeding.")

multicb_available = True

try:
    import shellphish_afl
except ImportError:
    l.warning("Unable to import shellphish_afl, multicb tracing will be disabled")
    multicb_available = False

class QEMURunner(Runner):
    """
    Trace an angr path with a concrete input using QEMU.
    """

    def __init__(self, project=None, binary=None, input=None, record_trace=True, record_stdout=False,
                 record_magic=True, record_core=False, seed=None, memory_limit="8G", bitflip=False, report_bad_args=False,
                 use_tiny_core=False, max_size=None, qemu=None, argv=None):
        """
        :param project       : The original project.
        :param binary        : Path to the binary to be traced.
        :param input         : Concrete input to feed to binary (string or CGC TracerPoV).
        :param record_trace  : Whether or not to record the basic block trace.
        :param record_stdout : Whether ot not to record the output of tracing process.
        :param record_magic  : Whether ot not to record the magic flag page as reported by QEMU.
        :param record_core   : Whether or not to record the core file in case of crash.
        :param report_bad_arg: Enable CGC QEMU's report bad args option.
        :param use_tiny_core : Use minimal core loading.
        :param max_size      : Optionally set max size of input. Defaults to size
                               of preconstrained input.
        :param qemu          : Path to QEMU to be forced used.
        :param argv          : Optionally specify argv params (i,e,: ['./calc', 'parm1']).
                               Defaults to binary name with no params.
        """
        if type(input) not in (str, TracerPoV):
            raise TracerEnvironmentError("Input for tracer should be either a string or a TracerPoV for CGC PoV file.")

        Runner.__init__(self, project=project, binary=binary, input=input, record_trace=record_trace,
                        record_core=record_core, use_tiny_core=use_tiny_core, trace_source_path=qemu, argv=argv)

        self._record_magic = record_magic and self.os == 'cgc'

        if record_trace and self._is_multicb:
            l.warning("record_trace specified with multicb, no trace will be recorded")

        if isinstance(seed, (int, long)):
            seed = str(seed)
        self._seed = seed
        self._memory_limit = memory_limit
        self._bitflip = bitflip

        if self._bitflip and self._is_multicb:
            raise ValueError("Cannot perform bitflip with MultiCB")

        self._report_bad_args = report_bad_args

        if self.input is None:
            raise ValueError("Must specify input.")

        # validate seed
        if self._seed is not None:
            try:
                iseed = int(self._seed)
                if iseed > 4294967295 or iseed < 0:
                    raise ValueError
            except ValueError:
                raise ValueError("The passed seed is either not an integer or is not between 0 and UINT_MAX")

        self.input_max_size = max_size or len(input) if input is not None else None

        self._fakeforksrv_path = os.path.join(shellphish_afl.afl_dir('multi-cgc'), "run_via_fakeforksrv")

        self._setup()

        l.debug("Accumulating basic block trace...")
        l.debug("tracer qemu path: %s", self._trace_source_path)

        self.stdout = None

        # We need this to keep symbolic traces following the same path
        # as their dynamic counterpart
        self.magic = None

        if record_stdout:
            tmp = tempfile.mktemp(prefix="stdout_" + os.path.basename(binary))
            # will set crash_mode correctly
            self._run(stdout_file=tmp)
            with open(tmp, "rb") as f:
                self.stdout = f.read()
            os.remove(tmp)
        else:
            # will set crash_mode correctly
            self._run()


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

        raise ValueError("Unrecognized size, should be 'k', 'M', or 'G'")

    def _setup(self):
        # check the binary
        for binary in self._binaries:
            if not os.access(binary, os.X_OK):
                if os.path.isfile(binary):
                    error_msg = "\"%s\" binary is not executable" % binary
                    l.error(error_msg)
                    raise TracerEnvironmentError(error_msg)
                else:
                    error_msg = "\"%s\" binary does not exist" % binary
                    l.error(error_msg)
                    raise TracerEnvironmentError(error_msg)

        if self._is_multicb:
            if not os.access(self._fakeforksrv_path, os.X_OK):
                error_msg = "fakeforksrv path %s is not executable" % self._fakeforksrv_path
                l.error(error_msg)
                raise TracerEnvironmentError(error_msg)

        # hack for the OS
        if self.os != 'cgc' and not self.os.startswith("UNIX"):
            error_msg = "\"%s\" runs on an OS not supported by the qemu runner (only cgc and elf at the moment)" % self._binaries[0]
            l.error(error_msg)
            raise TracerEnvironmentError(error_msg)

        # try to find the install base
        self._check_qemu_install()

    def _check_qemu_install(self):
        """
        Check the install location of QEMU.
        """
        if self.os == "cgc":
            suffix = "tracer" if self._record_trace else "base"
            self.trace_source = "shellphish-qemu-cgc-%s" % suffix
            qemu_platform = "cgc-%s" % suffix
        else:
            self.trace_source = "shellphish-qemu-linux-%s" % self._p.arch.qemu_name
            qemu_platform = self._p.arch.qemu_name

        if self._trace_source_path is None or not os.access(self._trace_source_path, os.X_OK):
            if self._trace_source_path is not None:
                l.warning("Problem accessing forced %s. Using our default %s.") % (self._trace_source_path, self.trace_source)

            self._trace_source_path = shellphish_qemu.qemu_path(self.trace_source)

            if not os.access(self._trace_source_path, os.X_OK):
                if os.path.isfile(self._trace_source_path):
                    error_msg = "%s is not executable" % self.trace_source
                    l.error(error_msg)
                    raise TracerEnvironmentError(error_msg)
                else:
                    error_msg = "\"%s\" does not exist" % self._trace_source_path
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
        for binary in self._binaries:
            binaries_old.append(binary)

        binary_replacements = [ ]
        for i, binary in enumerate(self._binaries):
            binary_replacements.append(os.path.join(tmpdir,"binary_replacement_%d" % i))

        for binary_o, binary_r in zip(binaries_old, binary_replacements):
            shutil.copy(binary_o, binary_r)

        self._binaries = binary_replacements
        if self.argv is not None and not self._is_multicb:
            self.argv = self._binaries + self.argv[1:]
        os.chdir(tmpdir)
        try:
            yield (tmpdir,binary_replacements)
        finally:
            assert tmpdir.startswith(prefix)
            shutil.rmtree(tmpdir)
            os.chdir(curdir)
            resource.setrlimit(resource.RLIMIT_CORE, saved_limit)
            self._binaries = binaries_old

    def _run(self, stdout_file=None):
        with self._setup_env() as (tmpdir,binary_replacement_fname):
            # get the dynamic trace
            self._run_trace(stdout_file=stdout_file)

            if self.crash_mode and self._record_core:
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
                if self._use_tiny_core:
                    self._load_tiny_core(core_file)
                else:
                    self._load_core_values(core_file)

    def _run_trace(self, stdout_file=None):
        if self._is_multicb:
            self._run_multicb_trace(stdout_file)
        else:
            self._run_singlecb_trace(stdout_file)

    def _run_multicb_trace(self, stdout_file=None):
        args = [self._fakeforksrv_path]
        args += self._binaries

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
        logname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-log-")
        args = [self._trace_source_path]

        if self._seed is not None:
            args.append("-seed")
            args.append(str(self._seed))

        # If the binary is CGC we'll also take this opportunity to read in the
        # magic page.
        if self._record_magic:
            mname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-magic-")
            args += ["-magicdump", mname]

        if self._record_trace:
            args += ["-d", "exec", "-D", logname]
        else:
            args += ["-enable_double_empty_exiting"]

        if self._report_bad_args:
            args += ["-report_bad_args"]

        # Memory limit option is only available in shellphish-qemu-cgc-*
        if 'cgc' in self._trace_source_path:
            args += ["-m", self._memory_limit]

        args += self.argv or [self._binaries[0]]
        
        if self._bitflip:
            args = [args[0]] + ["-bitflip"] + args[1:]

        with open('/dev/null', 'wb') as devnull:
            stdout_f = devnull
            if stdout_file is not None:
                stdout_f = open(stdout_file, 'wb')

            # we assume qemu with always exit and won't block
            if type(self.input) == str:
                l.debug("Tracing as raw input")
                l.debug(" ".join(args))
                p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=stdout_f, stderr=devnull)
                _, _ = p.communicate(self.input)
            else:
                l.debug("Tracing as pov file")
                in_s, out_s = socket.socketpair()
                p = subprocess.Popen(args, stdin=in_s, stdout=stdout_f, stderr=devnull)

                for write in self.input.writes:
                    out_s.send(write)
                    time.sleep(.01)

            ret = p.wait()
            self.returncode = p.returncode
            # did a crash occur?
            if ret < 0:
                if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
                    l.info("Input caused a crash (signal %d) during dynamic tracing", abs(ret))
                    l.debug(repr(self.input))
                    l.debug("Crash mode is set")
                    self.crash_mode = True

            if stdout_file is not None:
                stdout_f.close()

        if self._record_trace:
            trace = open(logname).read()
            addrs = [int(v.split('[')[1].split(']')[0], 16)
                     for v in trace.split('\n')
                     if v.startswith('Trace')]

            # Find where qemu loaded the binary. Primarily for PIE
            qemu_base_addr = int(trace.split("start_code")[1].split("\n")[0],16)
            if self.base_addr != qemu_base_addr and self._p.loader.main_object.pic:
                self.base_addr = qemu_base_addr
                self.rebase = True

            # grab the faulting address
            if self.crash_mode:
                self.crash_addr = int(trace.split('\n')[-2].split('[')[1].split(']')[0], 16)

            os.remove(logname)
            self.trace = addrs
            l.debug("Trace consists of %d basic blocks", len(self.trace))

        if self._record_magic:
            self.magic = open(mname).read()
            a_mesg = "Magic content read from QEMU improper size, should be a page in length"
            assert len(self.magic) == 0x1000, a_mesg
            os.remove(mname)

    def _load_core_values(self, core_file):
        p = angr.Project(core_file)
        self.reg_vals = {reg:val for (reg, val) in p.loader.main_object.initial_register_values()}
        self._state = p.factory.entry_state()
        self.memory = self._state.memory

    def _load_tiny_core(self, core_file):
        tc = TinyCore(core_file)
        self.reg_vals = tc.registers
        self.memory = None
