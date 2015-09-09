import logging

l = logging.getLogger("tracer.Tracer")

import cle
import angr
import simuvex

import os
import signal
import struct
import tempfile
import subprocess

class TracerEnvironmentError(Exception):
    pass

class TracerMisfollowError(Exception):
    pass

class TracerDynamicTraceOOBError(Exception):
    pass

class Tracer(object):
    '''
    Trace an angr path with a concrete input
    '''

    def __init__(self, binary, input, simprocedures=None, preconstrain=True, resiliency=True, chroot=None):
        '''
        :param binary: path to the binary to be traced
        :param input: concrete input string to feed to binary
        :param simprocedures: dictionary of replacement simprocedures
        :param preconstrain: should the path be preconstrained to the provided input
        :param resiliency: should we continue to step forward even if qemu and angr disagree?
        :param chroot: trace the program as though it were executing in a chroot
        '''

        self.binary        = binary
        self.input         = input
        self.preconstrain  = preconstrain
        self.simprocedures = { } if simprocedures is None else simprocedures
        self.resiliency    = resiliency
        self.chroot        = chroot

        self.base = os.path.join(os.path.dirname(__file__), "..", "..")

        # internal project object, useful for obtaining certain kinds of info
        self._p = angr.Project(self.binary)

        self._setup()

        l.debug("accumulating basic block trace...")
        l.debug("self.tracer_qemu_path: %s", self.tracer_qemu_path)

        # does the input cause a crash?
        self.crash_mode = False

        # will set crash_mode correctly
        self.trace = self._dynamic_trace()

        l.debug("trace consists of %d basic blocks", len(self.trace))

        self.preconstraints = [ ]

        # initialize the basic block counter to 0
        self.bb_cnt = 0

        # keep track of the last basic block we hit
        self.previous = None

        # whether we should follow the qemu trace
        self.no_follow = False

        # set of resolved dynamic functions which have been resolved
        # useful for handling PLT stubs
        self._resolved = set()

        self.path_group = self._prepare_paths()

### EXPOSED
    def next_branch(self):
        '''
        windup the tracer to the next branch

        :return: a path_group describing the possible paths at the next branch
                 branches which weren't taken by the dynamic trace are placed
                 into the 'missed' stash and any preconstraints are removed from
                 'missed' branches.
        '''

        while len(self.path_group.active) == 1:
            current = self.path_group.active[0]

            l.debug("current: %#x", current.addr)
            l.debug("trace: %s", map(hex, self.trace[self.bb_cnt:]))

            if not self.no_follow:

                # expected behavor, the dynamic trace and symbolic trace hit the
                # same basic block
                if current.addr == self.trace[self.bb_cnt]:
                    self.bb_cnt += 1

                # angr steps through the same basic block twice when a syscall
                # occurs
                elif current.addr == self.previous.addr:
                    pass

                # handle library calls and simprocedures
                elif self._p.is_hooked(current.addr) or not self._address_in_binary(current.addr):
                    # are we going to be jumping through the PLT stub? if so we need to take special care
                    if current.addr not in self._resolved and self.previous.addr in self._p.loader.main_bin.reverse_plt:
                        self.bb_cnt += 2
                        self._resolved.add(current.addr)

                else:
                    l.error("the dynamic trace and the symbolic trace disagreed")
                    l.error("[%s] dynamic [0x%x], symbolic [0x%x]", self.binary,
                            self.trace[self.bb_cnt], current.addr)
                    l.error("inputs was %r", self.input)
                    if self.resiliency:
                        l.error("TracerMisfollowError encountered")
                        l.warning("entering no follow mode")
                        self.no_follow = True
                    else:
                        raise TracerMisfollowError

            self.previous = current.copy()

            # Basic block's max size in angr is greater than the one in Qemu
            # We follow the one in Qemu
            if self.bb_cnt >= len(self.trace):
                bbl_max_bytes = 800
            else:
                bbl_max_bytes = self.trace[self.bb_cnt] - self.trace[self.bb_cnt - 1]
                if bbl_max_bytes <= 0:
                    bbl_max_bytes = 800

            # if we're not in crash mode we don't care about the history
            if not self.crash_mode:
                current.trim_history()

            self.path_group = self.path_group.step(max_size=bbl_max_bytes)

            # if our input was preconstrained we have to keep on the lookout for unsat paths
            if self.preconstrain:
              self.path_group = self.path_group.stash(filter_func=lambda p: p.reachable,
                                                      from_stash='unsat',
                                                      to_stash='active')


            self.path_group = self.path_group.drop(stash='unsat')

            # check to see if we reached a deadend
            if self.bb_cnt >= len(self.trace):
                tpg = self.path_group.step()
                # if we're in crash mode let's populate the crashed stash
                if self.crash_mode:
                    tpg = tpg.stash(from_stash='active', to_stash='crashed')
                    return tpg
                # if we're in normal follow mode, just step the path to
                # the deadend
                else:
                    if len(tpg.active) == 0:
                        self.path_group = tpg
                        return self.path_group

        # if we stepped to a point where there are no active paths, return the path_group
        if len(self.path_group.active) == 0:
            # possibly we want to have different behaviour if we're in crash mode
            return self.path_group

        # if we have to ditch the trace we use satisfiability
        # or if a split occurs in a library routine
        if self.no_follow or all(map(lambda p: not self._address_in_binary(p.addr), self.path_group.active)):
            self.path_group = self.path_group.prune(to_stash='missed')
        else:
            l.debug("bb %d / %d", self.bb_cnt, len(self.trace))
            self.path_group = self.path_group.stash_not_addr(
                                           self.trace[self.bb_cnt],
                                           to_stash='missed')

        # make sure we only have one or zero active paths at this point
        assert len(self.path_group.active) < 2

        l.debug("taking the branch at %x", self.path_group.active[0].addr)

        rpg = self.path_group

        self.path_group = self.path_group.drop(stash='missed')

        return rpg

    def run(self):
        '''
        run a trace to completion

        :return: a deadended path of a complete symbolic run of the program
                 with self.input
        '''

        # keep calling next_branch until it quits
        branches = None
        while branches is None or len(branches.active):
            branches = self.next_branch()

            # if we spot a crashed path in crash mode return the goods
            if self.crash_mode and 'crashed' in branches.stashes:
                l.info("crash occured in basic block %x", self.trace[self.bb_cnt - 1])

                # time to recover the crashing state

                # remove the preconstraints
                self.remove_preconstraints(self.previous)
                self.previous._run = None
                self.previous.step()

                successors = self.previous.next_run.successors + self.previous.next_run.unconstrained_successors
                state = successors[0]

                return (self.previous, state)

        # the caller is responsible for removing preconstraints

        return branches

    def remove_preconstraints(self, path):

        if not self.preconstrain:
            return

        new_constraints = path.state.se.constraints[len(self.preconstraints):]

        path.state.se.constraints[:] = new_constraints
        path.state.downsize()
        path.state.se._solver.result = None

### SETUP

    def _setup(self):
        '''
        make sure the environment is sane and we have everything we need to do a trace
        '''
        # check the binary
        if not os.access(self.binary, os.X_OK):
            if os.path.isfile(self.binary):
                l.error("\"%s\" binary is not executable", self.binary)
                raise TracerEnvironmentError
            else:
                l.error("\"%s\" binary does not exist", self.binary)
                raise TracerEnvironmentError

        self.os = self._p.loader.main_bin.os

        if self.os != "cgc" and self.os != "unix":
            l.error("\"%s\" runs on an OS not supported by the tracer", self.binary)
            raise TracerEnvironmentError

        if self.os == "cgc":
            self.tracer_qemu = "tracer-qemu-cgc"
        elif self.os == "unix":
            self.tracer_qemu = "tracer-qemu-linux-%s" % self._p.arch.qemu_name

        self.tracer_qemu_path = os.path.join(self.base, "bin", self.tracer_qemu)

        if not os.access(self.tracer_qemu_path, os.X_OK):
            if os.path.isfile(self.tracer_qemu_path):
                l.error("tracer-qemu-cgc is not executable")
                raise TracerEnvironmentError
            else:
                l.error("\"%s\" does not exist", self.tracer_qemu_path)
                raise TracerEnvironmentError

        return True

### DYNAMIC TRACING

    def _address_in_binary(self, addr):
        '''
        determine if address @addr is in the binary being traced
        :param addr: the address to test
        :return: True if the address is in between the binary's min and max address
        '''
        mb = self._p.loader.main_bin
        return mb.get_min_addr() <= addr and addr < mb.get_max_addr()

    def _current_bb(self):
        try:
            self.trace[self.bb_cnt]
        except IndexError:
            if self.crash_mode:
                return None
            else:
                raise TracerDynamicTraceOOBError

    def _dynamic_trace(self):
        '''
        accumulate a basic block trace using qemu
        '''

        args = [self.tracer_qemu_path, "-d", "exec", "-D", "/proc/self/fd/2", self.binary]

        with open('/dev/null', 'wb') as devnull:
            # we assume qemu with always exit and won't block
            p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=devnull, stderr=subprocess.PIPE)
            _, trace = p.communicate(self.input)
            ret = p.wait()
            # did a crash occur?
            if ret < 0:
                if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
                    l.info("input caused a crash (signal %d) during dynamic tracing", abs(ret))
                    l.info("entering crash mode")
                    self.crash_mode = True

        addrs = [int(v.split('[')[1].split(']')[0], 16)
                 for v in trace.split('\n')
                 if v.startswith('Trace')]

        return addrs

    def _load_backed(self):
        '''
        load an angr project with an initial state seeded by qemu
        '''

        # get the backing by calling out to qemu
        backingfd, backingfile = tempfile.mkstemp(prefix="tracer-backing-", dir="/dev/shm")
        os.close(backingfd)

        args = [self.tracer_qemu_path, "-predump", backingfile, self.binary]

        with open('/dev/null', 'wb') as devnull:
            # should never block, predump should exit at the first call which would block
            p = subprocess.Popen(args, stdout=devnull)
            p.wait()


        # parse out the predump file
        memory = {}
        regs = {}
        with open(backingfile, "rb") as f:
            while len(regs) == 0:
                tag = f.read(4)
                if tag != "REGS":
                    start = struct.unpack("<I", tag)[0]
                    end = struct.unpack("<I", f.read(4))[0]
                    length = struct.unpack("<I", f.read(4))[0]
                    content = f.read(length)
                    memory[start] = content
                else:
                    # general purpose regs
                    regs['eax'] = struct.unpack("<I", f.read(4))[0]
                    regs['ebx'] = struct.unpack("<I", f.read(4))[0]
                    regs['ecx'] = struct.unpack("<I", f.read(4))[0]
                    regs['edx'] = struct.unpack("<I", f.read(4))[0]
                    regs['esi'] = struct.unpack("<I", f.read(4))[0]
                    regs['edi'] = struct.unpack("<I", f.read(4))[0]
                    regs['ebp'] = struct.unpack("<I", f.read(4))[0]
                    regs['esp'] = struct.unpack("<I", f.read(4))[0]

                    # d flag
                    regs['d']   = struct.unpack("<I", f.read(4))[0]

                    # eip
                    # adjust eip
                    regs['eip'] = struct.unpack("<I", f.read(4))[0] - 2

                    # fp regs
                    regs['st0'] = struct.unpack("<Q", f.read(8))[0]
                    regs['st0'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['st1'] = struct.unpack("<Q", f.read(8))[0]
                    regs['st1'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['st2'] = struct.unpack("<Q", f.read(8))[0]
                    regs['st2'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['st3'] = struct.unpack("<Q", f.read(8))[0]
                    regs['st3'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['st4'] = struct.unpack("<Q", f.read(8))[0]
                    regs['st4'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['st5'] = struct.unpack("<Q", f.read(8))[0]
                    regs['st5'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['st6'] = struct.unpack("<Q", f.read(8))[0]
                    regs['st6'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['st7'] = struct.unpack("<Q", f.read(8))[0]
                    regs['st7'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    # fp tags
                    regs['fpu_t0'] = struct.unpack("B", f.read(1))[0]
                    regs['fpu_t1'] = struct.unpack("B", f.read(1))[0]
                    regs['fpu_t2'] = struct.unpack("B", f.read(1))[0]
                    regs['fpu_t3'] = struct.unpack("B", f.read(1))[0]
                    regs['fpu_t4'] = struct.unpack("B", f.read(1))[0]
                    regs['fpu_t5'] = struct.unpack("B", f.read(1))[0]
                    regs['fpu_t6'] = struct.unpack("B", f.read(1))[0]
                    regs['fpu_t7'] = struct.unpack("B", f.read(1))[0]

                    # ftop
                    regs['ftop'] = struct.unpack("<I", f.read(4))[0]

                    # sseround
                    regs['mxcsr'] = struct.unpack("<I", f.read(4))[0]

                    regs['xmm0'] = struct.unpack("<Q", f.read(8))[0]
                    regs['xmm0'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['xmm1'] = struct.unpack("<Q", f.read(8))[0]
                    regs['xmm1'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['xmm2'] = struct.unpack("<Q", f.read(8))[0]
                    regs['xmm2'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['xmm3'] = struct.unpack("<Q", f.read(8))[0]
                    regs['xmm3'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['xmm4'] = struct.unpack("<Q", f.read(8))[0]
                    regs['xmm4'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['xmm5'] = struct.unpack("<Q", f.read(8))[0]
                    regs['xmm5'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['xmm6'] = struct.unpack("<Q", f.read(8))[0]
                    regs['xmm6'] |= struct.unpack("<Q", f.read(8))[0] << 64

                    regs['xmm7'] = struct.unpack("<Q", f.read(8))[0]
                    regs['xmm7'] |= struct.unpack("<Q", f.read(8))[0] << 64

        os.remove(backingfile)

        ld = cle.Loader(self.binary, main_opts={'backend': cle.loader.BackedCGC, 'memory_backer': memory, 'register_backer': regs, 'writes_backer': []})

        return angr.Project(ld)

### SYMBOLIC TRACING

    def _preconstrain_state(self, entry_state):
        '''
        preconstrain the entry state to the input
        '''

        stdin = entry_state.posix.get_file(0)

        for b in self.input:
            c = stdin.read_from(1) == entry_state.BVV(b)
            self.preconstraints.append(c)
            entry_state.se.state.add_constraints(c)

        stdin.seek(0)

    def _set_cgc_simprocedures(self):
        for symbol in self.simprocedures:
            simuvex.SimProcedures['cgc'][symbol] = self.simprocedures[symbol]

    def _set_linux_simprocedures(self, project):
        for symbol in self.simprocedures:
            project.set_sim_procedure(project.loader.main_bin, symbol, self.simprocedures[symbol])

    def _prepare_paths(self):
        '''
        prepare initial paths
        '''

        if self.os == "cgc":
            return self._cgc_prepare_paths()
        elif self.os == "unix":
            return self._linux_prepare_paths()

        raise TracerEnvironmentError("unsupport OS \"%s\" called _prepare_paths", self.os)

    def _cgc_prepare_paths(self):
        '''
        prepare the initial paths for CGC binaries
        '''

        project = self._load_backed()

        # if we're in crash mode we want the authentic system calls
        if not self.crash_mode:
            self._set_cgc_simprocedures()

        fs = {'/dev/stdin': simuvex.storage.file.SimFile("/dev/stdin", "r", size=len(self.input))}
        entry_state = project.factory.entry_state(fs=fs, add_options={simuvex.s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY, simuvex.s_options.CGC_NO_SYMBOLIC_RECEIVE_LENGTH})

        # windup the basic block trace to the point where we'll begin symbolic trace
        while self.trace[self.bb_cnt] != project.entry + 2:
            self.bb_cnt += 1

        if self.preconstrain:
            self._preconstrain_state(entry_state)

        entry_state.cgc.input_size = len(self.input)

        pg = project.factory.path_group(entry_state, immutable=True,
                save_unsat=True, hierarchy=False, save_unconstrained=self.crash_mode)

        return pg.step()

    def _linux_prepare_paths(self):
        '''
        prepare the initial paths for Linux binaries
        '''

        project = angr.Project(self.binary)

        if not self.crash_mode:
            self._set_linux_simprocedures(project)

        # fix stdin to the size of the input being traced
        fs = {'/dev/stdin': simuvex.storage.file.SimFile("/dev/stdin", "r", size=len(self.input))}
        entry_state = project.factory.entry_state(fs=fs,concrete_fs=True, chroot=self.chroot, add_options={simuvex.s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY, simuvex.s_options.BYPASS_UNSUPPORTED_SYSCALL})

        if self.preconstrain:
            self._preconstrain_state(entry_state)

        # increase size of libc limits
        entry_state.libc.buf_symbolic_bytes = 1024 * 4
        entry_state.libc.max_str_len = 1024 * 4

        pg = project.factory.path_group(entry_state, immutable=True,
                save_unsat=True, hierarchy=False, save_unconstrained=self.crash_mode)

        # don't step here, because unlike CGC we aren't going to be starting anywhere but the entry point
        return pg
