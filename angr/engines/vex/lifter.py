import pyvex
import claripy
import cle
from archinfo import ArchARM
from cachetools import LRUCache
import logging

from ..engine import SimEngineBase
from ...state_plugins.inspect import BP_AFTER, BP_BEFORE, NO_OVERRIDE
from ...misc.ux import once
from ...errors import SimEngineError, SimTranslationError, SimError
from ... import sim_options as o

l = logging.getLogger(__name__)

VEX_IRSB_MAX_SIZE = 400
VEX_IRSB_MAX_INST = 99

class VEXLifter(SimEngineBase):
    def __init__(self, project,
                 use_cache=None,
                 cache_size=50000,
                 default_opt_level=1,
                 support_selfmodifying_code=None,
                 single_step=False,
                 default_strict_block_end=False, **kwargs):

        super().__init__(project, **kwargs)

        self._use_cache = use_cache
        self._default_opt_level = default_opt_level
        self._cache_size = cache_size
        self._support_selfmodifying_code = support_selfmodifying_code
        self._single_step = single_step
        self.default_strict_block_end = default_strict_block_end

        if self._use_cache is None:
            if self.project is not None:
                self._use_cache = self.project._translation_cache
            else:
                self._use_cache = False
        if self._support_selfmodifying_code is None:
            if self.project is not None:
                self._support_selfmodifying_code = self.project._support_selfmodifying_code
            else:
                self._support_selfmodifying_code = False

        # block cache
        self._block_cache = None
        self._block_cache_hits = 0
        self._block_cache_misses = 0

        self._initialize_block_cache()

    def _initialize_block_cache(self):
        self._block_cache = LRUCache(maxsize=self._cache_size)
        self._block_cache_hits = 0
        self._block_cache_misses = 0

    def clear_cache(self):
        self._block_cache = LRUCache(maxsize=self._cache_size)

        self._block_cache_hits = 0
        self._block_cache_misses = 0


    def lift_vex(self,
             addr=None,
             state=None,
             clemory=None,
             insn_bytes=None,
             arch=None,
             size=None,
             num_inst=None,
             traceflags=0,
             thumb=False,
             extra_stop_points=None,
             opt_level=None,
             strict_block_end=None,
             skip_stmts=False,
             collect_data_refs=False,
             cross_insn_opt=None):

        """
        Lift an IRSB.

        There are many possible valid sets of parameters. You at the very least must pass some
        source of data, some source of an architecture, and some source of an address.

        Sources of data in order of priority: insn_bytes, clemory, state

        Sources of an address, in order of priority: addr, state

        Sources of an architecture, in order of priority: arch, clemory, state

        :param state:           A state to use as a data source.
        :param clemory:         A cle.memory.Clemory object to use as a data source.
        :param addr:            The address at which to start the block.
        :param thumb:           Whether the block should be lifted in ARM's THUMB mode.
        :param opt_level:       The VEX optimization level to use. The final IR optimization level is determined by
                                (ordered by priority):
                                - Argument opt_level
                                - opt_level is set to 1 if OPTIMIZE_IR exists in state options
                                - self._default_opt_level
        :param insn_bytes:      A string of bytes to use as a data source.
        :param size:            The maximum size of the block, in bytes.
        :param num_inst:        The maximum number of instructions.
        :param traceflags:      traceflags to be passed to VEX. (default: 0)
        :param strict_block_end:   Whether to force blocks to end at all conditional branches (default: false)
        """

        # phase 0: sanity check
        if not state and not clemory and not insn_bytes:
            raise ValueError("Must provide state or clemory or insn_bytes!")
        if not state and not clemory and not arch:
            raise ValueError("Must provide state or clemory or arch!")
        if addr is None and not state:
            raise ValueError("Must provide state or addr!")
        if arch is None:
            arch = clemory._arch if clemory else state.arch
        if arch.name.startswith("MIPS") and self._single_step:
            l.error("Cannot specify single-stepping on MIPS.")
            self._single_step = False

        # phase 1: parameter defaults
        if addr is None:
            addr = state.solver.eval(state._ip)
        if size is not None:
            size = min(size, VEX_IRSB_MAX_SIZE)
        if size is None:
            size = VEX_IRSB_MAX_SIZE
        if num_inst is not None:
            num_inst = min(num_inst, VEX_IRSB_MAX_INST)
        if num_inst is None and self._single_step:
            num_inst = 1
        if opt_level is None:
            if state and o.OPTIMIZE_IR in state.options:
                opt_level = 1
            else:
                opt_level = self._default_opt_level
        if cross_insn_opt is None:
            if state and o.NO_CROSS_INSN_OPT in state.options:
                cross_insn_opt = False
            else:
                cross_insn_opt = True
        if strict_block_end is None:
            strict_block_end = self.default_strict_block_end
        if self._support_selfmodifying_code:
            if opt_level > 0:
                if once('vex-engine-smc-opt-warning'):
                    l.warning("Self-modifying code is not always correctly optimized by PyVEX. "
                              "To guarantee correctness, VEX optimizations have been disabled.")
                opt_level = 0
                if state and o.OPTIMIZE_IR in state.options:
                    state.options.remove(o.OPTIMIZE_IR)
        if skip_stmts is not True:
            skip_stmts = False

        use_cache = self._use_cache
        if skip_stmts or collect_data_refs:
            # Do not cache the blocks if skip_stmts or collect_data_refs are enabled
            use_cache = False

        # phase 2: thumb normalization
        thumb = int(thumb)
        if isinstance(arch, ArchARM):
            if addr % 2 == 1:
                thumb = 1
            if thumb:
                addr &= ~1
        elif thumb:
            l.error("thumb=True passed on non-arm architecture!")
            thumb = 0

        # phase 3: check cache
        cache_key = None
        if use_cache:
            cache_key = (addr, insn_bytes, size, num_inst, thumb, opt_level, strict_block_end, cross_insn_opt)
            if cache_key in self._block_cache:
                self._block_cache_hits += 1
                irsb = self._block_cache[cache_key]
                stop_point = self._first_stoppoint(irsb, extra_stop_points)
                if stop_point is None:
                    return irsb
                else:
                    size = stop_point - addr
                    # check the cache again
                    cache_key = (addr, insn_bytes, size, num_inst, thumb, opt_level, strict_block_end, cross_insn_opt)
                    if cache_key in self._block_cache:
                        self._block_cache_hits += 1
                        return self._block_cache[cache_key]
                    else:
                        self._block_cache_misses += 1
            else:
                # a special case: `size` is used as the maximum allowed size
                tmp_cache_key = (addr, insn_bytes, VEX_IRSB_MAX_SIZE, num_inst, thumb, opt_level, strict_block_end,
                                 cross_insn_opt)
                try:
                    irsb = self._block_cache[tmp_cache_key]
                    if irsb.size <= size:
                        self._block_cache_hits += 1
                        return self._block_cache[tmp_cache_key]
                except KeyError:
                    self._block_cache_misses += 1

        # vex_lift breakpoints only triggered when the cache isn't used
        buff = NO_OVERRIDE
        if state:
            state._inspect('vex_lift', BP_BEFORE, vex_lift_addr=addr, vex_lift_size=size, vex_lift_buff=NO_OVERRIDE)
            buff = state._inspect_getattr("vex_lift_buff", NO_OVERRIDE)
            addr = state._inspect_getattr("vex_lift_addr", addr)
            size = state._inspect_getattr("vex_lift_size", size)

        # phase 4: get bytes
        if buff is NO_OVERRIDE:
            if insn_bytes is not None:
                buff, size = insn_bytes, len(insn_bytes)
            else:
                buff, size = self._load_bytes(addr, size, state, clemory)

        if not buff or size == 0:
            raise SimEngineError("No bytes in memory for block starting at %#x." % addr)

        # phase 5: call into pyvex
        # l.debug("Creating pyvex.IRSB of arch %s at %#x", arch.name, addr)
        try:
            for subphase in range(2):

                irsb = pyvex.lift(buff, addr + thumb, arch,
                                  max_bytes=size,
                                  max_inst=num_inst,
                                  bytes_offset=thumb,
                                  traceflags=traceflags,
                                  opt_level=opt_level,
                                  strict_block_end=strict_block_end,
                                  skip_stmts=skip_stmts,
                                  collect_data_refs=collect_data_refs,
                                  cross_insn_opt=cross_insn_opt
                                  )

                if subphase == 0 and irsb.statements is not None:
                    # check for possible stop points
                    stop_point = self._first_stoppoint(irsb, extra_stop_points)
                    if stop_point is not None:
                        size = stop_point - addr
                        continue

                if use_cache:
                    self._block_cache[cache_key] = irsb
                if state:
                    state._inspect('vex_lift', BP_AFTER, vex_lift_addr=addr, vex_lift_size=size)
                return irsb

        # phase x: error handling
        except pyvex.PyVEXError as e:
            l.debug("VEX translation error at %#x", addr)
            if isinstance(buff, bytes):
                l.debug('Using bytes: %r', buff)
            else:
                l.debug("Using bytes: %r", pyvex.ffi.buffer(buff, size))
            raise SimTranslationError("Unable to translate bytecode") from e

    def _load_bytes(self, addr, max_size, state=None, clemory=None):
        if not clemory:
            if state is None:
                raise SimEngineError('state and clemory cannot both be None in _load_bytes().')
            if o.ABSTRACT_MEMORY in state.options:
                # abstract memory
                clemory = state.memory.regions['global'].memory.mem._memory_backer
            else:
                # symbolic memory
                clemory = state.memory.mem._memory_backer

        buff, size = b"", 0

        # Load from the clemory if we can
        smc = self._support_selfmodifying_code
        if state and not smc:
            try:
                p = state.memory.permissions(addr)
                if p.symbolic:
                    smc = True
                else:
                    smc = claripy.is_true(p & 2 != 0)
            except: # pylint: disable=bare-except
                smc = True # I don't know why this would ever happen, we checked this right?

        if (not smc or not state) and isinstance(clemory, cle.Clemory):
            try:
                start, backer = next(clemory.backers(addr))
            except StopIteration:
                pass
            else:
                if start <= addr:
                    offset = addr - start
                    buff = pyvex.ffi.from_buffer(backer) + offset
                    size = len(backer) - offset

        # If that didn't work, try to load from the state
        if size == 0 and state:
            fallback = True
            if addr in state.memory and addr + max_size - 1 in state.memory:
                try:
                    buff = state.solver.eval(state.memory.load(addr, max_size, inspect=False), cast_to=bytes)
                    size = max_size
                    fallback = False
                except SimError:
                    l.warning("Cannot load bytes at %#x. Fallback to the slow path.", addr)

            if fallback:
                buff_lst = [ ]
                symbolic_warned = False
                for i in range(max_size):
                    if addr + i in state.memory:
                        try:
                            byte = state.memory.load(addr + i, 1, inspect=False)
                            if byte.symbolic and not symbolic_warned:
                                symbolic_warned = True
                                l.warning("Executing symbolic code at %#x", addr + i)
                            buff_lst.append(state.solver.eval(byte))
                        except SimError:
                            break
                    else:
                        break

                buff = bytes(buff_lst)
                size = len(buff)

        size = min(max_size, size)
        return buff, size

    def _first_stoppoint(self, irsb, extra_stop_points=None):
        """
        Enumerate the imarks in the block. If any of them (after the first one) are at a stop point, returns the address
        of the stop point. None is returned otherwise.
        """
        if extra_stop_points is None and self.project is None:
            return None

        first_imark = True
        for stmt in irsb.statements:
            if type(stmt) is pyvex.stmt.IMark:  # pylint: disable=unidiomatic-typecheck
                addr = stmt.addr + stmt.delta
                if not first_imark:
                    if self.__is_stop_point(addr, extra_stop_points):
                        # could this part be moved by pyvex?
                        return addr
                    if stmt.delta != 0 and self.__is_stop_point(stmt.addr, extra_stop_points):
                        return addr

                first_imark = False
        return None

    def __is_stop_point(self, addr, extra_stop_points=None):
        if self.project is not None and addr in self.project._sim_procedures:
            return True
        elif extra_stop_points is not None and addr in extra_stop_points:
            return True
        return False

    def __getstate__(self):
        ostate = super().__getstate__()
        s = {
            '_use_cache': self._use_cache,
            '_default_opt_level': self._default_opt_level,
             '_support_selfmodifying_code': self._support_selfmodifying_code,
             '_single_step': self._single_step,
             '_cache_size': self._cache_size,
             'default_strict_block_end': self.default_strict_block_end
        }

        return (s, ostate)

    def __setstate__(self, state):
        s, ostate = state
        self._use_cache = s['_use_cache']
        self._default_opt_level = s['_default_opt_level']
        self._support_selfmodifying_code = s['_support_selfmodifying_code']
        self._single_step = s['_single_step']
        self._cache_size = s['_cache_size']
        self.default_strict_block_end = s['default_strict_block_end']

        # rebuild block cache
        self._initialize_block_cache()
        super().__setstate__(ostate)
