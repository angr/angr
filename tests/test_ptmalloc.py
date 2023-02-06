import unittest

from angr import SimState, SimHeapPTMalloc


# TODO: Make these tests more architecture-independent (note dependencies of some behavior on chunk metadata size)
class TestPtmalloc(unittest.TestCase):
    def chunk_iterators_are_same(self, iterator1, iterator2):
        for ck in iterator1:
            ck2 = next(iterator2)
            if ck.base != ck2.base:
                return False
            if ck.is_free() != ck2.is_free():
                return False
        try:
            next(iterator2)
        except StopIteration:
            return True
        return False

    def same_heap_states(self, state1, state2):
        return self.chunk_iterators_are_same(state1.heap.chunks(), state2.heap.chunks())

    def max_sym_var_val(self, state):
        return state.libc.max_variable_size

    def _run_malloc_maximizes_sym_arg(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        sc = s.copy()
        x = s.solver.BVS("x", 32)
        s.solver.add(x.UGE(0))
        s.solver.add(x.ULE(self.max_sym_var_val(s)))
        s.heap.malloc(x)
        sc.heap.malloc(self.max_sym_var_val(sc))
        assert self.same_heap_states(s, sc)

    def test_malloc_maximizes_sym_arg_X86(self):
        self._run_free_maximizes_sym_arg("X86")

    def test_malloc_maximizes_sym_arg_AMD64(self):
        self._run_free_maximizes_sym_arg("AMD64")

    def _run_free_maximizes_sym_arg(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        p = s.heap.malloc(50)
        sc = s.copy()
        x = s.solver.BVS("x", 32)
        s.solver.add(x.UGE(0))
        s.solver.add(x.ULE(p))
        s.heap.free(x)
        sc.heap.free(p)
        assert self.same_heap_states(s, sc)

    def test_free_maximizes_sym_arg_X86(self):
        self._run_free_maximizes_sym_arg("X86")

    def test_free_maximizes_sym_arg_AMD64(self):
        self._run_free_maximizes_sym_arg("AMD64")

    def _run_calloc_maximizes_sym_arg(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        sc = s.copy()
        x = s.solver.BVS("x", 32)
        s.solver.add(x.UGE(0))
        s.solver.add(x.ULE(20))
        y = s.solver.BVS("y", 32)
        s.solver.add(y.UGE(0))
        s.solver.add(y.ULE(6))
        s.heap.calloc(x, y)
        sc.heap.calloc(20, 6)
        assert self.same_heap_states(s, sc)

    def test_calloc_maximizes_sym_arg_X86(self):
        self._run_calloc_maximizes_sym_arg("X86")

    def test_calloc_maximizes_sym_arg_AMD64(self):
        self._run_calloc_maximizes_sym_arg("AMD64")

    def _run_realloc_maximizes_sym_arg(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        p = s.heap.malloc(50)
        sc = s.copy()
        x = s.solver.BVS("x", 32)
        s.solver.add(x.UGE(0))
        s.solver.add(x.ULE(p))
        y = s.solver.BVS("y", 32)
        s.solver.add(y.UGE(0))
        s.solver.add(y.ULE(self.max_sym_var_val(s)))
        s.heap.realloc(x, y)
        sc.heap.realloc(p, self.max_sym_var_val(sc))
        assert self.same_heap_states(s, sc)

    def test_realloc_maximizes_sym_arg_X86(self):
        self._run_realloc_maximizes_sym_arg("X86")

    def test_realloc_maximizes_sym_arg_AMD64(self):
        self._run_realloc_maximizes_sym_arg("AMD64")

    def _run_malloc_no_space_returns_null(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        sc = s.copy()
        p1 = s.heap.malloc(0x2000)
        assert p1 == 0
        assert self.same_heap_states(s, sc)

    def test_malloc_no_space_returns_null_X86(self):
        self._run_malloc_no_space_returns_null("X86")

    def test_malloc_no_space_returns_null_AMD64(self):
        self._run_malloc_no_space_returns_null("AMD64")

    def _run_calloc_no_space_returns_null(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        sc = s.copy()
        p1 = s.heap.calloc(0x500, 4)
        assert p1 == 0
        assert self.same_heap_states(s, sc)

    def test_calloc_no_space_returns_null_X86(self):
        self._run_calloc_no_space_returns_null("X86")

    def test_calloc_no_space_returns_null_AMD64(self):
        self._run_calloc_no_space_returns_null("AMD64")

    def _run_realloc_no_space_returns_null(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        p1 = s.heap.malloc(20)
        sc = s.copy()
        p2 = s.heap.realloc(p1, 0x2000)
        assert p2 == 0
        assert self.same_heap_states(s, sc)

    def test_realloc_no_space_returns_null_X86(self):
        self._run_realloc_no_space_returns_null("X86")

    def test_realloc_no_space_returns_null_AMD64(self):
        self._run_realloc_no_space_returns_null("AMD64")

    def _run_first_fit_and_free_malloced_makes_available(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        s.heap.malloc(20)
        p1 = s.heap.malloc(50)
        s.heap.free(p1)
        p2 = s.heap.malloc(30)
        assert p1 == p2

    def test_first_fit_and_free_malloced_makes_available_X86(self):
        self._run_first_fit_and_free_malloced_makes_available("X86")

    def test_first_fit_and_free_malloced_makes_available_AMD64(self):
        self._run_first_fit_and_free_malloced_makes_available("AMD64")

    def _run_free_calloced_makes_available(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        s.heap.calloc(20, 5)
        p1 = s.heap.calloc(30, 4)
        s.heap.free(p1)
        p2 = s.heap.calloc(15, 8)
        assert p1 == p2

    def test_free_calloced_makes_available_X86(self):
        self._run_free_calloced_makes_available("X86")

    def test_free_calloced_makes_available_AMD64(self):
        self._run_free_calloced_makes_available("AMD64")

    def _run_realloc_moves_and_frees(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        s.heap.malloc(20)
        p1 = s.heap.malloc(60)
        s.heap.malloc(200)
        p2 = s.heap.realloc(p1, 300)
        p3 = s.heap.malloc(30)
        assert p1 == p3
        assert p1 < p2

    def test_realloc_moves_and_frees_X86(self):
        self._run_realloc_moves_and_frees("X86")

    def test_realloc_moves_and_frees_AMD64(self):
        self._run_realloc_moves_and_frees("AMD64")

    def _run_realloc_near_same_size(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        s.heap.malloc(20)
        p1 = s.heap.malloc(61)
        s.heap.malloc(80)
        sc = s.copy()
        p2 = s.heap.realloc(p1, 62)
        assert p1 == p2
        assert self.same_heap_states(s, sc)

    def test_realloc_near_same_size_X86(self):
        self._run_realloc_near_same_size("X86")

    def test_realloc_near_same_size_AMD64(self):
        self._run_realloc_near_same_size("AMD64")

    def _run_needs_space_for_metadata(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        sc = s.copy()
        p1 = s.heap.malloc(0x1000)
        assert p1 == 0
        assert self.same_heap_states(s, sc)

    def test_needs_space_for_metadata_X86(self):
        self._run_needs_space_for_metadata("X86")

    def test_needs_space_for_metadata_AMD64(self):
        self._run_needs_space_for_metadata("AMD64")

    def _run_unusable_amount_returns_null(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        s.heap.malloc(0x1000 - 4 * s.heap._chunk_size_t_size)
        sc = s.copy()
        p = s.heap.malloc(1)
        assert p == 0
        assert self.same_heap_states(s, sc)

    def test_unusable_amount_returns_null_X86(self):
        self._run_unusable_amount_returns_null("X86")

    def test_unusable_amount_returns_null_AMD64(self):
        self._run_unusable_amount_returns_null("AMD64")

    def _run_free_null_preserves_state(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        s.heap.malloc(30)
        p = s.heap.malloc(40)
        s.heap.malloc(50)
        s.heap.free(p)
        s2 = s.copy()
        s2.heap.free(0)
        assert self.same_heap_states(s, s2)

    def test_free_null_preserves_state_X86(self):
        self._run_free_null_preserves_state("X86")

    def test_free_null_preserves_state_AMD64(self):
        self._run_free_null_preserves_state("AMD64")

    def _run_skips_chunks_too_small(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        s.heap.malloc(30)
        p = s.heap.malloc(50)
        s.heap.malloc(40)
        s.heap.free(p)
        p2 = s.heap.calloc(20, 5)
        assert p < p2

    def test_skips_chunks_too_small_X86(self):
        self._run_skips_chunks_too_small("X86")

    def test_skips_chunks_too_small_AMD64(self):
        self._run_skips_chunks_too_small("AMD64")

    def _run_calloc_multiplies(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        s.heap.malloc(30)
        sc = s.copy()
        s.heap.malloc(100)
        sc.heap.calloc(4, 25)
        assert self.same_heap_states(s, sc)

    def test_calloc_multiplies_X86(self):
        self._run_calloc_multiplies("X86")

    def test_calloc_multiplies_AMD64(self):
        self._run_calloc_clears("AMD64")

    def _run_calloc_clears(self, arch):
        s = SimState(arch=arch, plugins={"heap": SimHeapPTMalloc(heap_base=0xD0000000, heap_size=0x1000)})
        s.memory.store(0xD0000000 + 2 * s.heap._chunk_size_t_size, s.solver.BVV(-1, 100 * 8))
        sc = s.copy()
        p1 = s.heap.calloc(6, 5)
        p2 = sc.heap.malloc(30)
        v1 = s.memory.load(p1, 30)
        v2 = sc.memory.load(p2, 30)
        assert s.solver.is_true(v1 == 0)
        assert sc.solver.is_true(v2 == -1)

    def test_calloc_clears_X86(self):
        self._run_calloc_clears("X86")

    def test_calloc_clears_AMD64(self):
        self._run_calloc_clears("AMD64")


if __name__ == "__main__":
    unittest.main()
