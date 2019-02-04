import nose.tools
from angr import SimState, SimHeapPTMalloc

# TODO: Make these tests more architecture-independent (note dependencies of some behavior on chunk metadata size)

def chunk_iterators_are_same(iterator1, iterator2):
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

def same_heap_states(state1, state2):
    return chunk_iterators_are_same(state1.heap.chunks(), state2.heap.chunks())


def max_sym_var_val(state):
    return state.libc.max_variable_size


def run_malloc_maximizes_sym_arg(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    sc = s.copy()
    x = s.solver.BVS("x", 32)
    s.solver.add(x.UGE(0))
    s.solver.add(x.ULE(max_sym_var_val(s)))
    s.heap.malloc(x)
    sc.heap.malloc(max_sym_var_val(sc))
    nose.tools.assert_true(same_heap_states(s, sc))

def test_malloc_maximizes_sym_arg():
    for arch in ('X86', 'AMD64'):
        yield run_malloc_maximizes_sym_arg, arch


def run_free_maximizes_sym_arg(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    p = s.heap.malloc(50)
    sc = s.copy()
    x = s.solver.BVS("x", 32)
    s.solver.add(x.UGE(0))
    s.solver.add(x.ULE(p))
    s.heap.free(x)
    sc.heap.free(p)
    nose.tools.assert_true(same_heap_states(s, sc))

def test_free_maximizes_sym_arg():
    for arch in ('X86', 'AMD64'):
        yield run_free_maximizes_sym_arg, arch


def run_calloc_maximizes_sym_arg(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    sc = s.copy()
    x = s.solver.BVS("x", 32)
    s.solver.add(x.UGE(0))
    s.solver.add(x.ULE(20))
    y = s.solver.BVS("y", 32)
    s.solver.add(y.UGE(0))
    s.solver.add(y.ULE(6))
    s.heap.calloc(x, y)
    sc.heap.calloc(20, 6)
    nose.tools.assert_true(same_heap_states(s, sc))

def test_calloc_maximizes_sym_arg():
    for arch in ('X86', 'AMD64'):
        yield run_calloc_maximizes_sym_arg, arch


def run_realloc_maximizes_sym_arg(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    p = s.heap.malloc(50)
    sc = s.copy()
    x = s.solver.BVS("x", 32)
    s.solver.add(x.UGE(0))
    s.solver.add(x.ULE(p))
    y = s.solver.BVS("y", 32)
    s.solver.add(y.UGE(0))
    s.solver.add(y.ULE(max_sym_var_val(s)))
    s.heap.realloc(x, y)
    sc.heap.realloc(p, max_sym_var_val(sc))
    nose.tools.assert_true(same_heap_states(s, sc))

def test_realloc_maximizes_sym_arg():
    for arch in ('X86', 'AMD64'):
        yield run_realloc_maximizes_sym_arg, arch


def run_malloc_no_space_returns_null(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    sc = s.copy()
    p1 = s.heap.malloc(0x2000)
    nose.tools.assert_equals(p1, 0)
    nose.tools.assert_true(same_heap_states(s, sc))

def test_malloc_no_space_returns_null():
    for arch in ('X86', 'AMD64'):
        yield run_malloc_no_space_returns_null, arch


def run_calloc_no_space_returns_null(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    sc = s.copy()
    p1 = s.heap.calloc(0x500, 4)
    nose.tools.assert_equals(p1, 0)
    nose.tools.assert_true(same_heap_states(s, sc))

def test_calloc_no_space_returns_null():
    for arch in ('X86', 'AMD64'):
        yield run_calloc_no_space_returns_null, arch


def run_realloc_no_space_returns_null(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    p1 = s.heap.malloc(20)
    sc = s.copy()
    p2 = s.heap.realloc(p1, 0x2000)
    nose.tools.assert_equals(p2, 0)
    nose.tools.assert_true(same_heap_states(s, sc))

def test_realloc_no_space_returns_null():
    for arch in ('X86', 'AMD64'):
        yield run_realloc_no_space_returns_null, arch


def run_first_fit_and_free_malloced_makes_available(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    s.heap.malloc(20)
    p1 = s.heap.malloc(50)
    s.heap.free(p1)
    p2 = s.heap.malloc(30)
    nose.tools.assert_equals(p1, p2)

def test_first_fit_and_free_malloced_makes_available():
    for arch in ('X86', 'AMD64'):
        yield run_first_fit_and_free_malloced_makes_available, arch


def run_free_calloced_makes_available(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    s.heap.calloc(20, 5)
    p1 = s.heap.calloc(30, 4)
    s.heap.free(p1)
    p2 = s.heap.calloc(15, 8)
    nose.tools.assert_equals(p1, p2)

def test_free_calloced_makes_available():
    for arch in ('X86', 'AMD64'):
        yield run_free_calloced_makes_available, arch


def run_realloc_moves_and_frees(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    s.heap.malloc(20)
    p1 = s.heap.malloc(60)
    s.heap.malloc(200)
    p2 = s.heap.realloc(p1, 300)
    p3 = s.heap.malloc(30)
    nose.tools.assert_equals(p1, p3)
    nose.tools.assert_less(p1, p2)

def test_realloc_moves_and_frees():
    for arch in ('X86', 'AMD64'):
        yield run_realloc_moves_and_frees, arch


def run_realloc_near_same_size(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    s.heap.malloc(20)
    p1 = s.heap.malloc(61)
    s.heap.malloc(80)
    sc = s.copy()
    p2 = s.heap.realloc(p1, 62)
    nose.tools.assert_equals(p1, p2)
    nose.tools.assert_true(same_heap_states(s, sc))

def test_realloc_near_same_size():
    for arch in ('X86', 'AMD64'):
        yield run_realloc_near_same_size, arch


def run_needs_space_for_metadata(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    sc = s.copy()
    p1 = s.heap.malloc(0x1000)
    nose.tools.assert_equals(p1, 0)
    nose.tools.assert_true(same_heap_states(s, sc))

def test_needs_space_for_metadata():
    for arch in ('X86', 'AMD64'):
        yield run_needs_space_for_metadata, arch


def run_unusable_amount_returns_null(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    s.heap.malloc(0x1000 - 4 * s.heap._chunk_size_t_size)
    sc = s.copy()
    p = s.heap.malloc(1)
    nose.tools.assert_equals(p, 0)
    nose.tools.assert_true(same_heap_states(s, sc))

def test_unusable_amount_returns_null():
    for arch in ('X86', 'AMD64'):
        yield run_unusable_amount_returns_null, arch


def run_free_null_preserves_state(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    s.heap.malloc(30)
    p = s.heap.malloc(40)
    s.heap.malloc(50)
    s.heap.free(p)
    s2 = s.copy()
    s2.heap.free(0)
    nose.tools.assert_true(same_heap_states(s, s2))

def test_free_null_preserves_state():
    for arch in ('X86', 'AMD64'):
        yield run_free_null_preserves_state, arch


def run_skips_chunks_too_small(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    s.heap.malloc(30)
    p = s.heap.malloc(50)
    s.heap.malloc(40)
    s.heap.free(p)
    p2 = s.heap.calloc(20, 5)
    nose.tools.assert_less(p, p2)

def test_skips_chunks_too_small():
    for arch in ('X86', 'AMD64'):
        yield run_skips_chunks_too_small, arch


def run_calloc_multiplies(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    s.heap.malloc(30)
    sc = s.copy()
    s.heap.malloc(100)
    sc.heap.calloc(4, 25)
    nose.tools.assert_true(same_heap_states(s, sc))

def test_calloc_multiplies():
    for arch in ('X86', 'AMD64'):
        yield run_calloc_multiplies, arch


def run_calloc_clears(arch):
    s = SimState(arch=arch, plugins={'heap': SimHeapPTMalloc(heap_base=0xd0000000, heap_size=0x1000)})
    s.memory.store(0xd0000000 + 2 * s.heap._chunk_size_t_size, s.solver.BVV(-1, 100 * 8))
    sc = s.copy()
    p1 = s.heap.calloc(6, 5)
    p2 = sc.heap.malloc(30)
    v1 = s.memory.load(p1, 30)
    v2 = sc.memory.load(p2, 30)
    nose.tools.assert_true(s.solver.is_true(v1 == 0))
    nose.tools.assert_true(sc.solver.is_true(v2 == -1))

def test_calloc_clears():
    for arch in ('X86', 'AMD64'):
        yield run_calloc_clears, arch


if __name__ == "__main__":
    g = globals().copy()
    for func_name, func in g.items():
        if func_name.startswith("test_") and hasattr(func, '__call__'):
            for r, a in func():
                r(a)
