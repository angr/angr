
DEFAULT_STATEMENT = -2


def is_alignment_mask(n):
    return n in {0xffffffffffffffe0, 0xfffffffffffffff0, 0xfffffff0, 0xfffffffc}
