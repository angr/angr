
import angr


def test_libc_x86():

    p = angr.Project("C:\\Users\\Fish\\Desktop\\temp\\angr_rtld\\libc.so.6", auto_load_libs=True)
    dl_addr = p.loader.find_symbol('_dl_addr').rebased_addr
    cfg = p.analyses.CFGFast(regions=[(dl_addr, dl_addr + 4096)])
    func = cfg.functions['_dl_addr']

    rtld_global_sym = p.loader.find_symbol('_rtld_global')
    assert rtld_global_sym is not None
    _rtld_global_addr = rtld_global_sym.rebased_addr

    base_addr = 0x998f000
    state = p.factory.blank_state()
    for addr in range(0, 0 + 0x1000, p.arch.bytes):
        state.memory.store(_rtld_global_addr + addr, base_addr + addr, size=p.arch.bytes,
                           endness=p.arch.memory_endness)

    p.analyses.ConstantPropagation(func=func, base_state=state)


if __name__ == "__main__":
    test_libc_x86()
