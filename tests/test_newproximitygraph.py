import angr


def test_fauxware():
    proj = angr.Project("/home/woadey/members_binary", auto_load_libs=False)

    cfg = proj.analyses.CFG(data_references=True, cross_references=True, normalize=True)
    func = cfg.kb.functions['main']

    prox_1 = proj.analyses.NewProximity(func, cfg.model, cfg.kb.xrefs)  # pylint:disable=unused-variable

    # once we have decompiled code, things are different...
    dec = proj.analyses.Decompiler(func, cfg=cfg.model)
    prox_2 = proj.analyses.NewProximity(func, cfg.model, cfg.kb.xrefs, decompilation=dec)  # pylint:disable=unused-variable


if __name__ == "__main__":
    test_fauxware()
