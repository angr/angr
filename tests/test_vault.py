import unittest

import claripy
import angr


class A:
    n = 0


class TestVault(unittest.TestCase):
    def _do_vault_identity(self, v_factory):
        v = v_factory()
        v.uuid_dedup.add(A)
        assert len(v.keys()) == 0

        a = A()
        b = A()
        b.n = 1
        c = A()
        c.n = 2

        aid = v.store(a)
        assert len(v.keys()) == 1, "Current keys: %s" % v.keys()
        bid = v.store(b)
        assert len(v.keys()) == 2
        cid = v.store(c)
        assert len(v.keys()) == 3

        aa = v.load(aid)
        bb = v.load(bid)
        cc = v.load(cid)

        assert aa is a
        assert bb is b
        assert cc is c

        bb.n = 1337
        del bb
        del b
        import gc

        gc.collect()
        bbb = v.load(bid)
        assert bbb.n == 1

    def _do_vault_noidentity(self, v_factory):
        v = v_factory()
        assert len(v.keys()) == 0

        a = A()
        b = A()
        b.n = 1
        c = A()
        c.n = 2

        aid = v.store(a)
        assert len(v.keys()) == 1, "Current keys: %s" % v.keys()
        bid = v.store(b)
        assert len(v.keys()) == 2
        cid = v.store(c)
        assert len(v.keys()) == 3

        aa = v.load(aid)
        bb = v.load(bid)
        cc = v.load(cid)

        assert aa is not a
        assert bb is not b
        assert cc is not c

        v.store(aa)
        assert len(v.keys()) == 4
        v.store(bb)
        assert len(v.keys()) == 5
        v.store(cc)
        assert len(v.keys()) == 6

    def _do_ast_vault(self, v_factory):
        v = v_factory()
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        z = x + y

        v.store(x)
        assert len(v.keys()) == 1
        zid = v.store(z)
        assert len(v.keys()) == 3
        zz = v.load(zid)
        assert z is zz

        zs = v.dumps(z)
        zzz = v.loads(zs)
        assert zzz is z

    def test_vault_noidentity_VaultDir(self):
        self._do_vault_noidentity(angr.vaults.VaultDir)

    def test_vault_noidentity_VaultShelf(self):
        self._do_vault_noidentity(angr.vaults.VaultShelf)

    def test_vault_noidentity_VaultDict(self):
        self._do_vault_noidentity(angr.vaults.VaultDict)

    def test_vault_noidentity_VaultDirShelf(self):
        self._do_vault_noidentity(angr.vaults.VaultDirShelf)

    def test_vault_identity_VaultDir(self):
        self._do_vault_identity(angr.vaults.VaultDir)

    def test_vault_identity_VaultShelf(self):
        self._do_vault_identity(angr.vaults.VaultShelf)

    def test_vault_identity_VaultDict(self):
        self._do_vault_identity(angr.vaults.VaultDict)

    @unittest.expectedFailure
    def test_vault_identity_VaultDirShelf(self):
        # VaultDirShelf does not guarantee identity equivalence due to the absence of caching
        self._do_vault_identity(angr.vaults.VaultDirShelf)

    def test_ast_vault_do_ast_vault_VaultDir(self):
        self._do_ast_vault(angr.vaults.VaultDir)

    def test_ast_vault_do_ast_vault_VaultShelf(self):
        self._do_ast_vault(angr.vaults.VaultShelf)

    def test_ast_vault_do_ast_vault_VaultDict(self):
        self._do_ast_vault(angr.vaults.VaultDict)

    @unittest.expectedFailure
    def test_ast_vault_VaultDirShelf(self):
        # VaultDirShelf does not guarantee identity equivalence due to the absence of caching
        self._do_ast_vault(angr.vaults.VaultDirShelf)

    def test_project(self):
        v = angr.vaults.VaultDir()
        p = angr.Project("/bin/false", auto_load_libs=False)
        ps = v.store(p)
        pp = v.load(ps)
        assert p is pp
        assert sum(1 for k in v.keys() if k.startswith("Project")) == 1

        pstring = v.dumps(p)
        assert sum(1 for k in v.keys() if k.startswith("Project")) == 1
        pp2 = v.loads(pstring)
        assert sum(1 for k in v.keys() if k.startswith("Project")) == 1
        assert p is pp

        p._asdf = "fdsa"
        del pp2
        del pp
        del p
        import gc

        gc.collect()

        v.load(ps)
        assert sum(1 for k in v.keys() if k.startswith("Project")) == 1


if __name__ == "__main__":
    unittest.main()
