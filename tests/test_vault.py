import claripy
import angr

import nose.tools

class A:
	n = 0

def do_vault_identity(v_factory):
	v = v_factory()
	v.uuid_dedup.add(A)
	assert len(v.keys()) == 0

	a = A()
	b = A()
	b.n = 1
	c = A()
	c.n = 2

	aid = v.store(a)
	nose.tools.assert_equal(len(v.keys()), 1, msg="Current keys: %s" % v.keys())
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

def do_vault_noidentity(v_factory):
	v = v_factory()
	assert len(v.keys()) == 0

	a = A()
	b = A()
	b.n = 1
	c = A()
	c.n = 2

	aid = v.store(a)
	assert len(v.keys()) == 1
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

def do_ast_vault(v_factory):
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

def test_vault():
	yield do_vault_noidentity, angr.vaults.VaultDir
	yield do_vault_noidentity, angr.vaults.VaultShelf
	yield do_vault_noidentity, angr.vaults.VaultDict
	yield do_vault_noidentity, angr.vaults.VaultDirShelf
	yield do_vault_identity, angr.vaults.VaultDir
	yield do_vault_identity, angr.vaults.VaultShelf
	yield do_vault_identity, angr.vaults.VaultDict
	# VaultDirShelf does not guarantee identity equivalence due to the absence of caching
	# yield do_vault_identity, angr.vaults.VaultDirShelf

def test_ast_vault():
	yield do_ast_vault, angr.vaults.VaultDir
	yield do_ast_vault, angr.vaults.VaultShelf
	yield do_ast_vault, angr.vaults.VaultDict
	# VaultDirShelf does not guarantee identity equivalence due to the absence of caching
	# yield do_ast_vault, angr.vaults.VaultDirShelf

def test_project():
	v = angr.vaults.VaultDir()
	p = angr.Project("/bin/false")
	ps = v.store(p)
	pp = v.load(ps)
	assert p is pp
	assert sum(1 for k in v.keys() if k.startswith('Project')) == 1

	pstring = v.dumps(p)
	assert sum(1 for k in v.keys() if k.startswith('Project')) == 1
	pp2 = v.loads(pstring)
	assert sum(1 for k in v.keys() if k.startswith('Project')) == 1
	assert p is pp

	p._asdf = 'fdsa'
	del pp2
	del pp
	del p
	import gc
	gc.collect()

	p = v.load(ps)
	#assert not hasattr(p, '_asdf')
	assert sum(1 for k in v.keys() if k.startswith('Project')) == 1



if __name__ == '__main__':
	for _a,_b in test_vault():
		_a(_b)
	for _a,_b in test_ast_vault():
		_a(_b)
	test_project()
