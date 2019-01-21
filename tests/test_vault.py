import claripy
import angr

class A:
	n = 0

def do_vault(v):
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


def do_ast_vault(v):
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
	yield do_vault, angr.vaults.VaultDir()
	yield do_vault, angr.vaults.VaultShelf()
	yield do_vault, angr.vaults.VaultDict()

def test_ast_vault():
	yield do_ast_vault, angr.vaults.VaultDir()
	yield do_ast_vault, angr.vaults.VaultShelf()
	yield do_ast_vault, angr.vaults.VaultDict()

def test_project():
	v = angr.vaults.VaultDir()
	p = angr.Project("/bin/false")
	pid = id(p)
	ps = v.store(p)
	pp = v.load(ps)
	assert p is pp
	assert len(v.keys()) == 1

	pstring = v.dumps(p)
	assert len(v.keys()) == 1
	pp2 = v.loads(pstring)
	assert len(v.keys()) == 1
	assert p is pp

	del pp2
	del pp
	del p
	import gc
	gc.collect()

	p = v.load(ps)
	assert id(p) != pid
	assert len(v.keys()) == 1



if __name__ == '__main__':
	for _a,_b in test_vault():
		_a(_b)
	for _a,_b in test_ast_vault():
		_a(_b)
	test_project()
