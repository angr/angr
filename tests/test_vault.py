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

	assert aa is not a
	assert bb is not b
	assert cc is not c
	assert aa.n == a.n
	assert bb.n == b.n
	assert cc.n == c.n

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
	yield do_vault, (angr.vaults.VaultDir(),)
	yield do_vault, (angr.vaults.VaultShelf(),)

def test_ast_vault():
	yield do_ast_vault, (angr.vaults.VaultDir(),)
	yield do_ast_vault, (angr.vaults.VaultShelf(),)

if __name__ == '__main__':
	for _a,_b in test_vault():
		_a(*_b)
	for _a,_b in test_ast_vault():
		_a(*_b)
