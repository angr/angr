from __future__ import annotations

from abc import abstractmethod
import struct
from typing import Any, TypeVar
from itertools import count

from Crypto.Cipher import ARC4
import hashlib

import claripy

from angr import SimProcedure, errors
from angr.state_plugins.plugin import SimStatePlugin

T = TypeVar("T")


class CryptHasher:
    @abstractmethod
    def update(self, data: bytes): ...

    @abstractmethod
    def digest(self) -> bytes: ...


class CryptCipher:
    @abstractmethod
    def encrypt(self, data: bytes) -> bytes: ...

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes: ...


class CryptMD5(CryptHasher):
    def __init__(self):
        self.md5 = hashlib.md5()

    def update(self, data):
        self.md5.update(data)

    def digest(self):
        return self.md5.digest()


class CryptRC4(CryptCipher):
    def __init__(self, key: bytes):
        self.rc4 = ARC4.new(key)

    def encrypt(self, data):
        return self.rc4.encrypt(data)

    def decrypt(self, data):
        return self.rc4.decrypt(data)


def get_context(state, pointer: int | claripy.ast.BV, ty: type[T]) -> T | None:
    if not isinstance(pointer, int):
        (pointer,) = state.solver.eval_atmost(pointer, 1, cast_to=int)
    if not state.has_plugin("crypt"):
        state.register_plugin("crypt", CryptPlugin())
    return state.crypt.get(pointer, ty, False)


def new_context(state, ty: type[T], *args, **kwargs) -> tuple[int, T]:
    if not state.has_plugin("crypt"):
        state.register_plugin("crypt", CryptPlugin())
    ident = next(idgen)
    r = state.crypt.get(ident, ty, True, *args, **kwargs)
    assert r is not None
    return ident, r


idgen = count(1)


class CryptAcquireContextA(SimProcedure):
    def run(self, provider_p, container, provider, provider_type, flags):
        self.state.mem[provider_p].dword = struct.unpack("<I", b"angr")[0]
        return 1


class CryptCreateHash(SimProcedure):
    def run(self, provider, algid_bv, key, flags, hashout):
        (algid,) = self.state.solver.eval_atmost(algid_bv, 1)
        if algid == 0x8003:
            ident, _ = new_context(self.state, CryptMD5)
        else:
            return 0

        self.state.mem[hashout].dword = ident
        return 1


class CryptHashData(SimProcedure):
    def run(self, hashident_bv, data_p, data_len_bv, flags):
        (hashident,) = self.state.solver.eval_atmost(hashident_bv, 1)
        ctx = get_context(self.state, hashident, CryptHasher)
        if ctx is None:
            return 0
        (data_len,) = self.state.solver.eval_atmost(data_len_bv, 1)
        data_bv = self.state.memory.load(data_p, data_len)
        (data,) = self.state.solver.eval_atmost(data_bv, 1, cast_to=bytes)
        ctx.update(data)
        return 1


class CryptDeriveKey(SimProcedure):
    def run(self, provider, algid_bv, hashident_bv, flags, key_p):
        (algid,) = self.state.solver.eval_atmost(algid_bv, 1)
        (hashident,) = self.state.solver.eval_atmost(hashident_bv, 1)
        hctx = get_context(self.state, hashident, CryptHasher)
        if hctx is None:
            return 0
        if algid == 0x6801:
            ident, _ = new_context(self.state, CryptRC4, hctx.digest())
        else:
            return 0
        self.state.mem[key_p].dword = ident
        return 1


class CryptEncrypt(SimProcedure):
    def run(self, key, hash_, final_bv, flags, data_p, data_len_p, data_buf_len_bv):
        kctx = get_context(self.state, key, CryptCipher)
        if kctx is None:
            return 0
        # hctx = get_context(self.state, hash_, CryptHasher)
        data_len = self.state.mem[data_len_p].dword.concrete
        data_bv = self.state.memory.load(data_p, data_len)
        (data_bytes,) = self.state.solver.eval_atmost(data_bv, 1, cast_to=bytes)
        (data_buf_len,) = self.state.solver.eval_atmost(data_buf_len_bv, 1)

        crypted = kctx.encrypt(data_bytes)
        if len(crypted) < data_buf_len:
            return 0
        self.state.memory.store(data_p, crypted)
        self.state.mem[data_len_p].dword = len(crypted)
        return 1


class CryptPlugin(SimStatePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.context: dict[int, Any] = {}
        self.cow_pred: CryptPlugin | None = None
        self.cow_used: bool = False

    @SimStatePlugin.memo
    def copy(self, memo):
        o = type(self)()
        o.cow_pred = self if self.cow_pred is None else self.cow_pred
        return o

    def get(self, ident: int, ty: type[T], create: bool, *args, **kwargs) -> T | None:
        if self.cow_used or (self.cow_pred is not None and self.cow_pred.cow_used):
            raise errors.SimError("Can't perform cryptography on a copied state. sorry")
        if self.cow_pred is not None:
            self.cow_pred.cow_used = True
            self.context = self.cow_pred.context
            self.cow_pred.context = {}
            self.cow_pred = None

        if ident not in self.context:
            if not create:
                return None
            r = ty(*args, **kwargs)
            self.context[ident] = r
            return r
        r = self.context[ident]
        if not isinstance(r, ty):
            return None
        return r
