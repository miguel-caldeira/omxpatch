"""Verificação de assinaturas Ed25519 (RFC 8032) em Python puro, só biblioteca padrão — o agente não tem dependências.

Só verifica (a chave privada fica no servidor). É lenta (milissegundos), suficiente para uma assinatura por tarefa."""
from __future__ import annotations

import hashlib

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_B = (_xrecover(_BY) % _P, _BY % _P)


def _add(p, q):
    x1, y1 = p
    x2, y2 = q
    t = _D * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * _inv(1 + t) % _P, (y1 * y2 + x1 * x2) * _inv(1 - t) % _P)


def _mul(p, e: int):
    r = (0, 1)
    while e:
        if e & 1:
            r = _add(r, p)
        p = _add(p, p)
        e >>= 1
    return r


def _decode_point(s: bytes):
    if len(s) != 32:
        raise ValueError("ponto inválido")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("ponto inválido")
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7):
        x = _P - x
    pt = (x, y)
    if (-pt[0] * pt[0] + pt[1] * pt[1] - 1 - _D * pt[0] * pt[0] * pt[1] * pt[1]) % _P != 0:
        raise ValueError("ponto fora da curva")
    return pt


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True se ``signature`` (64 bytes) é válida para ``message`` com a chave pública Ed25519 de 32 bytes."""
    try:
        if len(signature) != 64 or len(public_key) != 32:
            return False
        a = _decode_point(public_key)
        r = _decode_point(signature[:32])
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
        left, right = _mul(_B, s), _add(r, _mul(a, h))
        return left[0] % _P == right[0] % _P and left[1] % _P == right[1] % _P
    except (ValueError, TypeError):
        return False
