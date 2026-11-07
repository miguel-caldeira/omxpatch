"""Comparação de versões tolerante (semver, Debian/RPM, Windows, Java 8u351, OpenSSL 1.1.1w…)."""
from __future__ import annotations

import re

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")


def _key(v: str) -> list[tuple[int, object]]:
    v = (v or "").strip().lower().lstrip("v")
    v = re.sub(r"^\d+:", "", v)                 # epoch
    out: list[tuple[int, object]] = []
    for tok in _TOKEN.findall(v):
        out.append((1, int(tok)) if tok.isdigit() else (0, tok))
    return out


def compare(a: str, b: str) -> int:
    """-1, 0, 1. Letras < números (``1.1.1w`` > ``1.1.1``; ``rc``/``beta`` <  versão final)."""
    ka, kb = _key(a), _key(b)
    for x, y in zip(ka, kb):
        if x == y:
            continue
        if x[0] != y[0]:
            return -1 if x[0] < y[0] else 1
        if x[0] == 1:
            return -1 if x[1] < y[1] else 1
        pre = ("alpha", "beta", "rc", "pre", "dev")
        xa, ya = str(x[1]), str(y[1])
        if xa in pre or ya in pre:
            rank = {n: i for i, n in enumerate(pre)}
            return -1 if rank.get(xa, 99) < rank.get(ya, 99) else 1
        return -1 if xa < ya else 1
    if len(ka) == len(kb):
        return 0
    longer, sign = (ka, 1) if len(ka) > len(kb) else (kb, -1)
    extra = longer[min(len(ka), len(kb))]
    if extra[0] == 0 and str(extra[1]) in ("alpha", "beta", "rc", "pre", "dev"):
        return -sign
    return sign if not (extra[0] == 1 and extra[1] == 0 and all(t == (1, 0) for t in longer[min(len(ka), len(kb)):])) else 0


def in_range(version: str, *, start: str = "", start_excl: str = "", end: str = "", end_excl: str = "",
             exact: str = "") -> bool:
    if not version:
        return False
    if exact:
        return compare(version, exact) == 0
    if start and compare(version, start) < 0:
        return False
    if start_excl and compare(version, start_excl) <= 0:
        return False
    if end and compare(version, end) > 0:
        return False
    if end_excl and compare(version, end_excl) >= 0:
        return False
    return bool(start or start_excl or end or end_excl)
