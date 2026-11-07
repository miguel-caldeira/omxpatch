"""Comparação de versões (cópia mínima do servidor, para o agente não depender dele)."""
from __future__ import annotations

import re

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")
_PRE = ("alpha", "beta", "rc", "pre", "dev")


def _key(v: str):
    v = re.sub(r"^\d+:", "", (v or "").strip().lower().lstrip("v"))
    return [(1, int(t)) if t.isdigit() else (0, t) for t in _TOKEN.findall(v)]


def compare(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    for x, y in zip(ka, kb):
        if x == y:
            continue
        if x[0] != y[0]:
            return -1 if x[0] < y[0] else 1
        if x[0] == 1:
            return -1 if x[1] < y[1] else 1
        if x[1] in _PRE or y[1] in _PRE:
            r = {n: i for i, n in enumerate(_PRE)}
            return -1 if r.get(x[1], 99) < r.get(y[1], 99) else 1
        return -1 if x[1] < y[1] else 1
    if len(ka) == len(kb):
        return 0
    longer, sign = (ka, 1) if len(ka) > len(kb) else (kb, -1)
    extra = longer[min(len(ka), len(kb))]
    if extra[0] == 0 and extra[1] in _PRE:
        return -sign
    rest = longer[min(len(ka), len(kb)):]
    return 0 if all(t == (1, 0) for t in rest) else sign
