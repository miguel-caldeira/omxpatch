"""Autenticação multifator.

Arquitetura por fornecedores (``PROVIDERS``) para permitir no futuro outros
métodos (ex.: WebAuthn/FIDO2, push) sem alterar o fluxo de login. Hoje:

* ``totp`` — RFC 6238 (SHA-1, 6 dígitos, 30 s), o perfil suportado por
  **Google Authenticator**, **FreeOTP**/FreeOTP+, Microsoft Authenticator,
  Authy, 1Password, Bitwarden, etc. Registo por QR code ou chave manual,
  com proteção contra reutilização do mesmo código (anti-replay).
* Códigos de recuperação de uso único (guardados como SHA-256).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from urllib.parse import quote

from flask import current_app

from .security import _totp_at, totp_new_secret

RECOVERY_CODES = 10


class TOTPProvider:
    key = "totp"
    label = "Aplicação autenticadora (TOTP — Google Authenticator, FreeOTP, Microsoft Authenticator…)"
    digits, period, algorithm = 6, 30, "SHA1"

    def new_secret(self) -> str:
        return totp_new_secret()

    def uri(self, secret: str, account: str) -> str:
        issuer = current_app.config.get("MFA_ISSUER") or "OMXPatch"
        label = quote(f"{issuer}:{account}", safe=":")
        return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
                f"&algorithm={self.algorithm}&digits={self.digits}&period={self.period}")

    def match(self, secret: str, code: str, last_counter: int | None = None, window: int = 1,
              now: float | None = None) -> int | None:
        """Devolve o contador TOTP aceite, ou None. Rejeita códigos já usados (anti-replay)."""
        code = (code or "").strip().replace(" ", "")
        if not secret or len(code) != self.digits or not code.isdigit():
            return None
        counter = int((now or time.time()) // self.period)
        for d in range(-window, window + 1):
            c = counter + d
            if last_counter is not None and c <= last_counter:
                continue
            if hmac.compare_digest(_totp_at(secret, c), code):
                return c
        return None


PROVIDERS = {"totp": TOTPProvider()}


def provider(user) -> TOTPProvider:
    return PROVIDERS.get(getattr(user, "mfa_method", None) or "totp", PROVIDERS["totp"])


def qr_image(data: str) -> str | None:
    """QR code como imagem PNG (data URI) com a zona de silêncio de 4 módulos exigida pela norma
    ISO/IEC 18004 — necessária para a leitura pelo Google Authenticator / FreeOTP. Desenhado em
    tamanho natural (sem redimensionamento por CSS, que distorce ou corta os módulos)."""
    try:
        import segno
    except ImportError:
        return None
    return segno.make(data, error="m").png_data_uri(scale=6, border=4, dark="#000000", light="#ffffff")


def _hash(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").replace(" ", "").lower().encode()).hexdigest()


def new_recovery_codes() -> tuple[list[str], str]:
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = secrets.token_hex(5)
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, ",".join(_hash(c) for c in codes)


def use_recovery_code(user, code: str) -> bool:
    hashes = [h for h in (user.mfa_recovery_codes or "").split(",") if h]
    h = _hash(code or "")
    for stored in hashes:
        if hmac.compare_digest(stored, h):
            hashes.remove(stored)
            user.mfa_recovery_codes = ",".join(hashes)
            return True
    return False


def recovery_left(user) -> int:
    return len([h for h in (user.mfa_recovery_codes or "").split(",") if h])


def verify_login(user, code: str) -> str | None:
    """Valida o 2.º fator no login. Devolve 'totp', 'recovery' ou None."""
    p = provider(user)
    counter = p.match(user.mfa_secret, code, user.mfa_last_counter)
    if counter is not None:
        user.mfa_last_counter = counter
        return "totp"
    if code and len(code.replace("-", "").strip()) == 10 and use_recovery_code(user, code):
        return "recovery"
    return None
