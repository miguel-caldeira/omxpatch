"""Identidade visual por organização: logótipo e cores aplicados à interface, ao painel e aos relatórios.

As cores escolhidas são ajustadas automaticamente para manter contraste legível (WCAG):
* barra superior — o texto passa a branco ou quase-preto, o que tiver mais contraste;
* cor principal (botões e ligações) — escurecida no modo claro / clareada no modo escuro até 4,5:1
  com o fundo dos painéis (texto) e com o texto dos botões;
* cor de destaque — usada em elementos decorativos (sublinhado dos relatórios, marca), mínimo 3:1.

O tema é servido como folha de estilos (``/branding/theme.css``) para respeitar a CSP (sem estilos inline).
O logótipo (PNG, JPEG ou WebP; SVG não é aceite por poder conter código) fica em ``<dados>/branding``.
"""
from __future__ import annotations

import re
from pathlib import Path

HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
DEFAULTS = {"brand_header": "#172c6c", "brand_primary": "#0053ad", "brand_accent": "#ff8000"}
LIGHT_PANEL, DARK_PANEL = "#ffffff", "#171d29"
LOGO_TYPES = {b"\x89PNG\r\n\x1a\n": ("png", "image/png"), b"\xff\xd8\xff": ("jpg", "image/jpeg")}
MAX_LOGO_BYTES = 512 * 1024


# --------------------------------------------------------------------------- cor


def valid_hex(value: str | None) -> bool:
    return bool(value and HEX_RE.match(value))


def _rgb(h: str) -> tuple[float, float, float]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]


def _hex(rgb) -> str:
    return "#" + "".join(f"{max(0, min(255, round(c * 255))):02x}" for c in rgb)


def luminance(h: str) -> float:
    def ch(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(c) for c in _rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return round((la + 0.05) / (lb + 0.05), 2)


def mix(a: str, b: str, t: float) -> str:
    ra, rb = _rgb(a), _rgb(b)
    return _hex(tuple(x + (y - x) * t for x, y in zip(ra, rb)))


def ensure_contrast(color: str, background: str, minimum: float) -> str:
    """Escurece (fundo claro) ou clareia (fundo escuro) a cor até atingir o contraste mínimo."""
    if contrast(color, background) >= minimum:
        return color
    target = "#000000" if luminance(background) > 0.5 else "#ffffff"
    for i in range(1, 21):
        c = mix(color, target, i / 20)
        if contrast(c, background) >= minimum:
            return c
    return target


def on_color(background: str) -> str:
    """Texto legível sobre a cor: branco ou quase-preto."""
    return "#ffffff" if contrast("#ffffff", background) >= contrast("#111111", background) else "#111111"


def palette(tenant) -> dict:
    header = tenant.brand_header if valid_hex(getattr(tenant, "brand_header", "")) else DEFAULTS["brand_header"]
    primary = tenant.brand_primary if valid_hex(getattr(tenant, "brand_primary", "")) else DEFAULTS["brand_primary"]
    accent = tenant.brand_accent if valid_hex(getattr(tenant, "brand_accent", "")) else DEFAULTS["brand_accent"]
    header_fg = on_color(header)
    light_primary = ensure_contrast(primary, LIGHT_PANEL, 4.5)
    dark_primary = ensure_contrast(primary, DARK_PANEL, 4.5)
    return {
        "header": header, "header_fg": header_fg,
        "header_muted": mix(header_fg, header, 0.18),
        "header_hover": mix(header, header_fg, 0.12),
        "primary": light_primary, "on_primary": on_color(light_primary),
        "primary_dark": dark_primary, "on_primary_dark": on_color(dark_primary),
        "accent": ensure_contrast(accent, LIGHT_PANEL, 3.0),
        "accent_on_header": ensure_contrast(accent, header, 3.0),
        "report_title": ensure_contrast(header, LIGHT_PANEL, 4.5),
        "adjusted": {
            "primary": light_primary.lower() != primary.lower(),
            "primary_dark": dark_primary.lower() != primary.lower(),
            "accent": ensure_contrast(accent, LIGHT_PANEL, 3.0).lower() != accent.lower(),
        },
        "source": {"header": header, "primary": primary, "accent": accent},
    }


def is_custom(tenant) -> bool:
    return bool(tenant is not None and (tenant.logo_file or any(
        valid_hex(getattr(tenant, k, "")) and getattr(tenant, k).lower() != v for k, v in DEFAULTS.items())))


def theme_css(tenant) -> str:
    if tenant is None or not is_custom(tenant):
        return "/* tema por omissão */\n"
    p = palette(tenant)
    return f"""/* Identidade visual: {tenant.name} */
:root{{--brand2:{p['primary']};--accent:{p['accent']};--header-bg:{p['header']};--header-fg:{p['header_fg']};
--header-muted:{p['header_muted']};--header-hover:{p['header_hover']};--on-brand2:{p['on_primary']};
--report-title:{p['report_title']};--logo-accent:{p['accent_on_header']}}}
@media (prefers-color-scheme:dark){{:root{{--brand2:{p['primary_dark']};--on-brand2:{p['on_primary_dark']}}}}}
"""


# --------------------------------------------------------------------------- logótipo


def logo_kind(data: bytes) -> tuple[str, str] | None:
    for magic, kind in LOGO_TYPES.items():
        if data.startswith(magic):
            return kind
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp", "image/webp"
    return None


def logo_dir(cfg) -> Path:
    return Path(cfg["DATA_DIR"]) / "branding"


def save_logo(cfg, tenant, data: bytes) -> str:
    if len(data) > MAX_LOGO_BYTES:
        raise ValueError(f"O logótipo excede {MAX_LOGO_BYTES // 1024} KB")
    kind = logo_kind(data)
    if kind is None:
        raise ValueError("Formato não suportado: use PNG, JPEG ou WebP")
    folder = logo_dir(cfg)
    folder.mkdir(parents=True, exist_ok=True)
    remove_logo(cfg, tenant)
    tenant.brand_version = (tenant.brand_version or 0) + 1
    name = f"tenant-{tenant.id}-{tenant.brand_version}.{kind[0]}"
    (folder / name).write_bytes(data)
    tenant.logo_file = name
    return name


def remove_logo(cfg, tenant) -> None:
    if tenant.logo_file:
        path = logo_dir(cfg) / Path(tenant.logo_file).name
        if path.is_file():
            path.unlink()
        tenant.logo_file = ""


def logo_path(cfg, tenant) -> Path | None:
    if not tenant.logo_file:
        return None
    path = logo_dir(cfg) / Path(tenant.logo_file).name
    return path if path.is_file() else None


def mimetype(name: str) -> str:
    return {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp"}.get(name.rsplit(".", 1)[-1], "image/png")
