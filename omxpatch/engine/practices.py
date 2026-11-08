"""Boas práticas de configuração (hardening) aplicáveis aos ativos: catálogo, parâmetros validados e aplicabilidade.

A execução real é do agente (``omxpatch_agent/practices``): simula (ações com *diff* e verificações), aplica com teste, verificação e
reversão automática, e pode reverter. Servidores suportados: **nginx**, **Apache** e **IIS**."""
from __future__ import annotations

from ..models import Asset

PRACTICES: dict[str, dict] = {
    "tls_protocols": {
        "label": "TLS 1.2 e 1.3 apenas, com cifras seguras", "category": "Servidor web / TLS", "risk": "médio", "servers": ["nginx", "apache", "iis"],
        "desc": "Desativa SSL 2.0/3.0 e TLS 1.0/1.1; ativa TLS 1.2 e, onde suportado, TLS 1.3, com as cifras «intermediate» da Mozilla. "
                "nginx: ssl_protocols/ssl_ciphers · Apache: SSLProtocol/SSLCipherSuite · IIS: Schannel + .NET (exige reinício).",
        "params": {"tls13": ("TLS 1.3", ["auto", "true", "false"], "auto"), "scope": ("IIS: lado do Schannel", ["server", "both"], "server")},
        "warn": "Clientes muito antigos (Windows XP/7 sem atualizações, Java 6/7, Android < 5) deixam de ligar. No IIS afeta todo o equipamento (RDP, SQL…) e exige reinício."},
    "hsts": {
        "label": "HSTS (Strict-Transport-Security)", "category": "Servidor web / cabeçalhos", "risk": "alto", "servers": ["nginx", "apache", "iis"],
        "desc": "Obriga os browsers a usar HTTPS. nginx: add_header · Apache: Header always set (mod_headers) · IIS: customHeaders.",
        "params": {"max_age": ("max-age (s)", None, "31536000"), "include_subdomains": ("includeSubDomains", ["true", "false"], "true"),
                   "preload": ("preload", ["false", "true"], "false")},
        "warn": "Os browsers memorizam o HSTS durante o max-age: confirme que todos os subdomínios têm HTTPS válido antes de aplicar."},
    "hide_version": {
        "label": "Ocultar a versão do servidor", "category": "Servidor web / cabeçalhos", "risk": "baixo", "servers": ["nginx", "apache", "iis"],
        "desc": "nginx: server_tokens off · Apache: ServerTokens Prod e ServerSignature Off · IIS: removeServerHeader, X-Powered-By e X-AspNet-Version.",
        "params": {}, "warn": ""},
    "security_headers": {
        "label": "Cabeçalhos de segurança (nosniff, X-Frame-Options, Referrer-Policy)", "category": "Servidor web / cabeçalhos", "risk": "baixo",
        "servers": ["nginx", "apache", "iis"], "desc": "X-Content-Type-Options: nosniff · X-Frame-Options: SAMEORIGIN · Referrer-Policy: same-origin.",
        "params": {}, "warn": "X-Frame-Options SAMEORIGIN impede que as páginas sejam embebidas por outros sites."},
    "ssh_hardening": {
        "label": "SSH: sem root, sem palavras-passe vazias (e sem palavra-passe, se houver chaves)", "category": "Sistema operativo", "risk": "médio", "servers": [], "os": ["linux", "macos"],
        "desc": "Corrige configurações fracas do servidor OpenSSH: PermitRootLogin no, PermitEmptyPasswords no e, opcionalmente, PasswordAuthentication no. "
                "Ficheiro próprio em sshd_config.d (ou o principal), validado com sshd -t, recarregado, verificado e revertido sozinho se falhar.",
        "params": {"disable_password": ("Desativar palavra-passe (só com chaves autorizadas)", ["false", "true"], "false")},
        "warn": "Desativar a palavra-passe corta quem ainda não tem chave: o plano bloqueia se não existir nenhuma chave autorizada, mas confirme com os administradores."},
    "windows_hardening": {
        "label": "Windows: desativar SMBv1 e exigir NLA no RDP", "category": "Sistema operativo", "risk": "médio", "servers": [], "os": ["windows"],
        "desc": "Desativa o protocolo SMBv1 (vetor de WannaCry/EternalBlue) e ativa a autenticação ao nível da rede (NLA) no RDP. Valor anterior guardado e reposto se a verificação falhar.",
        "params": {}, "warn": "Equipamentos muito antigos (XP/2003, impressoras antigas) deixam de partilhar ficheiros por SMBv1; clientes RDP sem NLA deixam de ligar."},
}


def clean_params(practice: str, raw: dict) -> dict:
    """Valida os parâmetros recebidos (valores só das listas permitidas ou números limitados)."""
    spec = PRACTICES[practice]["params"]
    out: dict = {}
    for key, (_label, choices, default) in spec.items():
        v = str(raw.get(key, default)).strip().lower()
        if key == "max_age":
            n = int(v) if v.isdigit() else int(default)
            out[key] = max(0, min(n, 63072000))
        elif choices:
            v = v if v in choices else default
            out[key] = (v == "true") if v in ("true", "false") and key != "tls13" else v
    if raw.get("server") in ("nginx", "apache", "iis"):
        out["server"] = raw["server"]
    return out


def detected_servers(asset: Asset) -> list[str]:
    return [w.get("type") for w in asset.hw.get("webservers", []) if w.get("type")]


def applicable(asset: Asset, practice: str) -> tuple[bool, str]:
    """(aplicável, motivo). Sem inventário de servidores web (agente antigo) aceita e deixa a simulação decidir."""
    if practice not in PRACTICES:
        return False, "Boa prática desconhecida"
    oses = PRACTICES[practice].get("os")
    if oses:
        return (True, "") if asset.os_family in oses else (False, f"Esta boa prática aplica-se a {', '.join(oses)}")
    if asset.os_family == "macos":
        return False, "Sem servidores web suportados em macOS"
    known = asset.hw.get("webservers")
    if known is None:
        return True, "servidores web ainda não inventariados: a simulação verifica"
    mine = set(detected_servers(asset)) & set(PRACTICES[practice]["servers"])
    return (True, "") if mine else (False, "Nenhum servidor web suportado (nginx, Apache, IIS) detetado")
