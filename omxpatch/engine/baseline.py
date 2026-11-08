"""Linhas de base (gold images): os requisitos que as imagens padrão devem trazer para que novas máquinas **não nasçam** com a vulnerabilidade.

Alimentadas automaticamente pelas remediações bem-sucedidas (patch → versão mínima do pacote; boa prática → parâmetros) e editáveis. Servem
para (1) medir o desvio dos ativos existentes e (2) exportar para a pipeline de imagens (Ansible, shell, Packer, JSON)."""
from __future__ import annotations

import json
import shlex

from ..extensions import db
from ..models import Asset, AssetSoftware, BaselineItem, PlanItem, Tenant, utcnow
from .versions import compare


def capture(it: PlanItem) -> BaselineItem | None:
    """Regista (ou sobe) o requisito da linha de base a partir de um item de plano concluído."""
    asset = it.asset
    scope = asset.os_family or "linux"
    if it.kind == "patch" and it.patch is not None:
        p = it.patch
        name = p.package_name or p.patch_uid
        row = BaselineItem.query.filter_by(tenant_id=it.tenant_id, scope=scope, kind="patch", name=name).first()
        if row is None:
            row = BaselineItem(tenant_id=it.tenant_id, scope=scope, kind="patch", name=name, installer=p.installer, min_version=p.version_fixed or "", source_plan_id=it.plan_id,
                               cves=json.dumps(p.cve_list), note=f"de {p.patch_uid}")
            db.session.add(row)
        else:
            if p.version_fixed and compare(p.version_fixed, row.min_version or "0") > 0:
                row.min_version, row.source_plan_id = p.version_fixed, it.plan_id
            row.cves = json.dumps(sorted(set(row.cve_list) | set(p.cve_list)))
            row.active = True
        return row
    if it.kind == "practice" and it.practice:
        row = BaselineItem.query.filter_by(tenant_id=it.tenant_id, scope=scope, kind="practice", name=it.practice).first()
        if row is None:
            row = BaselineItem(tenant_id=it.tenant_id, scope=scope, kind="practice", name=it.practice, params=json.dumps(it.params_data), source_plan_id=it.plan_id,
                               note="boa prática aplicada com sucesso")
            db.session.add(row)
        else:
            row.params, row.source_plan_id, row.active = json.dumps(it.params_data), it.plan_id, True
        return row
    return None


def items(tenant: Tenant, scope: str | None = None) -> list[BaselineItem]:
    q = BaselineItem.query.filter_by(tenant_id=tenant.id, active=True)
    if scope:
        q = q.filter_by(scope=scope)
    return q.order_by(BaselineItem.scope, BaselineItem.kind, BaselineItem.name).all()


def drift(tenant: Tenant) -> list[dict]:
    """Ativos que não cumprem a linha de base do seu SO: patch abaixo da versão mínima (ou em falta) e boas práticas por aplicar."""
    out = []
    done: dict[int, set] = {}
    for it in PlanItem.query.filter_by(tenant_id=tenant.id, kind="practice", status="succeeded"):
        done.setdefault(it.asset_id, set()).add(it.practice)
    by_scope: dict[str, list[BaselineItem]] = {}
    for b in items(tenant):
        by_scope.setdefault(b.scope.split(":")[0], []).append(b)
    for a in Asset.query.filter_by(tenant_id=tenant.id).all():
        gaps = []
        sw = {s.name.lower(): s.version for s in AssetSoftware.query.filter_by(asset_id=a.id)}
        for b in by_scope.get(a.os_family or "", []):
            if b.kind == "patch":
                have = sw.get(b.name.lower())
                if have is not None and b.min_version and compare(have, b.min_version) < 0:
                    gaps.append({"kind": "patch", "name": b.name, "have": have, "need": b.min_version})
            elif b.name not in done.get(a.id, set()) and (a.hw.get("webservers") or b.name not in ("tls_protocols", "hsts", "hide_version", "security_headers")):
                gaps.append({"kind": "practice", "name": b.name, "have": "", "need": "aplicada"})
        if gaps:
            out.append({"asset": a, "gaps": gaps})
    return out


# --------------------------------------------------------------------------- exportação


def _patches(tenant: Tenant, scope: str) -> list[BaselineItem]:
    return [b for b in items(tenant, scope) if b.kind == "patch"]


def _practices(tenant: Tenant, scope: str) -> list[BaselineItem]:
    return [b for b in items(tenant, scope) if b.kind == "practice"]


def export_json(tenant: Tenant, scope: str) -> str:
    return json.dumps({"tenant": tenant.slug, "scope": scope, "generated_at": utcnow().isoformat(), "patches": [{"name": b.name, "installer": b.installer, "min_version": b.min_version, "cves": b.cve_list} for b in _patches(tenant, scope)],
                       "practices": [{"id": b.name, "params": b.params_data} for b in _practices(tenant, scope)]}, indent=2, ensure_ascii=False)


def export_shell(tenant: Tenant, scope: str) -> str:
    """Script para aplicar numa imagem (build) — apt/dnf/zypper; versões mínimas verificadas no fim."""
    L = ["#!/bin/sh", f"# Linha de base OMXPatch — {tenant.slug} / {scope} — {utcnow():%Y-%m-%d}", "set -eu", ""]
    pk = _patches(tenant, scope)
    apt = [b for b in pk if b.installer in ("apt", "ansible", "")]
    rpm = [b for b in pk if b.installer in ("dnf", "yum", "zypper")]
    if apt:
        L += ["if command -v apt-get >/dev/null; then", "  apt-get update -q", "  DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade " + " ".join(shlex.quote(b.name) for b in apt), "fi"]
    if rpm:
        L += ["if command -v dnf >/dev/null; then dnf upgrade -y " + " ".join(shlex.quote(b.name) for b in rpm) + "; fi"]
    L += ["", "# Verificação das versões mínimas (falha o build se a imagem ficar abaixo da linha de base)"]
    for b in pk:
        if b.min_version:
            L.append(f"dpkg --compare-versions \"$(dpkg-query -W -f='${{Version}}' {shlex.quote(b.name)} 2>/dev/null || echo 0)\" ge {shlex.quote(b.min_version)} || {{ echo 'ABAIXO DA LINHA DE BASE: {b.name} < {b.min_version}' >&2; exit 1; }}" if b.installer in ("apt", "ansible", "") else f"# {b.name} >= {b.min_version}")
    for b in _practices(tenant, scope):
        L.append(f"# Boa prática da linha de base: {b.name} {json.dumps(b.params_data)}  (aplique com o plano OMXPatch ou o equivalente no seu build)")
    return "\n".join(L) + "\n"


def export_ansible(tenant: Tenant, scope: str) -> str:
    L = [f"# Linha de base OMXPatch — {tenant.slug} / {scope} — {utcnow():%Y-%m-%d}", "- hosts: all", "  become: true", "  tasks:"]
    for b in _patches(tenant, scope):
        mod = {"apt": "ansible.builtin.apt", "dnf": "ansible.builtin.dnf", "yum": "ansible.builtin.yum", "zypper": "community.general.zypper", "choco": "chocolatey.chocolatey.win_chocolatey",
               "brew": "community.general.homebrew"}.get(b.installer, "ansible.builtin.package")
        L += [f"    - name: baseline {b.name} >= {b.min_version or 'última'}", f"      {mod}:", f"        name: {b.name}", "        state: latest"]
        if b.cve_list:
            L.append(f"      # corrige {', '.join(b.cve_list[:5])}")
    for b in _practices(tenant, scope):
        L += [f"    - name: baseline boa prática {b.name}", "      ansible.builtin.debug:", f"        msg: 'aplicar {b.name} {json.dumps(b.params_data)} (plano OMXPatch)'"]
    return "\n".join(L) + "\n"


def export_packer(tenant: Tenant, scope: str) -> str:
    """Provisioner Packer (HCL) que usa o script da linha de base."""
    return ('# Packer — provisioner da linha de base OMXPatch\nprovisioner "shell" {\n  script = "omxpatch-baseline.sh"   # gerado por: omxpatch baseline export --format shell\n}\n'
            if scope.startswith(("linux", "macos")) else 'provisioner "powershell" {\n  inline = [\n' + ",\n".join(f'    "choco upgrade {b.name} -y"' for b in _patches(tenant, scope) if b.installer == "choco") + '\n  ]\n}\n')


EXPORTERS = {"json": ("application/json", "json", export_json), "shell": ("text/x-shellscript", "sh", export_shell), "ansible": ("text/yaml", "yml", export_ansible), "packer": ("text/plain", "pkr.hcl", export_packer)}
