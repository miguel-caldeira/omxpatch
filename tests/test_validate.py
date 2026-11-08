"""Validação do agente num sistema real: estrutura do relatório, níveis, redação de dados e isolamento de falhas."""
import json
import subprocess
import sys

import pytest

from omxpatch_agent import validate as v


def test_read_level_report_structure_and_no_changes(tmp_path):
    r = v.validate("read", redact=False)
    ids = [c["id"] for c in r["checks"]]
    assert ids[:5] == ["selftest", "inventory", "sources", "updates", "context"] and "firewall_cycle" not in ids and "hardening_cycle" not in ids          # leitura: sem ciclos
    assert r["level"] == "read" and r["summary"]["counts"]["fail"] == 0 and r["summary"]["ok"] and set(c["status"] for c in r["checks"]) <= set(v.STATUS)
    inv = next(c for c in r["checks"] if c["id"] == "inventory")
    assert inv["data"]["software"] > 0 and inv["ms"] >= 0
    md = v.to_markdown(r)
    assert md.startswith("# Validação OMXPatch Agent") and "| ✅ |" in md and "Dados técnicos" in md


def test_a_failing_check_is_isolated_and_reported(monkeypatch):
    def boom():
        raise RuntimeError("origem partida")
    monkeypatch.setattr(v, "_updates", lambda rep: rep.run("updates", "Descoberta", boom))
    r = v.validate("read", redact=False)
    up = next(c for c in r["checks"] if c["id"] == "updates")
    assert up["status"] == "fail" and "origem partida" in up["detail"] and not r["summary"]["ok"]
    assert next(c for c in r["checks"] if c["id"] == "context")["status"] in ("pass", "warn")                      # as outras continuam


def test_redaction_hides_hostname_and_ips():
    txt = v.redact_text("srv-finance-01 em 192.168.10.45 e 10.0.0.5; SRV-FINANCE-01", "srv-finance-01")
    assert "srv-finance-01" not in txt.lower() and "192.168.x.x" in txt and "10.0.x.x" in txt and "host-" in txt
    r = v.validate("read", redact=True)
    host = v.host_info()["hostname"]
    assert host.lower() not in json.dumps(r).lower() and r["host"]["hostname"].startswith("host-")


def test_lab_cycles_skip_without_admin_and_gate_by_level(monkeypatch):
    monkeypatch.setattr(v, "is_admin", lambda: False)
    r = v.validate("lab", redact=False)
    st = {c["id"]: c["status"] for c in r["checks"]}
    assert st["firewall_cycle"] == "skip" and st["hardening_cycle"] == "skip" and "isolation_cycle" not in st            # sem --with-isolation nem servidor
    r2 = v.validate("lab", with_isolation=True, redact=False)
    assert "isolation_cycle" not in [c["id"] for c in r2["checks"]]                                                   # isolamento exige também --server


def test_hardening_cycle_exercises_apply_and_rollback(monkeypatch):
    monkeypatch.setattr(v, "is_admin", lambda: True)
    from omxpatch_agent.practices import oshardening
    state = {"applied": False}
    monkeypatch.setattr(oshardening, "simulate", lambda p, params: {"checks": [], "actions": [{}], "predicted": {"noop": state["applied"]}})
    monkeypatch.setattr(oshardening, "apply", lambda p, params, item: (state.update(applied=True) or {"status": "succeeded", "actions": [{}], "output": "ok"}))
    monkeypatch.setattr(oshardening, "rollback", lambda p, item: (state.update(applied=False) or {"status": "succeeded"}))
    rep = v.Report("lab")
    v._hardening_cycle(rep)
    c = rep.checks[0]
    assert c["status"] == "pass" and "revertido=succeeded" in c["detail"] and not state["applied"]
    monkeypatch.setattr(oshardening, "apply", lambda p, params, item: {"status": "failed", "actions": [], "output": "sshd -t falhou", "rolled_back": True})
    rep = v.Report("lab")
    v._hardening_cycle(rep)
    assert rep.checks[0]["status"] == "fail" and "sshd -t falhou" in rep.checks[0]["detail"]


def test_cli_requires_explicit_confirmation_for_lab_and_isolation():
    base = [sys.executable, "-m", "omxpatch_agent", "validate"]
    r = subprocess.run(base + ["--level", "lab"], capture_output=True, text=True)
    assert r.returncode == 2 and "--yes-lab" in r.stderr
    r = subprocess.run(base + ["--with-isolation"], capture_output=True, text=True)
    assert r.returncode == 2 and "--server" in r.stderr
    r = subprocess.run(base + ["--level", "read", "--quiet"], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "Resultado" in r.stdout


def test_kit_files_and_ci_job_exist():
    import pathlib
    kit = pathlib.Path("packaging/validation-kit")
    assert (kit / "validate-windows.ps1").read_bytes().startswith(b"\xef\xbb\xbf")                                  # BOM para o PowerShell 5.1
    sh = (kit / "validate-macos.sh").read_text()
    assert "--yes-lab" in sh and "Xcode Command Line Tools" in sh and "set -eu" in sh
    assert subprocess.run(["sh", "-n", str(kit / "validate-macos.sh")]).returncode == 0
    ci = pathlib.Path(".github/workflows/ci.yml").read_text()
    assert "real-os-validation" in ci and "windows-latest" in ci and "macos-latest" in ci and "validate --level lab --yes-lab" in ci
    assert "pip install --require-hashes -r requirements.lock\n      - run: pip install pytest" in ci                # o erro encontrado no CI real: pytest fora do modo de hashes
    assert "CHECKLIST-LAB.md" in (kit / "LEIA-ME.txt").read_text()
