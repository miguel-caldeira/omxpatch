"""Caminhos de Windows e macOS do agente executados com saídas/registo simulados (a sério só correm no CI com esses sistemas)."""
import json
import sys
import types

import pytest

from omxpatch_agent.collectors import macos as cmac, windows as cwin
from omxpatch_agent.patchers import PatchError, macos as pmac
from omxpatch_agent.runner import Result


# ------------------------------------------------------------------ Windows: registo simulado


class FakeKey:
    def __init__(self, tree, path):
        self.tree, self.path = tree, path

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_winreg(tree: dict):
    """tree: {caminho: {"subs": {nome: {valor: ...}}, "values": {...}}}"""
    m = types.ModuleType("winreg")
    m.HKEY_LOCAL_MACHINE = "HKLM"

    def open_key(base, path):
        node = tree.get(path) if isinstance(base, str) else base.tree.get(base.path + "\\" + path)
        if node is None:
            raise OSError("não existe")
        return FakeKey(tree, path if isinstance(base, str) else base.path + "\\" + path)

    m.OpenKey = open_key
    m.QueryInfoKey = lambda k: (len(tree[k.path].get("subs", {})), 0, 0)
    m.EnumKey = lambda k, i: list(tree[k.path]["subs"])[i]
    m.CloseKey = lambda k: None

    def query(k, name):
        sub = k.path.rsplit("\\", 1)[-1]
        parent = k.path.rsplit("\\", 1)[0]
        values = tree[parent]["subs"][sub] if parent in tree and "subs" in tree[parent] and sub in tree[parent]["subs"] else tree[k.path].get("values", {})
        if name not in values:
            raise OSError("sem valor")
        return (values[name], 1)
    m.QueryValueEx = query
    return m


def test_windows_registry_software_inventory(monkeypatch):
    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    tree = {base: {"subs": {"a": {"DisplayName": "7-Zip", "DisplayVersion": "23.01", "Publisher": "Igor Pavlov"},
                            "b": {"DisplayName": "Hotfix", "DisplayVersion": "1", "SystemComponent": "1"},
                            "c": {"DisplayVersion": "9"}}},
            base + "\\a": {}, base + "\\b": {}, base + "\\c": {}}
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg(tree))
    items = cwin._reg_software()
    assert items == [{"name": "7-Zip", "version": "23.01", "vendor": "Igor Pavlov", "source": "registry"}]          # componentes de sistema e sem nome ficam de fora


def test_windows_reboot_pending_hotfixes_and_details(monkeypatch):
    reboot_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg({reboot_key: {}}))
    assert cwin._reboot_pending() is True
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg({}))
    assert cwin._reboot_pending() is False

    def ps(script, timeout=60, *a, **k):
        if "Get-HotFix" in script:
            return Result(0, "kb5031234\r\nKB5030000\nnot-a-kb\nKB5031234\n")
        return Result(0, "Microsoft Windows Server 2019 Standard\r\n")
    monkeypatch.setattr(cwin, "powershell", ps)
    monkeypatch.setattr(cwin, "run", lambda cmd, t=60, **k: Result(0, "  TCP    0.0.0.0:445    0.0.0.0:0    LISTENING\n  TCP    [::]:3389  [::]:0  LISTENING\n  TCP   10.0.0.5:5000  1.1.1.1:443  ESTABLISHED\n  UDP  0.0.0.0:53 *:*\n"))
    d = cwin.details()
    assert d["os_name"].startswith("Microsoft Windows Server 2019") and d["hotfixes"] == ["KB5030000", "KB5031234"]
    assert d["open_ports"] == [445, 3389] and d["reboot_pending"] is False


# ------------------------------------------------------------------ macOS


def test_macos_collector_details_and_software(monkeypatch):
    def run(cmd, t=60, **k):
        if cmd[0] == "sw_vers":
            return Result(0, "14.5\n" if "productVersion" in cmd[1] else "macOS\n")
        if cmd[0] == "system_profiler":
            return Result(0, json.dumps({"SPApplicationsDataType": [{"_name": "Safari", "version": "17.5", "obtained_from": "apple"}, {"version": "1"}]}))
        return Result(0, "openssl@3 3.3.1\npython@3.12 3.12.4 3.12.3\nwget\n")
    monkeypatch.setattr(cmac, "run", run)
    monkeypatch.setattr(cmac.shutil, "which", lambda n: "/opt/homebrew/bin/brew")
    d = cmac.details()
    assert d["os_name"] == "macOS" and d["os_version"] == "14.5"
    sw = cmac.software()
    assert {"name": "Safari", "version": "17.5", "vendor": "apple", "source": "app"} in sw
    assert {"name": "python@3.12", "version": "3.12.3", "source": "brew"} in sw and not any(s["name"] == "wget" for s in sw)
    monkeypatch.setattr(cmac, "run", lambda *a, **k: Result(0, "isto não é json"))
    monkeypatch.setattr(cmac.shutil, "which", lambda n: None)
    monkeypatch.setattr(cmac.os.path, "exists", lambda p: False)
    assert cmac.software() == []                                                                                 # saídas inválidas não rebentam


def test_macos_patcher_apply_softwareupdate_pkg_brew(monkeypatch):
    calls = []

    def run(cmd, t=60, **k):
        calls.append(cmd)
        if cmd[0] == "stat":
            return Result(0, "alice\n")
        return Result(0, "Done. restart required\n")
    monkeypatch.setattr(pmac, "run", run)
    monkeypatch.setattr(pmac, "_brew", lambda: "/opt/homebrew/bin/brew")
    r = pmac.apply({"installer": "softwareupdate", "package": "macOS Sonoma 14.5-23F79", "reboot_policy": "if_needed"}, lambda ext: "")
    assert r["status"] == "succeeded" and r["reboot_pending"] and ["shutdown", "-r", "+2"] in calls
    calls.clear()
    r = pmac.apply({"installer": "pkg", "reboot_policy": "none"}, lambda ext: "/tmp/x.pkg")
    assert r["status"] == "succeeded" and ["installer", "-pkg", "/tmp/x.pkg", "-target", "/"] in calls and ["shutdown", "-r", "+2"] not in calls
    calls.clear()
    pmac.apply({"installer": "brew", "package": "openssl@3", "reboot_policy": "none"}, lambda ext: "")
    assert ["sudo", "-u", "alice", "/opt/homebrew/bin/brew", "upgrade", "openssl@3"] in calls                     # Homebrew nunca como root
    monkeypatch.setattr(pmac, "_console_user", lambda: "root")
    with pytest.raises(PatchError):
        pmac.apply({"installer": "brew", "package": "wget"}, lambda ext: "")
    with pytest.raises(PatchError):
        pmac.apply({"installer": "softwareupdate", "package": "-R; rm"}, lambda ext: "")                    # nome inválido recusado


def test_macos_patcher_simulation_outcomes(monkeypatch):
    out = {"v": ""}
    monkeypatch.setattr(pmac, "run", lambda cmd, t=60, **k: Result(0, "alice\n" if cmd[0] == "stat" else out["v"]))
    monkeypatch.setattr(pmac, "_brew", lambda: "/opt/homebrew/bin/brew")
    out["v"] = "* Label: macOS Sonoma 14.5\n  restart"
    s = pmac.simulate({"installer": "softwareupdate", "package": "macOS Sonoma 14.5"}, lambda e: "")
    assert s["checks"][0]["status"] == "ok" and s["predicted"]["reboot"] is True
    out["v"] = "No new software available."
    s = pmac.simulate({"installer": "softwareupdate", "package": "macOS Sonoma 14.5"}, lambda e: "")
    assert s["predicted"]["noop"] is True
    out["v"] = "openssl@3 3.3.0 < 3.3.1"
    assert pmac.simulate({"installer": "brew", "package": "openssl@3"}, lambda e: "")["checks"][0]["status"] == "ok"
    out["v"] = ""
    assert pmac.simulate({"installer": "brew", "package": "openssl@3"}, lambda e: "")["predicted"]["noop"] is True
    out["v"] = "Status: signed by a developer certificate issued by Apple"
    assert pmac.simulate({"installer": "pkg"}, lambda e: "/tmp/a.pkg")["checks"][1]["status"] == "ok"
    out["v"] = "Status: no signature"
    assert pmac.simulate({"installer": "pkg"}, lambda e: "/tmp/a.pkg")["checks"][1]["status"] == "warn"
