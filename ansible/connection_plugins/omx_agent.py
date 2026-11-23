# -*- coding: utf-8 -*-
"""Ligação Ansible «omx_agent»: o agente OMXPatch do equipamento serve de PROCURAÇÃO (proxy) dos comandos do Ansible.

Em vez de SSH ou WinRM, cada comando que o Ansible quer executar no alvo é entregue ao agente como uma tarefa assinada pela consola
(o agente só faz pedidos de saída: não é preciso abrir nenhuma porta no equipamento). O agente executa o comando — num shell POSIX em
Linux/macOS, com o PowerShell em Windows — e devolve a saída e o código de saída. Os ficheiros (win_copy, copy, …) seguem por um
repositório temporário da consola, verificados por SHA-256.

Requisitos: a consola ativa AGENT_EXEC_ENABLED **e** o administrador do equipamento permite-o (omxpatch-agent config allow-exec on)."""
from __future__ import annotations

DOCUMENTATION = r'''
    name: omx_agent
    short_description: Executa os comandos do Ansible através do agente OMXPatch (procuração)
    description:
      - Os comandos são entregues ao agente OMXPatch do ativo (tarefas assinadas) e executados localmente (PowerShell em Windows, shell POSIX nos restantes).
    author: OMXPatch
    version_added: "1.0"
    options:
      omx_asset_id:
        description: Identificador do ativo no OMXPatch.
        type: int
        required: true
        vars:
          - name: omx_asset_id
          - name: ansible_omx_asset_id
      omx_timeout:
        description: Segundos de espera por cada comando.
        type: int
        default: 600
        vars:
          - name: omx_timeout
          - name: ansible_omx_timeout
'''

import base64
import hashlib
import json
import os
import shutil
import time
from pathlib import Path

from ansible.errors import AnsibleConnectionFailure
from ansible.plugins.connection import ConnectionBase
from ansible.utils.display import Display

display = Display()
_APP = None
FINAL = ("succeeded", "failed", "cancelled", "rolled_back", "skipped")


def _app():
    """A aplicação OMXPatch (mesma configuração do serviço: OMXPATCH_CONFIG) para ler/escrever as tarefas do agente."""
    global _APP
    if _APP is None:
        from omxpatch import create_app
        _APP = create_app(start_worker=False)
    return _APP


class Connection(ConnectionBase):
    """Transporte através do agente OMXPatch."""
    transport = "omx_agent"
    has_pipelining = True
    always_pipeline_modules = True          # os módulos seguem pelo stdin do comando (sem os escrever em disco no alvo)
    has_native_async = False

    @property
    def _windows(self) -> bool:
        return bool(getattr(self._shell, "_IS_WINDOWS", False)) or getattr(self._shell, "SHELL_FAMILY", "") == "powershell"

    @property
    def module_implementation_preferences(self):
        return (".ps1", ".exe", "") if self._windows else ("",)

    @property
    def allow_executable(self):
        return not self._windows

    def _connect(self):
        if not self._connected:
            self._connected = True
        return self

    # ------------------------------------------------------------------------------------------------------ tarefas
    def _submit(self, payload: dict) -> dict:
        from omxpatch.extensions import db
        from omxpatch.models import Agent, Asset, Task
        app = _app()
        asset_id = int(self.get_option("omx_asset_id"))
        timeout = int(self.get_option("omx_timeout") or app.config.get("AGENT_EXEC_TIMEOUT_SECONDS") or 600)
        with app.app_context():
            if not app.config.get("AGENT_EXEC_ENABLED"):
                raise AnsibleConnectionFailure("A execução remota através do agente está desativada na consola (AGENT_EXEC_ENABLED).")
            asset = db.session.get(Asset, asset_id)
            agent = Agent.query.filter_by(asset_id=asset_id, revoked=False).first() if asset else None
            if asset is None or agent is None:
                raise AnsibleConnectionFailure(f"O ativo {asset_id} não tem agente OMXPatch ativo.")
            if payload.get("op") == "run":
                payload.setdefault("timeout", timeout)
            task = Task(tenant_id=asset.tenant_id, type="exec", asset_id=asset_id, ring=asset.ring or 4, mode="agent", status="queued", payload=json.dumps(payload))
            db.session.add(task)
            db.session.commit()
            tid, t0 = task.id, time.time()
            while True:
                time.sleep(0.4 if time.time() - t0 < 6 else 1.0)
                db.session.commit()                     # termina a transação de leitura: vê as alterações do worker/servidor
                db.session.expire_all()
                t = db.session.get(Task, tid)
                if t.status in FINAL:
                    break
                if time.time() - t0 > timeout:
                    if t.status == "queued":
                        t.status, t.output = "cancelled", "Cancelada: o agente não respondeu a tempo."
                    db.session.commit()
                    raise AnsibleConnectionFailure(f"O agente do ativo {asset_id} não respondeu em {timeout} s (offline?).")
            result, output, status = t.result_data, t.output or "", t.status
            t.payload, t.result, t.output = json.dumps({"op": payload.get("op"), "limpo": True}), "{}", ""        # o comando e a saída podem ter segredos: não ficam na base de dados
            db.session.commit()
        if status != "succeeded":
            raise AnsibleConnectionFailure(output or "O agente recusou ou falhou o pedido.")
        return result

    # ------------------------------------------------------------------------------------------------------ API da ligação
    def exec_command(self, cmd, in_data=None, sudoable=True):
        super().exec_command(cmd, in_data=in_data, sudoable=sudoable)
        payload = {"op": "run", "cmd": cmd}
        if in_data:
            payload["stdin_b64"] = base64.b64encode(in_data if isinstance(in_data, bytes) else in_data.encode()).decode("ascii")
        res = self._submit(payload)
        return int(res.get("rc", 1)), base64.b64decode(res.get("stdout_b64", "")), base64.b64decode(res.get("stderr_b64", ""))

    def put_file(self, in_path, out_path):
        super().put_file(in_path, out_path)
        data_dir = Path(_app().config["DATA_DIR"]) / "ansible-blobs"
        data_dir.mkdir(parents=True, exist_ok=True)
        h = hashlib.sha256()
        with open(in_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        sha = h.hexdigest()
        blob = data_dir / sha
        if not blob.exists():
            shutil.copyfile(in_path, blob)
            os.chmod(blob, 0o600)
        try:
            res = self._submit({"op": "put", "sha256": sha, "dest": str(out_path), "size": os.path.getsize(in_path)})
        finally:
            try:
                blob.unlink()
            except OSError:
                pass
        if int(res.get("rc", 1)) != 0:
            raise AnsibleConnectionFailure(f"Falha ao copiar para {out_path}: {res.get('output', '')}")

    def fetch_file(self, in_path, out_path):
        super().fetch_file(in_path, out_path)
        res = self._submit({"op": "get", "src": str(in_path)})
        if int(res.get("rc", 1)) != 0 or "content_b64" not in res:
            raise AnsibleConnectionFailure(f"Falha ao ler {in_path}: {res.get('output', '')}")
        Path(out_path).write_bytes(base64.b64decode(res["content_b64"]))

    def close(self):
        self._connected = False
