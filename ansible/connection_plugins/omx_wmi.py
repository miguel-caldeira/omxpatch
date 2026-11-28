# -*- coding: utf-8 -*-
"""Ligação Ansible «omx_wmi»: acesso a Windows SEM agente, SEM WinRM e SEM SSH — WMI/DCOM para executar e SMB (partilha administrativa) para
as entradas, saídas e ficheiros. Os módulos do Ansible para Windows (win_updates, win_shell, win_copy, …) funcionam sobre esta ligação.

Requisitos no Windows: conta de administrador, TCP 135 + RPC dinâmico (49152–65535) e 445 abertos (regras «Windows Management Instrumentation»
e «Partilha de Ficheiros e Impressoras»); para contas locais, LocalAccountTokenFilterPolicy=1. No controlador: «impacket» (omxpatch ansible-doctor --fix)."""
from __future__ import annotations

DOCUMENTATION = r'''
    name: omx_wmi
    short_description: Executa os módulos do Ansible em Windows por WMI/DCOM + SMB (sem agente, sem WinRM)
    description:
      - Cada comando corre com Win32_Process.Create; stdin, stdout, stderr e ficheiros seguem pela partilha administrativa C$.
    author: OMXPatch
    version_added: "1.0"
    options:
      remote_addr:
        description: Nome ou IP do Windows.
        default: inventory_hostname
        vars:
          - name: inventory_hostname
          - name: ansible_host
      remote_user:
        description: Utilizador (administrador). «DOMINIO\\utilizador» ou «utilizador@dominio» para contas de domínio.
        vars:
          - name: ansible_user
          - name: ansible_wmi_user
      password:
        description: Palavra-passe.
        vars:
          - name: ansible_password
          - name: ansible_wmi_password
      omx_domain:
        description: Domínio (vazio para conta local).
        default: ''
        vars:
          - name: omx_domain
          - name: ansible_wmi_domain
      omx_wmi_timeout:
        description: Segundos de espera por cada comando.
        type: int
        default: 600
        vars:
          - name: omx_wmi_timeout
          - name: ansible_omx_wmi_timeout
'''

from ansible.errors import AnsibleConnectionFailure
from ansible.plugins.connection import ConnectionBase
from ansible.utils.display import Display

display = Display()


class Connection(ConnectionBase):
    """Transporte WMI/DCOM + SMB."""
    transport = "omx_wmi"
    has_pipelining = True
    always_pipeline_modules = True          # o módulo segue como stdin do comando (num ficheiro na partilha), sem o escrever primeiro no destino
    has_native_async = False

    @property
    def _windows(self) -> bool:
        return getattr(self._shell, "SHELL_FAMILY", "powershell") == "powershell" or bool(getattr(self._shell, "_IS_WINDOWS", False))

    @property
    def module_implementation_preferences(self):
        return (".ps1", ".exe", "") if self._windows else ("",)

    @property
    def allow_executable(self):
        return not self._windows

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._t = None

    def _transport(self):
        if self._t is None:
            from omxpatch.transports.base import TransportError
            from omxpatch.transports.wmi import WMITransport
            host, user, pw = self.get_option("remote_addr"), self.get_option("remote_user"), self.get_option("password")
            if not user or not pw:
                raise AnsibleConnectionFailure("WMI: falta o utilizador/palavra-passe (credencial do ativo).")
            try:
                self._t = WMITransport(host, user, pw, domain=self.get_option("omx_domain") or "").connect()
            except TransportError as exc:
                raise AnsibleConnectionFailure(str(exc)) from exc
        return self._t

    def _connect(self):
        self._connected = True
        return self

    def exec_command(self, cmd, in_data=None, sudoable=True):
        super().exec_command(cmd, in_data=in_data, sudoable=sudoable)
        from omxpatch.transports.base import TransportError
        try:
            r = self._transport().run(cmd, in_data if isinstance(in_data, (bytes, type(None))) else in_data.encode(), timeout=int(self.get_option("omx_wmi_timeout") or 600))
        except TransportError as exc:
            raise AnsibleConnectionFailure(str(exc)) from exc
        return r.rc, r.stdout, r.stderr

    def put_file(self, in_path, out_path):
        super().put_file(in_path, out_path)
        from omxpatch.transports.base import TransportError
        try:
            self._transport().put(in_path, out_path)
        except TransportError as exc:
            raise AnsibleConnectionFailure(str(exc)) from exc

    def fetch_file(self, in_path, out_path):
        super().fetch_file(in_path, out_path)
        from omxpatch.transports.base import TransportError
        try:
            data = self._transport().get(in_path)
        except TransportError as exc:
            raise AnsibleConnectionFailure(str(exc)) from exc
        with open(out_path, "wb") as fh:
            fh.write(data)

    def close(self):
        if self._t is not None:
            self._t.close()
            self._t = None
        self._connected = False
