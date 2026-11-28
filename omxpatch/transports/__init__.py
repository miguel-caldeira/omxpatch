"""Transportes de acesso SEM agente: SSH (Linux/macOS) e WMI/DCOM + SMB (Windows). Usados pela ligação «omx_wmi» do Ansible e pelo teste de ligação da consola."""
from .base import AuthError, ConnectError, Result, Transport, TransportError

__all__ = ["AuthError", "ConnectError", "Result", "Transport", "TransportError", "make_transport"]


def make_transport(kind: str, **kw) -> Transport:
    if kind == "ssh":
        from .ssh import SSHTransport
        return SSHTransport(**kw)
    if kind == "wmi":
        from .wmi import WMITransport
        return WMITransport(**kw)
    raise ValueError(f"transporte desconhecido: {kind}")
