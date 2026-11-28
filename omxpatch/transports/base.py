"""Interface comum dos transportes sem agente."""
from __future__ import annotations

from dataclasses import dataclass


class TransportError(RuntimeError):
    """Falha de transporte (rede, autenticação, protocolo)."""


class ConnectError(TransportError):
    """Não foi possível ligar (rede, porta, certificado/chave do equipamento)."""


class AuthError(TransportError):
    """Ligou, mas o utilizador/palavra-passe/chave foram recusados ou sem permissões."""


@dataclass
class Result:
    rc: int
    stdout: bytes = b""
    stderr: bytes = b""

    @property
    def out(self) -> str:
        return self.stdout.decode("utf-8", "replace")

    @property
    def err(self) -> str:
        return self.stderr.decode("utf-8", "replace")


class Transport:
    """Executa comandos e transfere ficheiros num equipamento sem nenhum agente instalado."""
    kind = ""
    shell = "sh"

    def run(self, cmd: str, stdin: bytes | None = None, timeout: int = 300) -> Result:  # pragma: no cover - interface
        raise NotImplementedError

    def put(self, local_path: str, remote_path: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def get(self, remote_path: str) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
