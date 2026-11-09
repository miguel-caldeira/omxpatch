"""OMXPatch - centro de comando de gestão de patches e remediação contínua (Ativo → Exposição → Risco → Mitigação
→ Patch → Validação → Monitorização contínua)."""
__version__ = "1.26.20261109"

import warnings  # noqa: E402

warnings.filterwarnings("ignore", message=".*urllib3 v2 only supports OpenSSL.*")

from .app import create_app  # noqa: E402,F401
