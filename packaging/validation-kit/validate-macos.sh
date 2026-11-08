#!/bin/sh
# OMXPatch — validação do agente em macOS (kit de teste).
#   ./validate-macos.sh                         # só leitura (seguro)
#   sudo ./validate-macos.sh --lab              # + alterações reversíveis (SÓ em Mac de laboratório)
#   ./validate-macos.sh --server https://10.0.0.5:4444 --pin <SHA-256>   # testa também a consola por IP + impressão digital
# Gera report-<data>.md e report-<data>.json nesta pasta (nome do equipamento e IP ocultados). Envie-os.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
LEVEL=read; EXTRA=""
while [ $# -gt 0 ]; do
  case "$1" in
    --lab) LEVEL=lab; EXTRA="$EXTRA --yes-lab"; shift ;;
    --server) EXTRA="$EXTRA --server $2"; shift 2 ;;
    --pin) EXTRA="$EXTRA --pin $2"; shift 2 ;;
    --with-isolation) EXTRA="$EXTRA --with-isolation"; shift ;;
    --no-redact) EXTRA="$EXTRA --no-redact"; shift ;;
    *) echo "Opção desconhecida: $1" >&2; exit 2 ;;
  esac
done
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3; do command -v "$c" >/dev/null 2>&1 && { PY="$(command -v "$c")"; break; }; done
[ -n "$PY" ] || { echo "Python 3.8+ não encontrado. Instale as Xcode Command Line Tools (xcode-select --install) ou o Python de python.org." >&2; exit 1; }
[ "$LEVEL" = lab ] && [ "$(id -u)" -ne 0 ] && echo "AVISO: sem root: as verificações de alteração serão saltadas (use sudo)."
STAMP="$(date +%Y%m%d-%H%M%S)"
echo "Python: $PY · Nível: $LEVEL · root: $([ "$(id -u)" -eq 0 ] && echo sim || echo não)"
cd "$HERE"
PYTHONPATH="$HERE" "$PY" -m omxpatch_agent validate --level "$LEVEL" --report "report-$STAMP.md" --json "report-$STAMP.json" $EXTRA
RC=$?
echo "Relatórios: report-$STAMP.md / report-$STAMP.json (código de saída $RC)"
exit $RC
