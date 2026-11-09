#!/usr/bin/env bash
# OMXPatch — atualização de uma instalação existente (Ubuntu/Debian), sem tocar na configuração nem nos dados.
# Uso (como root, na pasta extraída do pacote novo):  sudo ./update.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="${OMXPATCH_APP:-/opt/omxpatch}"; ETC="${OMXPATCH_ETC:-/etc/omxpatch}"; PORT="${OMXPATCH_PORT:-4434}"
[ "$(id -u)" = 0 ] || { echo "Execute como root: sudo $0" >&2; exit 1; }
[ -x "$APP/venv/bin/pip" ] || { echo "Instalação não encontrada em $APP — use ./install.sh" >&2; exit 1; }
ls "$HERE"/wheels/omxpatch-*.whl >/dev/null 2>&1 || { echo "Pacote incompleto: faltam os wheels" >&2; exit 1; }
NEW="$(cat "$HERE/VERSION" 2>/dev/null || true)"
PIP="$APP/venv/bin/pip"
OLD="$("$PIP" show omxpatch 2>/dev/null | sed -n 's/^Version: //p')"
echo "Versão instalada: ${OLD:-?}  ->  pacote: ${NEW:-?}"
[ -f "$ETC/omxpatch.toml" ] && cp -p "$ETC/omxpatch.toml" "$ETC/omxpatch.toml.bak-$(date +%Y%m%d%H%M%S)" || true
"$PIP" install -q --upgrade --no-index --find-links "$HERE/wheels" omxpatch || "$PIP" install -q --upgrade --find-links "$HERE/wheels" omxpatch
CUR="$("$PIP" show omxpatch | sed -n 's/^Version: //p')"
if [ -n "$NEW" ] && [ "$CUR" != "$NEW" ]; then
  echo "A forçar a reinstalação da aplicação ($CUR != $NEW)…"
  "$PIP" install -q --force-reinstall --no-deps --no-index --find-links "$HERE/wheels" "omxpatch==$NEW"
  CUR="$("$PIP" show omxpatch | sed -n 's/^Version: //p')"
fi
[ -z "$NEW" ] || [ "$CUR" = "$NEW" ] || { echo "ERRO: a versão instalada continua $CUR (esperado $NEW)." >&2; exit 1; }
if [ -d /run/systemd/system ]; then
  systemctl restart omxpatch omxpatch-worker
  for i in $(seq 1 30); do curl -ksf "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
  curl -ksf "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && echo "Consola a responder em :$PORT" || echo "AVISO: a consola não responde: journalctl -u omxpatch" >&2
else
  echo "systemd indisponível: reinicie o serviço manualmente."
fi
echo "OMXPatch atualizado: $OLD -> $CUR"
