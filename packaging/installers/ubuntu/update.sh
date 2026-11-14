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
# Ansible (modo sem agente): instala-o se faltar e ativa-o na configuração (por omissão desde a 1.32; use --no-ansible para saltar)
if [ "${1:-}" != "--no-ansible" ] && [ ! -x "$APP/venv/bin/ansible-playbook" ]; then
  echo "A instalar o Ansible (modo sem agente)…"
  if ls "$HERE"/wheels-ansible/ansible_core-*.whl >/dev/null 2>&1 && "$PIP" install -q --upgrade --no-index --find-links "$HERE/wheels-ansible" -r "$HERE/requirements-ansible.txt"; then :; else
    "$PIP" install -q --upgrade -r "$HERE/requirements-ansible.txt" || echo "AVISO: Ansible não instalado (sem acesso ao PyPI?)." >&2
  fi
  [ -x "$APP/venv/bin/ansible-galaxy" ] && "$APP/venv/bin/ansible-galaxy" collection install -r "$HERE/requirements-collections.yml" \
      -p "$APP/venv/share/omxpatch/ansible/collections" || echo "AVISO: coleções Ansible não instaladas (sem acesso ao Galaxy?): sudo $APP/venv/bin/ansible-galaxy collection install -r $HERE/requirements-collections.yml -p $APP/venv/share/omxpatch/ansible/collections" >&2
fi
if [ -x "$APP/venv/bin/ansible-playbook" ] && [ -f "$ETC/omxpatch.toml" ]; then
  python3 - "$ETC/omxpatch.toml" "$APP/venv/bin/ansible-playbook" <<'PY'
import re, sys
p, exe = sys.argv[1], sys.argv[2]
t = open(p, encoding="utf-8").read()
m = re.search(r"(?ms)^\[ansible\]\s*\n(.*?)(?=^\[|\Z)", t)
body = m.group(1) if m else ""
if "enabled" in body:
    body2 = re.sub(r"(?m)^enabled\s*=.*$", "enabled = true", body)
else:
    body2 = "enabled = true\n" + body
if re.search(r"(?m)^playbook\s*=", body2) is None:
    body2 = body2.rstrip("\n") + f'\nplaybook = "{exe}"\n'
if m:
    t = t[:m.start(1)] + body2 + t[m.end(1):]
else:
    t = t.rstrip("\n") + "\n\n[ansible]\n" + body2
open(p, "w", encoding="utf-8").write(t)
print("Ansible ativado em", p)
PY
fi
if [ -d /run/systemd/system ]; then
  systemctl restart omxpatch omxpatch-worker
  for i in $(seq 1 30); do curl -ksf "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
  curl -ksf "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && echo "Consola a responder em :$PORT — versão em execução: $(curl -ksf "https://127.0.0.1:$PORT/healthz" | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p')" || echo "AVISO: a consola não responde: journalctl -u omxpatch" >&2
else
  echo "systemd indisponível: reinicie o serviço manualmente."
fi
echo "OMXPatch atualizado: $OLD -> $CUR"
