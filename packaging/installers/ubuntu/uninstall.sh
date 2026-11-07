#!/usr/bin/env bash
# Remove o OMXPatch (serviços e aplicação). Mantém /var/lib/omxpatch e /etc/omxpatch, salvo --purge.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Execute como root" >&2; exit 1; }
systemctl disable --now omxpatch omxpatch-worker 2>/dev/null || true
rm -f /etc/systemd/system/omxpatch.service /etc/systemd/system/omxpatch-worker.service
systemctl daemon-reload 2>/dev/null || true
rm -rf /opt/omxpatch
if [ "${1:-}" = "--purge" ]; then rm -rf /var/lib/omxpatch /etc/omxpatch; userdel omxpatch 2>/dev/null || true; echo "Removido, incluindo dados e configuração."
else echo "Removido. Dados em /var/lib/omxpatch e configuração em /etc/omxpatch mantidos (use --purge para apagar)."; fi
