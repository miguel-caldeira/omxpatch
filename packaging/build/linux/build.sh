#!/usr/bin/env bash
# Compila NO LINUX (Ubuntu/Debian recomendado, 24.04 para incluir o Python/pip offline) os instaladores Linux:
#   omxpatch-ubuntu-<v>.tar.gz           centro de comando (instalador com wheelhouse offline)
#   omxpatch-server_<v>_all.deb          centro de comando em .deb (instala/atualiza ao instalar o .deb)
#   omxpatch-agent_<v>_all.deb           agente em .deb (Python >= 3.8; inscrição automática com /etc/omxpatch-agent/enroll.env)
#   omxpatch-agent-<v>-1.noarch.rpm      agente em .rpm (se «rpmbuild» existir)
#   omxpatch-agent-<v>.zip, omxpatch-validation-kit-<v>.zip, SHA256SUMS
# Requer: bash, python3 + pip, tar, dpkg-deb (pacote dpkg); opcional: rpmbuild (pacote rpm).   Uso: packaging/build/linux/build.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"; cd "$ROOT"
PY="${PYTHON:-python3}"
export DIST="${DIST:-$ROOT/dist}"; mkdir -p "$DIST"
VER="$($PY -c "import re;print(re.search(r'__version__ = \"([^\"]+)\"', open('omxpatch/__init__.py').read()).group(1))")"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
echo "OMXPatch $VER — compilação nativa Linux ($(uname -sm))"

bash packaging/build_installers.sh ubuntu agent kit

command -v dpkg-deb >/dev/null || { echo "ERRO: dpkg-deb não encontrado (apt install dpkg-dev)" >&2; exit 1; }
MAINT="OMXPatch <omxpatch@oramix.local>"

# ---------------------------------------------------------------------------------------------------------- .deb do servidor
echo "==> .deb do servidor"
tar -xzf "$DIST/omxpatch-ubuntu-$VER.tar.gz" -C "$WORK"
S="$WORK/deb-server"; mkdir -p "$S/DEBIAN" "$S/opt"
mv "$WORK/omxpatch-ubuntu-$VER" "$S/opt/omxpatch-installer"
cat > "$S/DEBIAN/control" <<CTL
Package: omxpatch-server
Version: $VER
Section: admin
Priority: optional
Architecture: all
Depends: bash, coreutils
Maintainer: $MAINT
Description: OMXPatch - centro de comando (instalador)
 Instala (ou atualiza) o centro de comando OMXPatch: consola (4434), servidor de agentes (4444), serviços systemd e Ansible.
 Para só copiar os ficheiros sem instalar: OMXPATCH_SKIP_INSTALL=1 apt install ./omxpatch-server_${VER}_all.deb
CTL
cat > "$S/DEBIAN/postinst" <<'SH'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
  I=/opt/omxpatch-installer
  if [ "${OMXPATCH_SKIP_INSTALL:-0}" = 1 ]; then
    echo "omxpatch-server: ficheiros em $I. Instale com: sudo $I/install.sh   (atualizar: sudo $I/update.sh)"
  elif [ -x /opt/omxpatch/venv/bin/pip ]; then
    "$I/update.sh" || echo "omxpatch-server: a atualização falhou; veja /var/log/omxpatch-install.log" >&2
  else
    "$I/install.sh" || echo "omxpatch-server: a instalação falhou; veja /var/log/omxpatch-install.log (repita: sudo $I/install.sh)" >&2
  fi
fi
exit 0
SH
cat > "$S/DEBIAN/postrm" <<'SH'
#!/bin/sh
# remover este .deb só apaga o instalador; a aplicação (/opt/omxpatch) remove-se com: sudo /opt/omxpatch/uninstall.sh [--purge]
exit 0
SH
chmod 0755 "$S/DEBIAN/postinst" "$S/DEBIAN/postrm"; find "$S/opt" -name '*.sh' -exec chmod 0755 {} +
dpkg-deb --root-owner-group -Zxz --build "$S" "$DIST/omxpatch-server_${VER}_all.deb" >/dev/null

# ---------------------------------------------------------------------------------------------------------- .deb do agente
echo "==> .deb do agente"
mkdir -p "$WORK/agent"
$PY -c "import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$DIST/omxpatch-agent-$VER.zip" "$WORK/agent"
A="$WORK/deb-agent"; mkdir -p "$A/DEBIAN" "$A/opt/omxpatch-agent" "$A/usr/bin" "$A/etc/omxpatch-agent"
cp -r "$WORK/agent/omxpatch-agent-$VER/omxpatch_agent" "$A/opt/omxpatch-agent/"
cat > "$A/usr/bin/omxpatch-agent" <<'SH'
#!/bin/sh
PYTHONPATH=/opt/omxpatch-agent${PYTHONPATH:+:$PYTHONPATH} exec python3 -m omxpatch_agent "$@"
SH
chmod 0755 "$A/usr/bin/omxpatch-agent"
cat > "$A/etc/omxpatch-agent/enroll.env.example" <<'ENV'
# Inscrição automática: copie para enroll.env (ANTES de instalar o pacote, ou depois e execute «dpkg-reconfigure omxpatch-agent»).
# O ficheiro é apagado depois de usado (contém o token de registo).
OMXPATCH_SERVER=https://omxpatchcli.oramix.local:4444
OMXPATCH_TOKEN=omxe_...
OMXPATCH_PIN=
ENV
cat > "$A/DEBIAN/control" <<CTL
Package: omxpatch-agent
Version: $VER
Section: admin
Priority: optional
Architecture: all
Depends: python3 (>= 3.8)
Maintainer: $MAINT
Description: OMXPatch - agente
 Agente de gestão de patches (só biblioteca padrão do Python). Inscrever: sudo omxpatch-agent enroll --server URL --token TOKEN --pin-sha256 SHA256 --install-service
CTL
cat > "$A/DEBIAN/postinst" <<'SH'
#!/bin/sh
set -e
if [ "$1" = configure ] || [ "$1" = reconfigure ]; then
  F=/etc/omxpatch-agent/enroll.env
  if [ -f "$F" ]; then
    . "$F"
    if [ -n "${OMXPATCH_SERVER:-}" ] && [ -n "${OMXPATCH_TOKEN:-}" ]; then
      if omxpatch-agent enroll --server "$OMXPATCH_SERVER" --token "$OMXPATCH_TOKEN" ${OMXPATCH_PIN:+--pin-sha256 "$OMXPATCH_PIN"} --install-service; then rm -f "$F"
      else echo "omxpatch-agent: a inscrição falhou (o ficheiro $F foi mantido)." >&2; fi
    fi
  else
    echo "omxpatch-agent: instalado. Inscrever: sudo omxpatch-agent enroll --server https://omxpatchcli.oramix.local:4444 --token omxe_… --pin-sha256 <SHA-256> --install-service"
  fi
fi
exit 0
SH
cat > "$A/DEBIAN/prerm" <<'SH'
#!/bin/sh
if [ "$1" = remove ] || [ "$1" = purge ]; then
  systemctl disable --now omxpatch-agent >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/omxpatch-agent.service; systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
SH
cat > "$A/DEBIAN/postrm" <<'SH'
#!/bin/sh
if [ "$1" = remove ] || [ "$1" = purge ]; then rm -rf /opt/omxpatch-agent; fi
exit 0
SH
chmod 0755 "$A/DEBIAN/postinst" "$A/DEBIAN/prerm" "$A/DEBIAN/postrm"; chmod 0600 "$A/etc/omxpatch-agent/enroll.env.example"
dpkg-deb --root-owner-group -Zxz --build "$A" "$DIST/omxpatch-agent_${VER}_all.deb" >/dev/null

# ---------------------------------------------------------------------------------------------------------- .rpm do agente
if command -v rpmbuild >/dev/null; then
  echo "==> .rpm do agente"
  R="$WORK/rpm"; mkdir -p "$R"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
  cat > "$R/SPECS/omxpatch-agent.spec" <<SPEC
Name: omxpatch-agent
Version: $VER
Release: 1
Summary: OMXPatch - agente
License: Proprietary
BuildArch: noarch
Requires: python3 >= 3.8
AutoReqProv: no
%description
Agente de gestao de patches OMXPatch (so biblioteca padrao do Python).
%install
mkdir -p %{buildroot}/opt/omxpatch-agent %{buildroot}/usr/bin %{buildroot}/etc/omxpatch-agent
cp -r $WORK/agent/omxpatch-agent-$VER/omxpatch_agent %{buildroot}/opt/omxpatch-agent/
install -m 0755 $A/usr/bin/omxpatch-agent %{buildroot}/usr/bin/omxpatch-agent
install -m 0600 $A/etc/omxpatch-agent/enroll.env.example %{buildroot}/etc/omxpatch-agent/enroll.env.example
%post
F=/etc/omxpatch-agent/enroll.env
if [ -f "\$F" ]; then . "\$F"; if [ -n "\${OMXPATCH_SERVER:-}" ] && [ -n "\${OMXPATCH_TOKEN:-}" ]; then
  omxpatch-agent enroll --server "\$OMXPATCH_SERVER" --token "\$OMXPATCH_TOKEN" \${OMXPATCH_PIN:+--pin-sha256 "\$OMXPATCH_PIN"} --install-service && rm -f "\$F" || true; fi; fi
%preun
if [ "\$1" = 0 ]; then systemctl disable --now omxpatch-agent >/dev/null 2>&1 || true; rm -f /etc/systemd/system/omxpatch-agent.service; rm -rf /opt/omxpatch-agent/omxpatch_agent/__pycache__; fi
%files
/opt/omxpatch-agent
/usr/bin/omxpatch-agent
%config(noreplace) /etc/omxpatch-agent/enroll.env.example
SPEC
  rpmbuild -bb --define "_topdir $R" "$R/SPECS/omxpatch-agent.spec" >/dev/null
  cp "$R"/RPMS/noarch/*.rpm "$DIST/"
else
  echo "AVISO: rpmbuild não encontrado: .rpm do agente não gerado (apt install rpm / dnf install rpm-build)"
fi

(cd "$DIST" && sha256sum $(ls -p | grep -v '/$' | grep -v SHA256SUMS) > SHA256SUMS && cat SHA256SUMS)
