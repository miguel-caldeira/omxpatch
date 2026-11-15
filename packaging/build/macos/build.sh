#!/usr/bin/env bash
# Compila NO macOS o instalador do agente:  omxpatch-agent-<v>.pkg  (e SHA256SUMS)
#   Instala em /Library/OMXPatchAgent + /usr/local/bin/omxpatch-agent. Inscrição automática (MDM): ver postinstall.
# Requer: macOS com as ferramentas de linha de comandos (pkgbuild, pkgutil) e python3.   Uso: packaging/build/macos/build.sh
# Assinatura/notarização (opcional): MACOS_INSTALLER_SIGN="Developer ID Installer: Empresa (TEAMID)"  e, para notarizar,
#   MACOS_NOTARY_PROFILE=<perfil criado com: xcrun notarytool store-credentials>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"; cd "$ROOT"
PY="${PYTHON:-python3}"
DIST="${DIST:-$ROOT/dist}"; mkdir -p "$DIST"
VER="$($PY -c "import re;print(re.search(r'__version__ = \"([^\"]+)\"', open('omxpatch/__init__.py').read()).group(1))")"
[ "$(uname -s)" = Darwin ] || { echo "AVISO: este construtor foi feito para o macOS (pkgbuild); a executar em $(uname -s)" >&2; }
command -v pkgbuild >/dev/null || { echo "ERRO: pkgbuild não encontrado (instale as ferramentas de linha de comandos: xcode-select --install)" >&2; exit 1; }
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
echo "OMXPatch $VER — compilação nativa macOS ($(uname -sm))"

ROOTDIR="$WORK/root"; mkdir -p "$ROOTDIR/Library/OMXPatchAgent" "$ROOTDIR/usr/local/bin" "$ROOTDIR/Library/OMXPatchAgent/docs"
cp -R omxpatch_agent "$ROOTDIR/Library/OMXPatchAgent/"; find "$ROOTDIR" -name __pycache__ -prune -exec rm -rf {} +
echo "$VER" > "$ROOTDIR/Library/OMXPatchAgent/VERSION"
cat > "$ROOTDIR/Library/OMXPatchAgent/enroll.env.example" <<'ENV'
# Inscrição automática (MDM/pré-instalação): crie «/Library/Application Support/OMXPatchAgent/enroll.env» com estas linhas
# ANTES de instalar o .pkg. O ficheiro é apagado depois de usado (contém o token de registo).
OMXPATCH_SERVER=https://omxpatchcli.oramix.local:4444
OMXPATCH_TOKEN=omxe_...
OMXPATCH_PIN=
ENV
cat > "$ROOTDIR/usr/local/bin/omxpatch-agent" <<'SH'
#!/bin/sh
# O python3 de /usr/bin é um atalho das ferramentas de linha de comandos; procura um Python 3 que funcione
for p in /usr/local/bin/python3 /opt/homebrew/bin/python3 /Library/Frameworks/Python.framework/Versions/Current/bin/python3 /usr/bin/python3; do
  if [ -x "$p" ] && "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then PY="$p"; break; fi
done
[ -n "${PY:-}" ] || { echo "omxpatch-agent: Python 3.8+ não encontrado (instale as ferramentas de linha de comandos: xcode-select --install)" >&2; exit 127; }
PYTHONPATH=/Library/OMXPatchAgent${PYTHONPATH:+:$PYTHONPATH} exec "$PY" -m omxpatch_agent "$@"
SH
chmod 0755 "$ROOTDIR/usr/local/bin/omxpatch-agent"
cp packaging/build/macos/scripts/postinstall "$WORK/postinstall"; mkdir -p "$WORK/scripts"; mv "$WORK/postinstall" "$WORK/scripts/postinstall"; chmod 0755 "$WORK/scripts/postinstall"

SIGN=(); [ -n "${MACOS_INSTALLER_SIGN:-}" ] && SIGN=(--sign "$MACOS_INSTALLER_SIGN")
PKG="$DIST/omxpatch-agent-$VER.pkg"
pkgbuild --root "$ROOTDIR" --identifier pt.oramix.omxpatch.agent --version "$VER" --install-location / --scripts "$WORK/scripts" ${SIGN[@]+"${SIGN[@]}"} "$PKG"
pkgutil --check-signature "$PKG" || true
if [ -n "${MACOS_INSTALLER_SIGN:-}" ] && [ -n "${MACOS_NOTARY_PROFILE:-}" ]; then
  xcrun notarytool submit "$PKG" --keychain-profile "$MACOS_NOTARY_PROFILE" --wait && xcrun stapler staple "$PKG"
fi
pkgutil --payload-files "$PKG" | head -5
(cd "$DIST" && shasum -a 256 omxpatch-agent-"$VER".pkg > omxpatch-agent-"$VER".pkg.sha256 && cat omxpatch-agent-"$VER".pkg.sha256)
