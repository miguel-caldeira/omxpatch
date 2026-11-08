#!/usr/bin/env bash
# Constrói os pacotes de instalação em dist/:
#   omxpatch-ubuntu-<versão>.tar.gz   centro de comando (Ubuntu/Debian) com wheelhouse offline (cp312/cp313, x86_64 e aarch64)
#   omxpatch-windows-<versão>.zip     centro de comando (Windows) com wheelhouse offline (cp312, win_amd64)
#   omxpatch-windows2012r2-<versão>.zip centro de comando para Windows Server 2012 R2 (Python 3.11, cp311 win_amd64)
#   omxpatch-agent-<versão>.zip       agente (só biblioteca padrão) para instalação manual/offline
#   SHA256SUMS
# Requer: python3 com pip e tar (zip é opcional). Uso: packaging/build_installers.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
PY="${PYTHON:-python3}"
# zip: usa o comando se existir; caso contrário, o módulo zipfile do Python (não exige instalar nada)
mkzip() {  # mkzip <destino.zip> <pasta>   (executado dentro da pasta-mãe)
  if command -v zip >/dev/null 2>&1; then zip -qr "$1" "$2"; else
    "$PY" - "$1" "$2" <<'PYZIP'
import os, sys, zipfile
dest, root = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
    for d, _, files in os.walk(root):
        if not files and not _:
            z.write(d)
        for f in files:
            p = os.path.join(d, f)
            z.write(p, p)
PYZIP
  fi
}
VER="$($PY -c "import re;print(re.search(r'__version__ = \"([^\"]+)\"', open('omxpatch/__init__.py').read()).group(1))")"
DIST="$ROOT/dist"; STAGE="$(mktemp -d)"; rm -rf "$DIST"; mkdir -p "$DIST"
trap 'rm -rf "$STAGE"' EXIT
echo "OMXPatch $VER"

echo "==> wheel da aplicação"
$PY -m pip wheel . --no-deps -q -w "$STAGE/app-wheel"
rm -rf build ./*.egg-info

dl() {  # dl <pasta> <plataforma> <python> -> dependências binárias
  $PY -m pip download -q -r requirements.lock --require-hashes --only-binary=:all: --platform "$2" --python-version "$3" --implementation cp -d "$1" 2>&1 | tail -2
}

echo "==> Ubuntu"
U="$STAGE/omxpatch-ubuntu-$VER"; mkdir -p "$U/wheels"
cp "$STAGE"/app-wheel/*.whl "$U/wheels/"
for arch in manylinux2014_x86_64 manylinux2014_aarch64; do for pv in 3.12 3.13; do dl "$U/wheels" "$arch" "$pv"; done; done
$PY -m pip download -q "tomli>=2.0" --only-binary=:all: --python-version 3.9 --platform manylinux2014_x86_64 --implementation cp -d "$U/wheels" 2>/dev/null || true
cp packaging/installers/ubuntu/* "$U/"; echo "$VER" > "$U/VERSION"
# Python/pip/venv offline (Ubuntu 24.04 amd64): .deb usados pelo instalador se o apt não tiver acesso à rede
DEBS="python3.12-venv python3-venv python3-pip python3-pip-whl python3-setuptools python3-setuptools-whl python3-pkg-resources python3-wheel sshpass openssh-client libfido2-1 libcbor0.10 libedit2"
mkdir -p "$U/debs"
if [ -r /etc/os-release ] && grep -q 'VERSION_ID="24.04"' /etc/os-release && command -v apt-get >/dev/null; then
  (cd "$U/debs" && apt-get download $DEBS >/dev/null 2>&1) || echo "AVISO: não foi possível descarregar os .deb (debs/ incompleto)"
else
  echo "AVISO: construa num Ubuntu 24.04 para incluir os .deb offline (python3-venv, pip) em debs/"
fi
ls "$U/debs" | grep -q . || echo "AVISO: pacote Ubuntu sem .deb offline: o instalador precisará de acesso ao apt"
tar -C "$STAGE" -czf "$DIST/omxpatch-ubuntu-$VER.tar.gz" "omxpatch-ubuntu-$VER"

echo "==> Windows"
W="$STAGE/omxpatch-windows-$VER"; mkdir -p "$W/wheels"
cp "$STAGE"/app-wheel/*.whl "$W/wheels/"
dl "$W/wheels" win_amd64 3.12
$PY -m pip download -q tzdata --only-binary=:all: -d "$W/wheels" 2>/dev/null || true
# Python para Windows (offline): PYTHON_WIN_EXE=<ficheiro> ou descarregado de python.org (SHA-256 gravado em python-installer.sha256)
PYV=3.12.8
if [ -n "${PYTHON_WIN_EXE:-}" ] && [ -f "$PYTHON_WIN_EXE" ]; then cp "$PYTHON_WIN_EXE" "$W/python-installer.exe"
else curl -fsSL -m 300 -o "$W/python-installer.exe" "https://www.python.org/ftp/python/$PYV/python-$PYV-amd64.exe" 2>/dev/null || rm -f "$W/python-installer.exe"; fi
if [ -f "$W/python-installer.exe" ]; then sha256sum "$W/python-installer.exe" | cut -d' ' -f1 > "$W/python-installer.sha256"
else echo "AVISO: instalador do Python não incluído (sem acesso a python.org): defina PYTHON_WIN_EXE=<python-3.12.x-amd64.exe>"; fi
cp packaging/installers/windows/* "$W/"; echo "$VER" > "$W/VERSION"
(cd "$STAGE" && mkzip "$DIST/omxpatch-windows-$VER.zip" "omxpatch-windows-$VER")

echo "==> Windows Server 2012 R2 (Python 3.11)"
W2="$STAGE/omxpatch-windows2012r2-$VER"; mkdir -p "$W2/wheels" "$W2/prereq"
cp "$STAGE"/app-wheel/*.whl "$W2/wheels/"
dl "$W2/wheels" win_amd64 3.11
$PY -m pip download -q tzdata --only-binary=:all: -d "$W2/wheels" 2>/dev/null || true
cp packaging/installers/windows/Instalar.cmd packaging/installers/windows/Uninstall-OMXPatch.ps1 "$W2/"
$PY packaging/make_2012r2.py packaging/installers/windows/Install-OMXPatch.ps1 "$W2/Install-OMXPatch.ps1"
cp packaging/installers/windows2012r2/LEIA-ME.txt "$W2/"; echo "$VER" > "$W2/VERSION"
PY2=3.11.9
if [ -n "${PYTHON_WIN2012_EXE:-}" ] && [ -f "$PYTHON_WIN2012_EXE" ]; then cp "$PYTHON_WIN2012_EXE" "$W2/python-installer.exe"
else curl -fsSL -m 300 -o "$W2/python-installer.exe" "https://www.python.org/ftp/python/$PY2/python-$PY2-amd64.exe" 2>/dev/null || rm -f "$W2/python-installer.exe"; fi
if [ -f "$W2/python-installer.exe" ]; then sha256sum "$W2/python-installer.exe" | cut -d' ' -f1 > "$W2/python-installer.sha256"
else echo "AVISO: pacote 2012 R2 sem python-installer.exe (defina PYTHON_WIN2012_EXE=<python-3.11.x-amd64.exe>)"; fi
for f in "$W2"/*.ps1; do head -c3 "$f" | grep -q $'\xef\xbb\xbf' || { printf '\xef\xbb\xbf' | cat - "$f" > "$f.n" && mv "$f.n" "$f"; }; done
(cd "$STAGE" && mkzip "$DIST/omxpatch-windows2012r2-$VER.zip" "omxpatch-windows2012r2-$VER")

echo "==> Kit de validação (Windows/macOS)"
K="$STAGE/omxpatch-validation-kit-$VER"; mkdir -p "$K"
cp -r omxpatch_agent "$K/"; find "$K" -name __pycache__ -prune -exec rm -rf {} +
cp packaging/validation-kit/* "$K/"; chmod +x "$K/validate-macos.sh"; echo "$VER" > "$K/VERSION"
(cd "$STAGE" && mkzip "$DIST/omxpatch-validation-kit-$VER.zip" "omxpatch-validation-kit-$VER")

echo "==> Agente"
A="$STAGE/omxpatch-agent-$VER"; mkdir -p "$A"
cp -r omxpatch_agent "$A/"; find "$A" -name __pycache__ -prune -exec rm -rf {} +
cat > "$A/LEIA-ME.txt" <<'EOF'
Agente OMXPatch (Python 3.8+, sem dependências). Instalação normal: gere o script de auto-instalação na consola («Agentes»).
Manual:  PYTHONPATH=<esta pasta> python3 -m omxpatch_agent enroll --server https://omxpatchcli.oramix.local:4444 --token omxe_… --pin-sha256 <SHA-256> --install-service
EOF
(cd "$STAGE" && mkzip "$DIST/omxpatch-agent-$VER.zip" "omxpatch-agent-$VER")

(cd "$DIST" && sha256sum * > SHA256SUMS && cat SHA256SUMS && du -sh *)
