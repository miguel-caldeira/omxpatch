#!/usr/bin/env bash
# Constrói os pacotes de instalação em dist/:
#   omxpatch-ubuntu-<versão>.tar.gz   centro de comando (Ubuntu/Debian) com wheelhouse offline (cp312/cp313, x86_64 e aarch64)
#   omxpatch-windows-<versão>.zip     centro de comando (Windows) com wheelhouse offline (cp312, win_amd64)
#   omxpatch-agent-<versão>.zip       agente (só biblioteca padrão) para instalação manual/offline
#   SHA256SUMS
# Requer: python3 com pip, zip, tar. Uso: packaging/build_installers.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
PY="${PYTHON:-python3}"
VER="$($PY -c "import re;print(re.search(r'__version__ = \"([^\"]+)\"', open('omxpatch/__init__.py').read()).group(1))")"
DIST="$ROOT/dist"; STAGE="$(mktemp -d)"; rm -rf "$DIST"; mkdir -p "$DIST"
trap 'rm -rf "$STAGE"' EXIT
echo "OMXPatch $VER"

echo "==> wheel da aplicação"
$PY -m pip wheel . --no-deps -q -w "$STAGE/app-wheel"
rm -rf build ./*.egg-info

dl() {  # dl <pasta> <plataforma> <python> -> dependências binárias
  $PY -m pip download -q -r requirements.txt --only-binary=:all: --platform "$2" --python-version "$3" --implementation cp -d "$1" 2>&1 | tail -2 || true
}

echo "==> Ubuntu"
U="$STAGE/omxpatch-ubuntu-$VER"; mkdir -p "$U/wheels"
cp "$STAGE"/app-wheel/*.whl "$U/wheels/"
for arch in manylinux2014_x86_64 manylinux2014_aarch64; do for pv in 3.12 3.13; do dl "$U/wheels" "$arch" "$pv"; done; done
$PY -m pip download -q "tomli>=2.0" --only-binary=:all: --python-version 3.9 --platform manylinux2014_x86_64 --implementation cp -d "$U/wheels" 2>/dev/null || true
cp packaging/installers/ubuntu/* "$U/"; echo "$VER" > "$U/VERSION"
tar -C "$STAGE" -czf "$DIST/omxpatch-ubuntu-$VER.tar.gz" "omxpatch-ubuntu-$VER"

echo "==> Windows"
W="$STAGE/omxpatch-windows-$VER"; mkdir -p "$W/wheels"
cp "$STAGE"/app-wheel/*.whl "$W/wheels/"
dl "$W/wheels" win_amd64 3.12
$PY -m pip download -q tzdata --only-binary=:all: -d "$W/wheels" 2>/dev/null || true
cp packaging/installers/windows/* "$W/"; echo "$VER" > "$W/VERSION"
(cd "$STAGE" && zip -qr "$DIST/omxpatch-windows-$VER.zip" "omxpatch-windows-$VER")

echo "==> Agente"
A="$STAGE/omxpatch-agent-$VER"; mkdir -p "$A"
cp -r omxpatch_agent "$A/"; find "$A" -name __pycache__ -prune -exec rm -rf {} +
cat > "$A/LEIA-ME.txt" <<'EOF'
Agente OMXPatch (Python 3.8+, sem dependências). Instalação normal: gere o script de auto-instalação na consola («Agentes»).
Manual:  PYTHONPATH=<esta pasta> python3 -m omxpatch_agent enroll --server https://omxpatchcli.oramix.local:4444 --token omxe_… --pin-sha256 <SHA-256> --install-service
EOF
(cd "$STAGE" && zip -qr "$DIST/omxpatch-agent-$VER.zip" "omxpatch-agent-$VER")

(cd "$DIST" && sha256sum * > SHA256SUMS && cat SHA256SUMS && du -sh *)
