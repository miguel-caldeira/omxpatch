#!/bin/sh
# Gera a referência e as versões Word e PDF dos manuais em docs/build/. Requer pandoc e LibreOffice (soffice).
set -eu
cd "$(dirname "$0")/.."
VER="$(python3 -c "import re;print(re.search(r'__version__ = \"([^\"]+)\"', open('../omxpatch/__init__.py').read()).group(1))")"
mkdir -p build
python3 tools/gen_reference.py
for m in MANUAL-UTILIZACAO MANUAL-ADMINISTRACAO REFERENCIA; do
  if [ "$m" = REFERENCIA ]; then cp "$m.md" "build/$m.tmp.md"; else python3 tools/add_toc.py "$m.md" "build/$m.tmp.md"; fi
  pandoc "build/$m.tmp.md" -o "build/$m-$VER.docx" --reference-doc=tools/reference.docx --resource-path=. \
         --metadata lang=pt-PT --metadata date="$(date +%Y-%m-%d)" --metadata "version=$VER"
  rm -f "build/$m.tmp.md"
  (cd build && soffice --headless --convert-to pdf "$m-$VER.docx" >/dev/null 2>&1)
done
ls -la build
