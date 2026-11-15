"""Cria um .zip de uma pasta com caminhos «/» (compatível com qualquer SO) e a pasta-raiz dentro do ficheiro.
Uso: zipdir.py <pasta> <destino.zip>   (o SO de origem não importa: não depende de zip/Compress-Archive)"""
import os
import sys
import zipfile

src, dst = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
base = os.path.basename(src.rstrip("/\\"))
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for root, dirs, files in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        rel_root = os.path.relpath(root, os.path.dirname(src)).replace(os.sep, "/")
        if not files and not dirs:
            z.write(root, rel_root + "/")
        for f in sorted(files):
            if f.endswith((".pyc", ".pyo")):
                continue
            z.write(os.path.join(root, f), f"{rel_root}/{f}")
print(f"{dst} ({os.path.getsize(dst) // 1024} KB)")
