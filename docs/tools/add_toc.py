"""Acrescenta um índice estático (secções) a um manual em Markdown: python add_toc.py entrada.md saida.md
(o campo de índice do Word fica vazio no PDF gerado pelo LibreOffice, por isso o índice é escrito como texto)."""
import re
import sys

src = open(sys.argv[1], encoding="utf-8").read()
m = re.match(r"^---\n.*?\n---\n", src, re.S)
front, body = (m.group(0), src[m.end():]) if m else ("", src)
lines, in_code = [], False
for l in body.splitlines():
    if l.startswith("```"):
        in_code = not in_code
    if in_code:
        continue
    if l.startswith("# "):
        lines.append("**" + l[2:].strip() + "**")
    elif l.startswith("## "):
        lines.append("    " + l[3:].strip())
BR = "\n\n```{=openxml}\n<w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>\n```\n\n"
toc = BR + "# Índice {.unnumbered}\n\n" + "\n".join(f"{x}  " if not x.startswith("**") else f"\n{x}  " for x in lines) + BR
open(sys.argv[2], "w", encoding="utf-8").write(front + toc + body)
