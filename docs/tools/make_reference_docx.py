"""Gera o modelo Word (cores e tipos de letra Oramix) usado pelo pandoc: python docs/tools/make_reference_docx.py docs/tools/reference.docx"""
import subprocess
import sys

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH  # noqa: F401
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor

out = sys.argv[1]
raw = subprocess.run(["pandoc", "--print-default-data-file", "reference.docx"], capture_output=True)
open(out, "wb").write(raw.stdout)
d = Document(out)
FONT, BLUE, TECH, ORANGE = "Arimo", RGBColor(0x17, 0x2C, 0x6C), RGBColor(0x00, 0x53, 0xAD), RGBColor(0xFF, 0x80, 0x00)


def style(name, size=None, color=None, bold=None, font=FONT, before=None, after=None):
    try:
        s = d.styles[name]
    except KeyError:
        return
    s.font.name = font
    s.element.rPr.rFonts.set(qn("w:eastAsia"), font) if s.element.rPr is not None and s.element.rPr.rFonts is not None else None
    if size:
        s.font.size = Pt(size)
    if color is not None:
        s.font.color.rgb = color
    if bold is not None:
        s.font.bold = bold
    if before is not None:
        s.paragraph_format.space_before = Pt(before)
    if after is not None:
        s.paragraph_format.space_after = Pt(after)


style("Normal", 10.5)
style("Body Text", 10.5, after=6)
style("First Paragraph", 10.5, after=6)
style("Compact", 10.5)
style("Title", 26, BLUE, True, after=6)
style("Subtitle", 14, ORANGE, False, after=18)
style("Heading 1", 18, BLUE, True, before=22, after=8)
style("Heading 2", 14, TECH, True, before=16, after=6)
style("Heading 3", 12, BLUE, True, before=12, after=4)
style("Block Text", 10, RGBColor(0x40, 0x40, 0x40))
style("Source Code", 8.5, RGBColor(0x20, 0x20, 0x20), font="DejaVu Sans Mono")
style("Verbatim Char", 9, RGBColor(0x17, 0x2C, 0x6C), font="DejaVu Sans Mono")
# tabelas com linhas finas e cabeçalho azul
try:
    t = d.styles["Table"]
    pr = t.element.get_or_add_tblPr() if hasattr(t.element, "get_or_add_tblPr") else None
except KeyError:
    t = None
if t is not None:
    el = t.element
    tblPr = el.find(qn("w:tblPr"))
    if tblPr is None:
        tblPr = OxmlElement("w:tblPr")
        el.append(tblPr)
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        b = OxmlElement(f"w:{edge}")
        b.set(qn("w:val"), "single")
        b.set(qn("w:sz"), "4")
        b.set(qn("w:color"), "C9D2E3")
        borders.append(b)
    tblPr.append(borders)
    cm = OxmlElement("w:tblCellMar")
    for side, w in (("top", 50), ("left", 80), ("bottom", 50), ("right", 80)):
        m = OxmlElement(f"w:{side}")
        m.set(qn("w:w"), str(w))
        m.set(qn("w:type"), "dxa")
        cm.append(m)
    tblPr.append(cm)
from docx.shared import Cm
for sec in d.sections:                      # A4 com margens de 2 cm
    sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
    sec.left_margin = sec.right_margin = Cm(2.0)
    sec.top_margin = sec.bottom_margin = Cm(2.0)
d.save(out)
print("modelo Word gerado:", out)
