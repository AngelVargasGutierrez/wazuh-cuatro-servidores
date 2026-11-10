import os, sys, site
sys.path.append(site.getusersitepackages())
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

NAVY, ORANGE, GREEN, INK = "#1f3a7a", "#eb6834", "#10734f", "#1b1b1b"
plt.rcParams.update({"font.family": "DejaVu Sans"})
f, a = plt.subplots(figsize=(7.4, 4.8))
a.set_xlim(0, 100); a.set_ylim(0, 100); a.axis("off")


def box(x, y, w, h, title, lines=(), ec=NAVY, fc="white", tc=NAVY, step=3.1):
    a.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=.7", fc=fc, ec=ec, lw=1.1))
    n = len(lines)
    top = y + h / 2 + n * step / 2
    a.text(x + w / 2, top, title, ha="center", va="center", fontsize=8, fontweight="bold", color=tc)
    for i, l in enumerate(lines):
        a.text(x + w / 2, top - (i + 1) * step, l, ha="center", va="center", fontsize=7, color=INK)


def down(x, y1, y2):
    a.annotate("", xy=(x, y2), xytext=(x, y1), arrowprops=dict(arrowstyle="-|>", color=NAVY, lw=1.1, shrinkA=0, shrinkB=0))


def side(y, color=ORANGE, reverse=False):
    p, q = ((60, y), (46, y)) if reverse else ((46, y), (60, y))
    a.annotate("", xy=q, xytext=p, arrowprops=dict(arrowstyle="-|>", color=color, lw=1.1, shrinkA=0, shrinkB=0))


H, X, W = 9.6, 6, 40
rows = [
    (89.5, "Registros recuperados: 1 142", ["9 consultas en OpenAlex, desde 2018"]),
    (75.2, "Candidatos únicos: 626", ["Con título y enlace a PDF"]),
    (60.9, "Elegibles: 546", ["Pasaron los filtros de contenido"]),
    (46.6, "Descargas intentadas: 163", ["Por orden de prioridad y cupo temático"]),
    (32.3, "Selección inicial: 80", ["PDF válido y título coincidente"]),
    (18.0, "Retenidos tras revisión: 60", ["Revisión manual de pertinencia"]),
    (3.7, "Corpus final: 80", ["DOI verificado en Crossref"]),
]
for i, (y, t, l) in enumerate(rows):
    final = i == 6
    box(X, y, W, H, t, l, ec=GREEN if final else NAVY, tc=GREEN if final else NAVY, fc="#effaf5" if final else "white")
    if i < 6:
        down(X + W / 2, y, rows[i + 1][0] + H)
S = [
    (82.0, 11.4, "Eliminados: 516", ["Duplicados entre consultas", "o sin enlace a PDF"], 1),
    (64.6, 16.0, "Excluidos: 80", ["67 tipo no elegible · 8 sin resumen", "2 sin términos de ciberseguridad", "2 sin mención de SIEM · 1 duplicado"], 2),
    (49.6, 10.0, "No intentados: 383", ["Cupo temático ya completo"], 3),
    (33.2, 11.0, "No seleccionados: 83", ["63 sin PDF válido", "20 excedente de cupo"], 4),
    (17.2, 13.2, "Retirados: 20", ["3 ajenos a ciberseguridad", "12 aporte limitado", "5 sustituidos por lista del grupo"], 5),
]
for y, h, t, l, k in S:
    box(60, y, 38, h, t, l, ec=ORANGE, tc=ORANGE, fc="#fff6ef")
    side(rows[k][0] + H + 1.6 + (rows[k - 1][0] - rows[k][0] - H) * .0 if False else (y + h / 2))
box(60, 1.3, 38, 13.6, "Incorporados: 20", ["3 de la misma base de candidatos", "12 de búsqueda complementaria", "5 de la lista del grupo"], ec=GREEN, tc=GREEN, fc="#effaf5")
side(8.1, color=GREEN, reverse=True)
f.savefig(r"D:\ARTICULO_WAZUH\figuras\d_seleccion.png", dpi=220, bbox_inches="tight", facecolor="white", pad_inches=.04)
