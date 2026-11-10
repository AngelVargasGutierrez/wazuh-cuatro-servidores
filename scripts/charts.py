import os, sys, site, json, glob
sys.path.append(site.getusersitepackages())
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
COMMA = FuncFormatter(lambda v, _: f"{v:.2f}".replace(".", ","))

sys.stdout.reconfigure(encoding="utf-8")
R = r"D:\ARTICULO_WAZUH\resultados"
F = r"D:\ARTICULO_WAZUH\figuras"
BLUE, ORANGE, GREEN, INK, MUT, GRID, GREY = "#2a78d6", "#eb6834", "#1baf7a", "#0b0b0b", "#52514e", "#e4e3df", "#b8b6ae"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8.5, "axes.edgecolor": GRID, "axes.labelcolor": MUT, "xtick.color": MUT, "ytick.color": INK,
                     "axes.spines.top": False, "axes.spines.right": False, "axes.spines.left": False, "axes.grid": True, "grid.color": GRID, "grid.linewidth": .7, "axes.axisbelow": True})
res = pd.read_csv(os.path.join(R, "resultados_modelos_v2.csv")).set_index("config")
fold = pd.read_csv(os.path.join(R, "resultados_por_escenario_v2.csv"))
ph = pd.read_csv(os.path.join(R, "cobertura_fases_v2.csv"))
win = pd.read_csv(os.path.join(R, "ventanas_multiservidor.csv.gz"), usecols=["escenario", "wid", "y"])


def save(f, n):
    f.tight_layout()
    f.savefig(os.path.join(F, n), dpi=220, facecolor="white", bbox_inches="tight", pad_inches=.04)
    plt.close(f)


# Metodos: dos paneles con eje propio
order = ["Regla: nivel Wazuh", "Regla: volumen", "RF (cuatro servidores)", "HGB (cuatro servidores)", "LR (cuatro servidores)"]
names = ["Regla: nivel Wazuh", "Regla: volumen", "Bosque aleatorio", "Gradient boosting", "Regresión logística"]
f, ax = plt.subplots(1, 2, figsize=(7.2, 2.5), sharey=True)
for a, k, t in zip(ax, ["ap", "f1"], ["Precisión promedio (AP)", "Puntaje F1"]):
    y = np.arange(len(order))
    v = [res.loc[c, f"{k}_mean"] for c in order]
    s = [res.loc[c, f"{k}_sd"] for c in order]
    a.errorbar(v, y, xerr=s, fmt="none", ecolor=GREY, elinewidth=1, capsize=2.5, zorder=2)
    a.scatter(v, y, s=52, color=BLUE, edgecolor="white", linewidth=1.5, zorder=3)
    for yy, val, sd in zip(y, v, s):
        a.text(val, yy + .3, f"{val:.2f}".replace(".", ","), fontsize=7.8, color=INK, va="center", ha="center")
    a.set_yticks(y, names); a.set_title(t, fontsize=9, color=INK, loc="left", pad=8); a.set_xlim(0, .56); a.set_ylim(-.55, len(order) - .25); a.grid(axis="y", visible=False)
    a.tick_params(length=0); a.xaxis.set_major_formatter(COMMA)
save(f, "c_metodos.png")

# Por servidor
o2 = ["LR (solo correo)", "LR (solo sistema)", "LR (solo ids)", "LR (solo web)", "LR (cuatro servidores)"]
n2 = ["Solo correo", "Solo sistema", "Solo IDS", "Solo web", "Cuatro roles"]
f, a = plt.subplots(figsize=(7.2, 2.2))
v = [res.loc[c, "ap_mean"] for c in o2]
b = a.barh(n2, v, color=[GREY] * 4 + [BLUE], height=.55)
for r, val in zip(b, v):
    a.text(val + .004, r.get_y() + r.get_height() / 2, f"{val:.3f}".replace(".", ","), va="center", fontsize=8, color=INK)
a.set_xlabel("Precisión promedio (AP), media de ocho escenarios"); a.grid(axis="y", visible=False); a.tick_params(length=0); a.set_xlim(0, .3); a.xaxis.set_major_formatter(COMMA)
save(f, "c_servidores.png")

# Cobertura por etapa
st_order = ["Reconocimiento", "Acceso", "Ejecución", "Escalada", "Exfiltración", "Impacto"]
g = ph.groupby("etapa").agg(n=("fase", "count"), d=("detectada", "sum"), a=("con_alertas", "sum")).reindex(st_order)
f, a = plt.subplots(figsize=(7.2, 2.3))
y = np.arange(len(st_order))[::-1]
det, sal, nal = g.d.values, (g.a - g.d).clip(lower=0).values, (g.n - g.a).values
a.barh(y, det, color=BLUE, height=.56, label="Detectada", edgecolor="white", linewidth=1.2)
a.barh(y, sal, left=det, color=ORANGE, height=.56, label="Con alertas, no detectada", edgecolor="white", linewidth=1.2)
a.barh(y, nal, left=det + sal, color=GREY, height=.56, label="Sin alertas Wazuh", edgecolor="white", linewidth=1.2)
for yy, d, n in zip(y, det, g.n.values):
    a.text(n + .4, yy, f"{d} de {n}", va="center", fontsize=8, color=INK)
a.set_yticks(y, st_order); a.set_xlabel("Fases de ataque (79 en total)"); a.grid(axis="y", visible=False); a.tick_params(length=0); a.set_xlim(0, 37)
a.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(.45, 1.2), fontsize=7.8)
save(f, "c_etapas.png")

print(g)
print("total detectadas", int(g.d.sum()), "de", int(g.n.sum()), "con alertas", int(g.a.sum()))
L = fold[fold.config == "LR (cuatro servidores)"][["escenario", "ap", "f1", "precision", "recall", "umbral", "marcadas"]].round(3)
B = fold[fold.config == "Regla: nivel Wazuh"][["escenario", "ap", "f1"]].round(3).rename(columns={"ap": "ap_regla", "f1": "f1_regla"})
w = win.groupby("escenario").agg(ventanas=("y", "size"), positivas=("y", "sum"), horas=("wid", lambda s: round((s.max() - s.min()) / 60, 1))).reset_index()
print(L.merge(B).merge(w).to_string())
print(ph.groupby("fase").agg(d=("detectada", "sum"), n=("fase", "count"), a=("con_alertas", "sum"), lat=("latencia_s", "median")).to_string())
print(ph.groupby("escenario").detectada.sum().to_dict())
root = r"D:\ARTICULO_WAZUH\datasets\wazuh_cluster_timeliness\raw\zenodo-jcp"
for d in ("armA_n100_rep1", "armB_n100_rep1", "armC_n100_rep1"):
    t = open(os.path.join(root, "data", "exp1-main-campaign", d, "simulate.log"), encoding="utf-8", errors="replace").read()
    print(d, " | ".join(t.splitlines()[:3])[:260])
for p in glob.glob(os.path.join(root, "scripts", "**", "*"), recursive=True):
    if os.path.isfile(p) and p.endswith((".md", ".sh", ".py", ".txt")):
        t = open(p, encoding="utf-8", errors="replace").read()
        for ln in t.splitlines():
            if ("arm a" in ln.lower() or "arm b" in ln.lower() or "arm c" in ln.lower() or "armA" in ln and "#" in ln):
                print(os.path.basename(p), ln.strip()[:170])
                break
