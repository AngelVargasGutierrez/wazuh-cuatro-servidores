"""Segunda ronda: linea base causal por escenario y umbral elegido solo con entrenamiento (LOSO anidado)."""
import csv, json, os, sys, site, time, warnings
from collections import Counter, defaultdict
sys.path.append(site.getusersitepackages())
import numpy as np, pandas as pd
from scipy.stats import wilcoxon
from sklearn.ensemble import HistGradientBoostingClassifier as HGB, RandomForestClassifier as RF
from sklearn.linear_model import LogisticRegression as LR
from sklearn.metrics import average_precision_score as ap, f1_score, matthews_corrcoef as mcc, precision_score, recall_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")
sys.stdout.reconfigure(encoding="utf-8")
OUT = r"D:\ARTICULO_WAZUH\resultados"
D = r"D:\ARTICULO_WAZUH\datasets\ait_ads"
df = pd.read_csv(os.path.join(OUT, "ventanas_multiservidor.csv.gz"))
df["fases"] = df.fases.fillna("")
ROLES = ["web", "ids", "correo", "sistema"]
BASECOLS = [c for c in df.columns if "__" in c]
W, HIST = 60, 120
t0 = time.time()
new = []
for sc, g in df.groupby("escenario"):
    g = g.set_index("wid").sort_index()
    idx = range(g.index.min(), g.index.max() + 1)
    full = np.log1p(g[BASECOLS].reindex(idx, fill_value=0))
    med = full.shift(1).rolling(HIST, min_periods=10).median().fillna(0)
    delta = (full - med).reindex(g.index)
    delta.columns = ["d_" + c for c in delta.columns]
    new.append(pd.concat([g.reset_index(), delta.reset_index(drop=True).set_axis(g.index.values)[delta.columns].reset_index(drop=True)], axis=1))
df = pd.concat(new, ignore_index=True)
for c in BASECOLS:
    df[c] = np.log1p(df[c])
ABS = BASECOLS
REL = ["d_" + c for c in BASECOLS]
SC = sorted(df.escenario.unique())
print("features", len(ABS), len(REL), round(time.time() - t0), flush=True)


def model(n):
    if n == "LR":
        return make_pipeline(StandardScaler(), LR(max_iter=1500, class_weight="balanced"))
    if n == "RF":
        return RF(n_estimators=150, min_samples_leaf=3, class_weight="balanced", n_jobs=6, random_state=42)
    return HGB(max_iter=150, learning_rate=0.07, max_leaf_nodes=15, class_weight="balanced", random_state=42)


GRID = np.linspace(.02, .98, 49)


def best_th(y, p):
    return float(GRID[int(np.argmax([f1_score(y, p >= t, zero_division=0) for t in GRID]))])


def met(y, s, yhat):
    return dict(ap=ap(y, s), f1=f1_score(y, yhat, zero_division=0), precision=precision_score(y, yhat, zero_division=0), recall=recall_score(y, yhat, zero_division=0),
                mcc=mcc(y, yhat), fpr=float(((yhat == 1) & (y == 0)).sum() / max(1, (y == 0).sum())), marcadas=float(yhat.mean()))


def nested(name, cols):
    per, oof, flag = [], np.zeros(len(df)), np.zeros(len(df), int)
    Xa, y = df[cols].to_numpy(float), df.y.to_numpy()
    groups = df.escenario.to_numpy()
    for sc in SC:
        tr, te = groups != sc, groups == sc
        ip = np.zeros(tr.sum())
        gtr = groups[tr]
        for s2 in SC:
            if s2 == sc:
                continue
            a, b = gtr != s2, gtr == s2
            ip[b] = model(name).fit(Xa[tr][a], y[tr][a]).predict_proba(Xa[tr][b])[:, 1]
        th = best_th(y[tr], ip)
        p = model(name).fit(Xa[tr], y[tr]).predict_proba(Xa[te])[:, 1]
        oof[te], flag[te] = p, (p >= th).astype(int)
        per.append({"modelo": name, "escenario": sc, "umbral": th, **met(y[te], p, flag[te])})
    return per, oof, flag


res, folds, store = [], [], {}
K = ["ap", "f1", "precision", "recall", "mcc", "fpr", "marcadas"]


def add(label, per):
    folds.extend({"config": label, **p} for p in per)
    d = pd.DataFrame(per)
    store[label] = d
    res.append({"config": label, **{f"{k}_mean": d[k].mean() for k in K}, **{f"{k}_sd": d[k].std(ddof=1) for k in K}})
    print(label, {k: round(d[k].mean(), 3) for k in K}, "t", round(time.time() - t0), flush=True)


# Lineas base con umbral aprendido en entrenamiento
y, g = df.y.to_numpy(), df.escenario.to_numpy()
lmax = np.expm1(df[[f"{r}__lvl_max" for r in ROLES]].to_numpy()).max(axis=1)
tot = np.expm1(df.x__total.to_numpy())
for label, s, grid in [("Regla: nivel Wazuh", lmax, [3, 4, 5, 6, 8, 10, 11, 12]), ("Regla: volumen", tot, None)]:
    per = []
    for sc in SC:
        tr, te = g != sc, g == sc
        gr = grid if grid else np.unique(np.quantile(s[tr], np.linspace(.05, .995, 80)))
        th = gr[int(np.argmax([f1_score(y[tr], s[tr] >= t, zero_division=0) for t in gr]))]
        per.append({"modelo": label, "escenario": sc, "umbral": float(th), **met(y[te], s[te], (s[te] >= th).astype(int))})
    add(label, per)

best = None
for m in ["LR", "RF", "HGB"]:
    per, oof, flag = nested(m, ABS + REL)
    add(f"{m} (cuatro servidores)", per)
    store[m + "_oof"], store[m + "_flag"] = oof, flag
bestm = max(["LR", "RF", "HGB"], key=lambda m: store[f"{m} (cuatro servidores)"].f1.mean())
print("mejor", bestm, flush=True)
per, _, _ = nested(bestm, ABS)
add(f"{bestm} (cuatro servidores, solo valores absolutos)", per)
per, _, _ = nested(bestm, REL)
add(f"{bestm} (cuatro servidores, solo linea base)", per)
for r in ROLES:
    cols = [c for c in ABS + REL if c.startswith(r + "__") or c.startswith("d_" + r + "__")]
    per, _, _ = nested(bestm, cols)
    add(f"{bestm} (solo {r})", per)

pd.DataFrame(res).to_csv(os.path.join(OUT, "resultados_modelos_v2.csv"), index=False)
pd.DataFrame(folds).to_csv(os.path.join(OUT, "resultados_por_escenario_v2.csv"), index=False)

A = store[f"{bestm} (cuatro servidores)"]
tests = {}
for label in [f"{bestm} (solo {r})" for r in ROLES] + ["Regla: nivel Wazuh", "Regla: volumen"]:
    B = store[label]
    for k in ("ap", "f1"):
        diff = (A[k].to_numpy() - B[k].to_numpy())
        try:
            p = wilcoxon(diff).pvalue
        except ValueError:
            p = 1.0
        tests[f"{label}|{k}"] = {"dif_media": float(diff.mean()), "p": float(p), "ganados": int((diff > 0).sum())}
print(json.dumps(tests, indent=0)[:1600], flush=True)

labels = defaultdict(list)
for r in csv.DictReader(open(os.path.join(D, "labels.csv"), encoding="utf-8")):
    labels[r["scenario"]].append((float(r["start"]), float(r["end"]), r["attack"]))
STAGE = {"network_scans": "Reconocimiento", "service_scans": "Reconocimiento", "dirb": "Reconocimiento", "wpscan": "Reconocimiento", "webshell": "Acceso", "cracking": "Acceso",
         "reverse_shell": "Ejecución", "privilege_escalation": "Escalada", "service_stop": "Impacto", "dnsteal": "Exfiltración"}
df["yhat"] = store[bestm + "_flag"]
df["wid_i"] = df.wid
ph = []
for sc in SC:
    x0 = df[df.escenario == sc]
    for s, e, a in labels[sc]:
        x = x0[(x0.wid >= int(s // W)) & (x0.wid <= int(e // W))]
        hit = x[x.yhat == 1]
        ph.append({"escenario": sc, "fase": a, "etapa": STAGE[a], "dur_s": e - s, "con_alertas": int(len(x) > 0), "detectada": int(len(hit) > 0),
                   "latencia_s": max(hit.wid.min() * W - s, 0) if len(hit) else np.nan})
ph = pd.DataFrame(ph)
ph.to_csv(os.path.join(OUT, "cobertura_fases_v2.csv"), index=False)
st = ph.groupby("etapa").agg(fases=("fase", "count"), con_alertas=("con_alertas", "sum"), detectadas=("detectada", "sum"), lat_mediana=("latencia_s", "median"))
print(st, flush=True)
camp = ph.groupby("escenario").agg(detectadas=("detectada", "sum"), fases=("fase", "count"))
print(camp.T, flush=True)
# horas de operacion y falsas alarmas
dur_h = df.groupby("escenario").wid.agg(lambda w: (w.max() - w.min()) * W / 3600)
fp = df[(df.yhat == 1) & (df.y == 0)].groupby("escenario").size()
print("falsas_por_dia_mediana", (fp / dur_h * 24).round(1).to_dict(), flush=True)
json.dump({"mejor": bestm, "tests": tests, "etapas": st.reset_index().to_dict("records"), "campanas": camp.reset_index().to_dict("records"),
           "falsas_por_dia": (fp / dur_h * 24).to_dict(), "duracion_h": dur_h.to_dict()}, open(os.path.join(OUT, "resumen_v2.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=float)
print("FIN", round(time.time() - t0), flush=True)
