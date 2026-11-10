"""Prueba de concepto sobre AIT-ADS: deduplicacion, ventanas multiservidor y evaluacion por escenario."""
import csv, glob, json, os, sys, site, time, warnings
from collections import Counter, defaultdict
from datetime import datetime, timezone
sys.path.append(site.getusersitepackages())
import numpy as np, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier as HGB, RandomForestClassifier as RF
from sklearn.linear_model import LogisticRegression as LR
from sklearn.metrics import average_precision_score as ap, f1_score, matthews_corrcoef as mcc, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")
sys.stdout.reconfigure(encoding="utf-8")
D = r"D:\ARTICULO_WAZUH\datasets\ait_ads"
OUT = r"D:\ARTICULO_WAZUH\resultados"
os.makedirs(OUT, exist_ok=True)
W = 60
ROLES = ["web", "ids", "correo", "sistema"]
GROUPS = ["web_scan", "recon", "attack", "access_denied", "appsec", "authentication_failed", "authentication_success",
          "invalid_login", "pam", "sshd", "audit", "syslog", "suricata", "access_control", "authentication_failures"]
STAGE = {"network_scans": "reconocimiento", "service_scans": "reconocimiento", "dirb": "reconocimiento", "wpscan": "reconocimiento",
         "webshell": "acceso", "cracking": "acceso", "reverse_shell": "ejecucion", "privilege_escalation": "escalada",
         "service_stop": "impacto", "dnsteal": "exfiltracion"}


def role(loc, groups):
    if "suricata" in loc:
        return "ids"
    if "apache" in loc or "horde" in loc:
        return "web"
    if "mail." in loc or "dovecot" in groups:
        return "correo"
    return "sistema"


labels = defaultdict(list)
for r in csv.DictReader(open(os.path.join(D, "labels.csv"), encoding="utf-8")):
    labels[r["scenario"]].append((float(r["start"]), float(r["end"]), r["attack"]))

t0 = time.time()
stats = Counter()
per_role_raw, per_role_ded, per_scen_ded = Counter(), Counter(), Counter()
win = defaultdict(lambda: defaultdict(float))
rules = defaultdict(lambda: defaultdict(set))
sanity = Counter()
for f in sorted(glob.glob(os.path.join(D, "raw", "*_wazuh.json"))):
    scen = os.path.basename(f).split("_")[0]
    for line in open(f, encoding="utf-8", errors="replace"):
        line = line.strip().rstrip(",")
        if not line:
            continue
        a = json.loads(line)
        loc, r = a.get("location", ""), a.get("rule") or {}
        groups = r.get("groups") or []
        ro = role(loc, groups)
        stats["crudas"] += 1
        per_role_raw[ro] += 1
        # Suricata llega por eve.json y fast.log; dovecot por mail.log, mail.info y syslog
        if "fast.log" in loc:
            stats["dup_suricata"] += 1
            continue
        if "dovecot" in groups and not loc.endswith("mail.log"):
            stats["dup_dovecot"] += 1
            continue
        ts = datetime.fromisoformat(a["@timestamp"].replace("Z", "+00:00")).replace(tzinfo=timezone.utc).timestamp()
        stats["deduplicadas"] += 1
        per_role_ded[ro] += 1
        per_scen_ded[scen] += 1
        wid = int(ts // W)
        k = (scen, wid)
        lvl = int(r.get("level") or 0)
        c = win[k]
        c[f"{ro}__n"] += 1
        c[f"{ro}__lvl_bajo"] += lvl < 5
        c[f"{ro}__lvl_medio"] += 5 <= lvl < 8
        c[f"{ro}__lvl_alto"] += 8 <= lvl < 10
        c[f"{ro}__lvl_critico"] += lvl >= 10
        c[f"{ro}__lvl_max"] = max(c[f"{ro}__lvl_max"], lvl)
        for g in groups:
            if g in GROUPS:
                c[f"{ro}__g_{g}"] += 1
        rules[k][ro].add(r.get("id"))
        if "web_scan" in groups:
            sanity["web_scan_total"] += 1
            sanity["web_scan_en_ventana"] += any(s <= ts <= e for s, e, _ in labels[scen])
print("parseo", round(time.time() - t0), "s", dict(stats), dict(sanity), flush=True)

BASE = ["n", "lvl_bajo", "lvl_medio", "lvl_alto", "lvl_critico", "lvl_max", "rules"] + [f"g_{g}" for g in GROUPS]
rows = []
for (scen, wid), c in win.items():
    row = {"escenario": scen, "wid": wid}
    for ro in ROLES:
        for b in BASE:
            row[f"{ro}__{b}"] = len(rules[(scen, wid)].get(ro, ())) if b == "rules" else c.get(f"{ro}__{b}", 0)
    rows.append(row)
df = pd.DataFrame(rows).sort_values(["escenario", "wid"]).reset_index(drop=True)

# Contexto temporal por servidor (5 min previos) sobre la linea de tiempo completa
fr = []
for scen, g in df.groupby("escenario"):
    g = g.set_index("wid")
    full = g.drop(columns="escenario").reindex(range(g.index.min(), g.index.max() + 1), fill_value=0)
    for ro in ROLES:
        g[f"{ro}__prev5_n"] = full[f"{ro}__n"].shift(1).rolling(5, min_periods=1).sum().reindex(g.index).fillna(0)
    roles_act = (full[[f"{ro}__n" for ro in ROLES]] > 0)
    g["x__servidores_activos"] = roles_act.loc[g.index].sum(axis=1)
    g["x__servidores_activos_prev5"] = (roles_act.shift(1).rolling(5, min_periods=1).max().fillna(0)).sum(axis=1).reindex(g.index)
    g["x__total"] = g[[f"{ro}__n" for ro in ROLES]].sum(axis=1)
    fr.append(g.reset_index())
df = pd.concat(fr, ignore_index=True)


def tag(row):
    lo, hi = row.wid * W, (row.wid + 1) * W
    hits = [a for s, e, a in labels[row.escenario] if s < hi and e > lo]
    return ";".join(sorted(set(hits)))


df["fases"] = [tag(r) for r in df.itertuples()]
df["y"] = (df.fases != "").astype(int)
df.to_csv(os.path.join(OUT, "ventanas_multiservidor.csv.gz"), index=False, compression="gzip")
SC = sorted(df.escenario.unique())
print("ventanas", len(df), "positivas", int(df.y.sum()), "prev", round(df.y.mean(), 4), flush=True)

ALL = [c for c in df.columns if "__" in c]
SETS = {"4 servidores": ALL}
for ro in ROLES:
    SETS[f"solo {ro}"] = [c for c in ALL if c.startswith(ro + "__")]


def model(name):
    if name == "LR":
        return make_pipeline(StandardScaler(), LR(max_iter=2000, class_weight="balanced"))
    if name == "RF":
        return RF(n_estimators=300, min_samples_leaf=2, class_weight="balanced", n_jobs=6, random_state=42)
    return HGB(max_iter=300, learning_rate=0.06, max_leaf_nodes=31, class_weight="balanced", random_state=42)


def X(frame, cols):
    return np.log1p(frame[cols].to_numpy(dtype=float))


def met(y, s, yhat):
    if y.sum() == 0:
        return None
    return dict(ap=ap(y, s), f1=f1_score(y, yhat, zero_division=0), precision=precision_score(y, yhat, zero_division=0),
                recall=recall_score(y, yhat, zero_division=0), mcc=mcc(y, yhat),
                fpr=float(((yhat == 1) & (y == 0)).sum() / max(1, (y == 0).sum())))


def loso(name, cols):
    per, oof = [], np.full(len(df), np.nan)
    for sc in SC:
        tr, te = df.escenario != sc, df.escenario == sc
        m = model(name).fit(X(df[tr], cols), df.y[tr])
        p = m.predict_proba(X(df[te], cols))[:, 1]
        oof[te.to_numpy()] = p
        r = met(df.y[te].to_numpy(), p, (p >= .5).astype(int))
        per.append({"modelo": name, "escenario": sc, **r})
    return per, oof


res, folds = [], []
def add(label, per):
    folds.extend({"config": label, **p} for p in per)
    d = pd.DataFrame(per)
    res.append({"config": label, **{f"{k}_mean": d[k].mean() for k in ["ap", "f1", "precision", "recall", "mcc", "fpr"]},
                **{f"{k}_sd": d[k].std(ddof=1) for k in ["ap", "f1", "precision", "recall", "mcc", "fpr"]}})
    print(label, {k: round(d[k].mean(), 3) for k in ["ap", "f1", "precision", "recall", "mcc", "fpr"]}, flush=True)


# Lineas base
lmax = df[[f"{ro}__lvl_max" for ro in ROLES]].max(axis=1).to_numpy()
add("Base: nivel Wazuh >= 10", [{"modelo": "base", "escenario": sc, **met(df.y[df.escenario == sc].to_numpy(), lmax[df.escenario == sc], (lmax[df.escenario == sc] >= 10).astype(int))} for sc in SC])
per = []
for sc in SC:
    tr, te = df.escenario != sc, df.escenario == sc
    grid = np.unique(np.quantile(df.x__total[tr], np.linspace(.05, .99, 60)))
    th = grid[int(np.argmax([f1_score(df.y[tr], df.x__total[tr] >= g) for g in grid]))]
    per.append({"modelo": "base", "escenario": sc, **met(df.y[te].to_numpy(), df.x__total[te].to_numpy(), (df.x__total[te] >= th).astype(int))})
add("Base: umbral de volumen", per)

oof_best = None
for name in ["LR", "RF", "HGB"]:
    per, oof = loso(name, ALL)
    add(f"{name} (4 servidores)", per)
    if name == "RF":
        oof_rf = oof
    if name == "HGB":
        oof_best = oof

for label, cols in SETS.items():
    if label != "4 servidores":
        per, _ = loso("HGB", cols)
        add(f"HGB ({label})", per)
per, _ = loso("HGB", [c for c in ALL if not c.startswith("x__") and "prev5" not in c])
add("HGB (4 servidores, sin contexto temporal ni cruzado)", per)

# Optimismo por particion aleatoria
skf, per = StratifiedKFold(8, shuffle=True, random_state=42), []
for k, (tr, te) in enumerate(skf.split(df, df.y)):
    m = model("HGB").fit(X(df.iloc[tr], ALL), df.y.iloc[tr])
    p = m.predict_proba(X(df.iloc[te], ALL))[:, 1]
    per.append({"modelo": "HGB", "escenario": f"fold{k}", **met(df.y.iloc[te].to_numpy(), p, (p >= .5).astype(int))})
add("HGB (particion aleatoria, con fuga)", per)

pd.DataFrame(res).to_csv(os.path.join(OUT, "resultados_modelos.csv"), index=False)
pd.DataFrame(folds).to_csv(os.path.join(OUT, "resultados_por_escenario.csv"), index=False)

# Cobertura por fase y latencia con el modelo HGB
df["p"] = oof_best
df["yhat"] = (df.p >= .5).astype(int)
ph, cov = [], []
for sc in SC:
    g = df[df.escenario == sc]
    got = Counter()
    for s, e, a in labels[sc]:
        lo, hi = int(s // W), int(e // W)
        x = g[(g.wid >= lo) & (g.wid <= hi)]
        hit = x[x.yhat == 1]
        lat = (hit.wid.min() * W - s) if len(hit) else np.nan
        ph.append({"escenario": sc, "fase": a, "etapa": STAGE[a], "dur_s": e - s, "ventanas_con_alertas": len(x),
                   "ventanas_detectadas": len(hit), "detectada": int(len(hit) > 0), "con_alertas": int(len(x) > 0),
                   "latencia_s": max(lat, 0) if lat == lat else np.nan})
ph = pd.DataFrame(ph)
ph.to_csv(os.path.join(OUT, "cobertura_fases.csv"), index=False)
print(ph.groupby("etapa")[["con_alertas", "detectada"]].agg(["sum", "count"]), flush=True)
print(ph.groupby("fase")[["con_alertas", "detectada", "latencia_s"]].mean().round(2), flush=True)

# Importancia aproximada por servidor con RF completo
rf = model("RF").fit(X(df, ALL), df.y)
imp = pd.Series(rf.feature_importances_, ALL)
by = imp.groupby(lambda c: c.split("__")[0]).sum().sort_values(ascending=False)
imp.sort_values(ascending=False).to_csv(os.path.join(OUT, "importancia_rf.csv"))
print("importancia_servidor", by.round(3).to_dict(), flush=True)
print("top", imp.sort_values(ascending=False).head(10).round(3).to_dict(), flush=True)

summ = dict(stats=dict(stats), sanity=dict(sanity), roles_crudas=dict(per_role_raw), roles_dedup=dict(per_role_ded),
            escenarios_dedup=dict(per_scen_ded), ventanas=int(len(df)), positivas=int(df.y.sum()),
            ventana_s=W, fases=int(len(ph)), fases_con_alertas=int(ph.con_alertas.sum()), fases_detectadas=int(ph.detectada.sum()),
            alertas_marcadas=float(df.loc[df.yhat == 1, "x__total"].sum()), ventanas_marcadas=int(df.yhat.sum()),
            roles_coactivos=df.x__servidores_activos.value_counts().sort_index().to_dict(),
            roles_coactivos_pos=df[df.y == 1].x__servidores_activos.value_counts().sort_index().to_dict(),
            importancia=by.to_dict())
json.dump(summ, open(os.path.join(OUT, "resumen.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=float)
print("FIN", round(time.time() - t0), "s", flush=True)
