import os, re, sys, site, glob, json
sys.path.append(site.getusersitepackages())
import pandas as pd, numpy as np
sys.stdout.reconfigure(encoding="utf-8")
root = r"D:\ARTICULO_WAZUH\datasets\wazuh_cluster_timeliness\raw\zenodo-jcp\data\exp1-main-campaign"
rows = []
for d in sorted(os.listdir(root)):
    m = re.match(r"arm([ABC])_n(\d+)_rep(\d+)$", d)
    if not m:
        continue
    p = os.path.join(root, d)
    mg = pd.read_csv(glob.glob(os.path.join(p, "*_manager.csv"))[0])
    ix = pd.read_csv(glob.glob(os.path.join(p, "*_indexer.csv"))[0])
    la = pd.read_csv(os.path.join(p, "latency.csv"))
    f = la[la.status == "found"].latency_ms
    rows.append(dict(arm=m[1], agentes=int(m[2]), rep=int(m[3]), mgr_cpu=mg.cpu_percent.mean(), mgr_mem=mg.mem_percent.mean(), mgr_mem_mb=mg.mem_used_mb.mean(), mgr_total_mb=mg.mem_total_mb.iloc[0],
                     idx_cpu=ix.cpu_percent.mean(), idx_mem=ix.mem_percent.mean(), idx_total_mb=ix.mem_total_mb.iloc[0],
                     lat_med_s=f.median() / 1000, lat_p95_s=f.quantile(.95) / 1000 if len(f) else np.nan, timeout=float((la.status != "found").mean()),
                     disc=mg.rmt_discarded_count.max() - mg.rmt_discarded_count.min(), drop=mg.ana_events_dropped.max() - mg.ana_events_dropped.min()))
df = pd.DataFrame(rows)
s = df.groupby(["arm", "agentes"]).agg(n=("rep", "count"), mgr_cpu=("mgr_cpu", "mean"), mgr_mem=("mgr_mem", "mean"), mgr_total_mb=("mgr_total_mb", "first"), idx_cpu=("idx_cpu", "mean"), idx_mem=("idx_mem", "mean"), idx_total_mb=("idx_total_mb", "first"),
                                    lat_med_s=("lat_med_s", "mean"), lat_p95_s=("lat_p95_s", "mean"), timeout=("timeout", "mean"), disc=("disc", "mean"), drop=("drop", "mean")).round(2)
print(s.to_string())
s.reset_index().to_csv(r"D:\ARTICULO_WAZUH\resultados\cluster_exp1.csv", index=False)
rd = open(r"D:\ARTICULO_WAZUH\datasets\wazuh_cluster_timeliness\raw\zenodo-jcp\README.md", encoding="utf-8").read() if os.path.exists(r"D:\ARTICULO_WAZUH\datasets\wazuh_cluster_timeliness\raw\zenodo-jcp\README.md") else ""
print(rd[:1500])
print(os.listdir(r"D:\ARTICULO_WAZUH\datasets\wazuh_cluster_timeliness\raw\zenodo-jcp"))
for p in glob.glob(r"D:\ARTICULO_WAZUH\datasets\wazuh_cluster_timeliness\raw\zenodo-jcp\**\*", recursive=True):
    if re.search(r"(arm|config|hardware|testbed|env)", os.path.basename(p), re.I) and os.path.isfile(p) and p.endswith((".md", ".txt", ".yaml", ".yml", ".sh", ".py")):
        print("F", p[-70:])
