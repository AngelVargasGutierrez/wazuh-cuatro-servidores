import json, os, re, sys, site, time, unicodedata, tarfile
sys.path.append(site.getusersitepackages())
import requests

sys.stdout.reconfigure(encoding="utf-8")
B = r"D:\ARTICULO_WAZUH"
M = os.path.join(B, "metadata")
H = {"User-Agent": "academic-literature-harvester/1.0"}
corpus = json.load(open(os.path.join(M, "corpus_80.json"), encoding="utf-8"))


def norm(s):
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9 ]+", " ", s)


def sim(a, b):
    x, y = set(norm(a).split()), set(norm(b).split())
    return len(x & y) / max(1, len(x | y))


# 1. Crossref
cache = os.path.join(M, "crossref_80.json")
cr = json.load(open(cache, encoding="utf-8")) if os.path.exists(cache) else {}
for r in corpus:
    if r["id"] in cr and cr[r["id"]].get("doi") == r["doi"]:
        continue
    doi = r["doi"].replace("https://doi.org/", "")
    m = None
    for _ in range(3):
        try:
            g = requests.get("https://api.crossref.org/works/" + requests.utils.quote(doi, safe=""), headers=H, timeout=40)
            if g.status_code == 200:
                m = g.json()["message"]
                break
            if g.status_code == 404:
                break
        except requests.RequestException:
            pass
        time.sleep(2)
    time.sleep(0.25)
    if not m:
        cr[r["id"]] = {"doi": r["doi"], "found": False}
        continue
    dp = (m.get("published-print") or m.get("published-online") or m.get("published") or m.get("issued") or {}).get("date-parts", [[None]])[0]
    cr[r["id"]] = {"doi": r["doi"], "found": True, "title": " ".join((m.get("title") or [""])[0].split()), "year": dp[0],
                   "authors": [{"family": a.get("family") or a.get("name") or "", "given": a.get("given", "")} for a in m.get("author", [])],
                   "container": " ".join((m.get("container-title") or [""])[0].split()), "volume": m.get("volume"), "issue": m.get("issue"),
                   "page": m.get("page") or m.get("article-number"), "type": m.get("type"), "publisher": m.get("publisher")}
json.dump(cr, open(cache, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("crossref encontrados", sum(c.get("found", False) for c in cr.values()), "/", len(cr))
for r in corpus:
    c = cr[r["id"]]
    if not c.get("found"):
        print("NO_CROSSREF", r["id"], r["doi"], r["title"][:70], r["year"])
    else:
        s = sim(c["title"], r["title"])
        if s < 0.8 or (c["year"] and r["year"] and abs(c["year"] - r["year"]) > 0):
            print("REVISAR", r["id"], "sim", round(s, 2), "cat", r["year"], "cr", c["year"], "|", c["title"][:60], "||", r["title"][:60])
        if not c["authors"]:
            print("SIN_AUTORES", r["id"], c["title"][:60])

# 2. Fichas
CUE = re.compile(r"(accuracy|precision|recall|f1|detect\w+ rate|false positive|mttd|mttr|reduc\w+|achiev\w+|results? show|we propose|proposed|cluster|multi-?host|multiple|correlat\w+|limitation)", re.I)
out = []
for r in corpus:
    t = open(os.path.join(B, "markdown", r["id"] + ".md"), encoding="utf-8").read()
    pages = re.split(r"<!-- pagina (\d+) -->", t)
    sents = []
    limit = len(pages)
    for k in range(1, limit, 2):
        n, body = int(pages[k]), re.sub(r"\s+", " ", pages[k + 1])
        if re.search(r"\b(references|referencias|daftar pustaka|bibliography)\b", body, re.I) and n > 3 and n > (limit // 2) * 0.75:
            body = re.split(r"\b(?:references|referencias|daftar pustaka|bibliography)\b", body, flags=re.I)[0]
            sents += [(n, s.strip()) for s in re.split(r"(?<=[.!?])\s+", body)]
            break
        sents += [(n, s.strip()) for s in re.split(r"(?<=[.!?])\s+", body)]
    good = [(n, s) for n, s in sents if 60 < len(s) < 260 and CUE.search(s) and n > 1]
    num = sorted(good, key=lambda x: (bool(re.search(r"\d+(\.\d+)?\s?%", x[1])), bool(re.search(r"wazuh|cluster|multi", x[1], re.I))), reverse=True)[:3]
    ab = " ".join((r.get("abstract") or "").split()[:75])
    a = cr[r["id"]].get("authors") or []
    fam = a[0]["family"] if a else (r["authors"][0].split()[-1] if r["authors"] else "?")
    out.append(f"**{r['id']}** {fam}{' et al.' if len(a) > 2 else ''} ({r['year']}) [{r['categoria']}, {r['pages']}p] {r['title'][:95]}\nR: {ab}\n" +
               "\n".join(f"p{n}: {s}" for n, s in num))
p = os.path.join(M, "fichas_80.md")
open(p, "w", encoding="utf-8").write("\n\n".join(out))
print("fichas", len(out), "palabras", sum(len(x.split()) for x in out))

# 3. Dataset del cluster
root = os.path.join(B, "datasets", "wazuh_cluster_timeliness", "raw")
if not os.path.isdir(root):
    with tarfile.open(os.path.join(B, "datasets", "wazuh_cluster_timeliness", "wazuh-timeliness-dataset.tgz")) as tf:
        tf.extractall(root, filter="data")
exp = os.path.join(root, "zenodo-jcp", "data", "exp1-main-campaign")
ds = sorted(os.listdir(exp))
print("exp1", len(ds), ds[:6])
one = os.path.join(exp, ds[0])
print(os.listdir(one))
print(open(os.path.join(one, [f for f in os.listdir(one) if f.endswith("manager.csv")][0]), encoding="utf-8").readline()[:900])
print(open(os.path.join(one, "latency.csv"), encoding="utf-8").read()[:200])
rd = open(os.path.join(B, "datasets", "wazuh_cluster_timeliness", "README.md"), encoding="utf-8").read()
for m_ in re.finditer(r"(?i)\barms?\b[^\n]{0,220}", rd):
    print("ARM:", m_.group(0)[:230])
