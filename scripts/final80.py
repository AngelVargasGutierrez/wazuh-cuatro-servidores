import json, os, re, csv, hashlib, shutil, unicodedata, sys, site
from collections import Counter
sys.path.append(site.getusersitepackages())
import fitz

sys.stdout.reconfigure(encoding="utf-8")
B = r"D:\ARTICULO_WAZUH"
M = os.path.join(B, "metadata")
PDFS = os.path.join(B, "pdfs")
OLD = os.path.join(B, "pdfs_retirados")
MD = os.path.join(B, "markdown")
os.makedirs(MD, exist_ok=True)
TMP = r"C:\Users\Angel\AppData\Local\Temp\claude\1b5b5e12a59ef712\ce95a15d-d8ed-448e-8261-a82ff4e60839\scratchpad\update_tmp"
NEW = ["A009", "A012", "A026", "A067"]
DELETE = ["A009_nizam_2026.pdf", "A012_poudel_2026.pdf", "A026_anon_2025.pdf", "A067_ndibe_2025.pdf"]
RESTORE = ["A015", "A027", "A030", "A069", "A072", "A075", "A080"]


def norm(s):
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9 ]+", " ", s)


corpus = json.load(open(os.path.join(M, "corpus_80.json"), encoding="utf-8"))
pos = {r["id"]: n for n, r in enumerate(corpus)}
old = {r["id"]: r for r in json.load(open(os.path.join(M, "retirados_lista_usuario.json"), encoding="utf-8"))}

# 1. validar antes de tocar nada
checked = {}
for i in NEW:
    p = os.path.join(PDFS, f"{i}.pdf")
    d = fitz.open(p)
    head = norm(" ".join(d[k].get_text() for k in range(min(2, d.page_count))))
    toks = [t for t in norm(corpus[pos[i]]["title"]).split() if len(t) > 3]
    score = sum(t in head for t in toks) / len(toks)
    n = len(re.findall("wazuh", " ".join(pg.get_text() for pg in d), re.I))
    pages = d.page_count
    d.close()
    print(i, "coincidencia", round(score, 2), "pag", pages, "wazuh", n, flush=True)
    if score < 0.7 or pages < 4:
        sys.exit(f"ABORTADO: {i} no coincide con su titulo; no se modifico nada")
    checked[i] = (pages, n)
for f in DELETE:
    assert os.path.exists(os.path.join(OLD, f)), f
for i in RESTORE:
    assert os.path.exists(os.path.join(OLD, old[i]["file"])), i

# 2. renombrar los 4 nuevos
for i in NEW:
    r = corpus[pos[i]]
    first = norm((r["authors"] or ["anon"])[0]).split()
    name = f"{i}_{first[-1] if first else 'anon'}_{r['year']}.pdf"
    os.replace(os.path.join(PDFS, f"{i}.pdf"), os.path.join(PDFS, name))
    dst = os.path.join(PDFS, name)
    r.update(file=name, pages=checked[i][0], wazuh_mentions=checked[i][1], pdf_status="ok", pdf_url="aportado por el grupo",
             sha256=hashlib.sha256(open(dst, "rb").read()).hexdigest())

# 3. borrar los 4 reemplazados y devolver los 7
for f in DELETE:
    os.remove(os.path.join(OLD, f))
for i in RESTORE:
    e = dict(old[i])
    e["pdf_status"] = "ok"
    shutil.move(os.path.join(OLD, e["file"]), os.path.join(PDFS, e["file"]))
    corpus[pos[i]] = e

json.dump(corpus, open(os.path.join(M, "corpus_80.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
cols = ["id", "pdf_status", "file", "categoria", "title", "authors", "year", "type", "venue", "venue_type", "issn",
        "doi", "cited_by", "license", "pages", "pdf_url", "sha256"]
with open(os.path.join(M, "corpus_80.csv"), "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, cols, extrasaction="ignore")
    w.writeheader()
    for r in corpus:
        w.writerow({**r, "authors": "; ".join(r["authors"])})
L = ["# Enlaces del corpus", "", "## Datasets",
     "- AIT Alert Data Set: https://zenodo.org/records/8263181",
     "- Wazuh Cyber Range ATT&CK: https://zenodo.org/records/19691904",
     "- Wazuh cluster timeliness: https://zenodo.org/records/22763421", "", "## Articulos"]
for r in corpus:
    L.append(f"{r['id']}. {' '.join(r['title'].split())} ({r['year']}): {r.get('doi') or r['pdf_url']}")
open(os.path.join(B, "ENLACES.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")

# 4. markdown con marcas de pagina
words, empty = 0, []
for r in corpus:
    d = fitz.open(os.path.join(PDFS, r["file"]))
    out = [f"# {r['title']}", "", f"- ID: {r['id']}", f"- Autores: {'; '.join(r['authors'])}", f"- Año: {r['year']}",
           f"- Fuente: {r['venue']}", f"- DOI: {r.get('doi') or ''}", ""]
    for n, pg in enumerate(d, 1):
        out += [f"<!-- pagina {n} -->", pg.get_text().strip(), ""]
    d.close()
    t = "\n".join(out)
    open(os.path.join(MD, f"{r['id']}.md"), "w", encoding="utf-8").write(t)
    w = len(t.split())
    words += w
    if w < 800:
        empty.append((r["id"], w))

disk = {f for f in os.listdir(PDFS) if f.endswith(".pdf")}
print("catalogo", len(corpus), "disco", len(disk), "coinciden", disk == {r["file"] for r in corpus},
      "pendientes", [r["id"] for r in corpus if r.get("pdf_status") != "ok"], "retirados", os.listdir(OLD))
print("markdown", len(os.listdir(MD)), "palabras", words, "poco_texto", empty)
print("sin_doi", [r["id"] for r in corpus if not r.get("doi")], "anios2021+", sum((r["year"] or 0) >= 2021 for r in corpus), Counter(r["type"] for r in corpus))
