import json, re, os, csv, hashlib, unicodedata, tempfile
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import requests, fitz

BASE = r"D:\ARTICULO_WAZUH"
PDFS = os.path.join(BASE, "pdfs")
META = os.path.join(BASE, "metadata")
UA = {"User-Agent": "academic-literature-harvester/1.0", "Accept": "application/pdf,*/*"}
MAX_BYTES = 40 * 1024 * 1024

QUOTAS = {"wazuh": 50, "siem_ml": 8, "correlacion": 6, "fatiga": 5,
          "priorizacion": 3, "hids": 3, "logs": 3, "attack": 2, "siem_open": 0}
TARGET = 80
MAX_PREPRINTS = 12
OK_TYPES = {"article", "conference-paper", "preprint", "review", "book-chapter"}
SEC = re.compile(r"secur|cyber|intrusion|attack|threat|malware|\bsoc\b|\bsiem\b", re.I)
SIEM = re.compile(r"\bsiem\b|security information and event", re.I)


def norm(s):
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9 ]+", " ", s)


def relevant(r):
    txt = r["title"] + " " + r["abstract"]
    if r["type"] not in OK_TYPES or not r["abstract"]:
        return False
    if r["categoria"] == "wazuh":
        return "wazuh" in txt.lower()
    if not SEC.search(txt):
        return False
    if r["categoria"] == "siem_ml" and not SIEM.search(txt):
        return False
    return True


def rank(r):
    peer = r["type"] != "preprint" and r.get("venue_type") in ("journal", "conference")
    return (peer, "wazuh" in r["title"].lower(), min(r["cited_by"] or 0, 200), r["year"] or 0)


def validate(path, r):
    doc = fitz.open(path)
    try:
        if doc.page_count < 4:
            return "pocas_paginas"
        head = norm(" ".join(doc[i].get_text() for i in range(min(2, doc.page_count))))
        if len(head) < 300:
            return "sin_texto"
        toks = [t for t in norm(r["title"]).split() if len(t) > 3]
        if toks and sum(t in head for t in toks) / len(toks) < 0.7:
            return "titulo_no_coincide"
        if r["categoria"] == "wazuh":
            if not any("wazuh" in doc[i].get_text().lower() for i in range(doc.page_count)):
                return "sin_wazuh"
        r["pages"] = doc.page_count
        return None
    finally:
        doc.close()


def attempt(r):
    for url in r["pdf_urls"]:
        tmp = None
        try:
            with requests.get(url, headers=UA, timeout=45, stream=True, allow_redirects=True) as g:
                if g.status_code != 200:
                    r["fail"] = f"http_{g.status_code}"
                    continue
                fd, tmp = tempfile.mkstemp(suffix=".part", dir=META)
                size, first = 0, b""
                with os.fdopen(fd, "wb") as f:
                    for chunk in g.iter_content(65536):
                        if not first:
                            first = chunk[:5]
                        size += len(chunk)
                        if size > MAX_BYTES:
                            break
                        f.write(chunk)
            if size > MAX_BYTES or not first.startswith(b"%PDF"):
                r["fail"] = "no_pdf"
                os.remove(tmp)
                continue
            err = validate(tmp, r)
            if err:
                r["fail"] = err
                os.remove(tmp)
                continue
            r["tmp"], r["pdf_url"] = tmp, url
            r.pop("fail", None)
            return r
        except Exception as e:
            r["fail"] = type(e).__name__
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    return r


rows = json.load(open(os.path.join(META, "candidatos.json"), encoding="utf-8"))
titles, pool = set(), {}
for r in sorted(filter(relevant, rows), key=rank, reverse=True):
    t = norm(r["title"]).strip()
    if t in titles:
        continue
    titles.add(t)
    pool.setdefault(r["categoria"], []).append(r)

selected, failures = [], Counter()
preprints = [0]


def run(cat, need):
    got = 0
    q = pool.get(cat, [])
    while got < need and q:
        batch, q[:] = q[:max(8, int((need - got) * 1.6))], q[max(8, int((need - got) * 1.6)):]
        kept = []
        for r in batch:
            if r["type"] == "preprint":
                if preprints[0] >= MAX_PREPRINTS:
                    continue
                preprints[0] += 1
                r["_counted"] = True
            kept.append(r)
        with ThreadPoolExecutor(8) as ex:
            done = list(ex.map(attempt, kept))
        for r in done:
            if r.get("tmp") and got < need:
                selected.append(r)
                got += 1
            else:
                if r.get("tmp"):
                    os.remove(r["tmp"])
                    r.pop("tmp")
                failures[r.get("fail", "excedente")] += 1
                if r.pop("_counted", False):
                    preprints[0] -= 1
        print(cat, got, "/", need, "total", len(selected), flush=True)
    return got


for cat, n in QUOTAS.items():
    if n:
        run(cat, n)
order = ["wazuh", "correlacion", "siem_ml", "priorizacion", "hids", "attack", "fatiga", "logs", "siem_open"]
for cat in order:
    if len(selected) >= TARGET:
        break
    run(cat, TARGET - len(selected))

selected.sort(key=lambda r: (r["categoria"] != "wazuh", r["categoria"], -(r["year"] or 0)))
for i, r in enumerate(selected, 1):
    first = norm((r["authors"] or ["anon"])[0]).split()
    name = f"A{i:03d}_{first[-1] if first else 'anon'}_{r['year']}.pdf"
    dst = os.path.join(PDFS, name)
    os.replace(r.pop("tmp"), dst)
    r.update(id=f"A{i:03d}", file=name, sha256=hashlib.sha256(open(dst, "rb").read()).hexdigest())
    r.pop("_counted", None)

json.dump(selected, open(os.path.join(META, "corpus_80.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
cols = ["id", "file", "categoria", "title", "authors", "year", "type", "venue", "venue_type", "issn",
        "doi", "cited_by", "license", "pages", "pdf_url", "sha256"]
with open(os.path.join(META, "corpus_80.csv"), "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, cols, extrasaction="ignore")
    w.writeheader()
    for r in selected:
        w.writerow({**r, "authors": "; ".join(r["authors"])})

print("FIN validos", len(selected), Counter(r["categoria"] for r in selected),
      Counter(r["type"] for r in selected), "fallos", failures, flush=True)
