import json, time, sys, requests

OUT = r"D:\ARTICULO_WAZUH\metadata\candidatos.json"
UA = {"User-Agent": "academic-literature-harvester/1.0"}
FIELDS = ("id,doi,title,publication_year,type,authorships,primary_location,"
          "best_oa_location,locations,open_access,cited_by_count,abstract_inverted_index")

# (categoria, consulta, paginas de 200)
QUERIES = [
    ("wazuh", "wazuh", 3),
    ("siem_ml", "SIEM machine learning", 1),
    ("siem_open", "open source SIEM deployment evaluation", 1),
    ("correlacion", "alert correlation multi-step attack", 1),
    ("fatiga", "alert fatigue security operations center", 1),
    ("priorizacion", "security alert prioritization triage machine learning", 1),
    ("hids", "host-based intrusion detection system log analysis", 1),
    ("logs", "log anomaly detection cybersecurity machine learning", 1),
    ("attack", "MITRE ATT&CK detection alerts", 1),
]


def abstract(inv):
    if not inv:
        return ""
    pos = [(i, w) for w, idx in inv.items() for i in idx]
    return " ".join(w for _, w in sorted(pos))


def fetch(q, pages):
    out = []
    for p in range(1, pages + 1):
        params = {
            "filter": f"title_and_abstract.search:{q},is_oa:true,from_publication_date:2018-01-01",
            "per-page": 200, "page": p, "select": FIELDS,
        }
        for attempt in range(4):
            r = requests.get("https://api.openalex.org/works", params=params, headers=UA, timeout=60)
            if r.status_code == 200:
                break
            print("HTTP", r.status_code, r.text[:200], flush=True)
            time.sleep(5 * (attempt + 1))
        else:
            return out
        res = r.json()["results"]
        out += res
        print(q, "pag", p, len(res), "total", r.json()["meta"]["count"], flush=True)
        if len(res) < 200:
            break
        time.sleep(1)
    return out


def pdf_urls(w):
    urls = []
    locs = [w.get("best_oa_location") or {}] + (w.get("locations") or [])
    for l in locs:
        u = l.get("pdf_url")
        if u and u not in urls:
            urls.append(u)
    return urls


seen, rows = {}, []
for cat, q, pages in QUERIES:
    for w in fetch(q, pages):
        if w["id"] in seen:
            continue
        urls = pdf_urls(w)
        if not urls or not w.get("title"):
            continue
        src = ((w.get("primary_location") or {}).get("source") or {})
        row = {
            "openalex": w["id"], "doi": w.get("doi"), "title": w["title"],
            "year": w.get("publication_year"), "type": w.get("type"),
            "authors": [a["author"]["display_name"] for a in w.get("authorships") or []],
            "venue": src.get("display_name"), "venue_type": src.get("type"),
            "issn": src.get("issn_l"), "cited_by": w.get("cited_by_count"),
            "license": (w.get("best_oa_location") or {}).get("license"),
            "abstract": abstract(w.get("abstract_inverted_index")),
            "pdf_urls": urls, "categoria": cat,
        }
        seen[w["id"]] = row
        rows.append(row)

json.dump(rows, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
from collections import Counter
print("candidatos", len(rows), Counter(r["categoria"] for r in rows), Counter(r["type"] for r in rows))
