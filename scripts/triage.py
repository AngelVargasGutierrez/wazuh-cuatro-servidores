"""Reconstruye el triaje de los 626 candidatos aplicando la logica registrada en download_pdfs.py."""
import csv, json, os, re, sys, unicodedata
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8")
B = r"D:\ARTICULO_WAZUH"
M = os.path.join(B, "metadata")
QUOTAS = {"wazuh": 50, "siem_ml": 8, "correlacion": 6, "fatiga": 5, "priorizacion": 3, "hids": 3, "logs": 3, "attack": 2, "siem_open": 0}
OK_TYPES = {"article", "conference-paper", "preprint", "review", "book-chapter"}
SEC = re.compile(r"secur|cyber|intrusion|attack|threat|malware|\bsoc\b|\bsiem\b", re.I)
SIEM = re.compile(r"\bsiem\b|security information and event", re.I)
OBSERVED = {"wazuh": [46, 50], "siem_ml": [6, 8], "correlacion": [6], "fatiga": [4, 5], "priorizacion": [3], "hids": [3], "logs": [3], "attack": [2]}


def norm(s):
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9 ]+", " ", s).strip()


def reason(r):
    txt = r["title"] + " " + r["abstract"]
    if r["type"] not in OK_TYPES:
        return "E1", f"Tipo de documento no elegible ({r['type']})"
    if not r["abstract"]:
        return "E2", "Sin resumen disponible"
    if r["categoria"] == "wazuh":
        return (None, None) if "wazuh" in txt.lower() else ("E3", "Wazuh no aparece en título ni resumen")
    if not SEC.search(txt):
        return "E4", "Sin términos de ciberseguridad en título ni resumen"
    if r["categoria"] == "siem_ml" and not SIEM.search(txt):
        return "E5", "Consulta SIEM sin mención explícita de SIEM"
    return None, None


def rank(r):
    peer = r["type"] != "preprint" and r.get("venue_type") in ("journal", "conference")
    return (peer, "wazuh" in r["title"].lower(), min(r["cited_by"] or 0, 200), r["year"] or 0)


cands = json.load(open(os.path.join(M, "candidatos.json"), encoding="utf-8"))
final = json.load(open(os.path.join(M, "corpus_80.json"), encoding="utf-8"))
swap = json.load(open(os.path.join(M, "retirados.json"), encoding="utf-8"))
user_old = json.load(open(os.path.join(M, "retirados_lista_usuario.json"), encoding="utf-8"))
final_t = {norm(r["title"]): r for r in final}
swap_t = {norm(r["title"]) for r in swap}
off_t = {norm(r["title"]) for r in cands if re.search(r"cardiovascular AI: designing|post-war malnutrition|Enabling Responsible, Secure and Sustainable Healthcare", r["title"])}
assert len(off_t) == 3, off_t
group_t = {norm(r["title"]) for r in user_old} - set(final_t)
assert len(group_t) == 5, len(group_t)

status = {}
seen, pool = set(), {}
ordered = sorted(cands, key=rank, reverse=True)
for r in ordered:
    k, why = reason(r)
    t = norm(r["title"])
    if k:
        status[r["openalex"]] = (k, why)
        continue
    if t in seen:
        status[r["openalex"]] = ("E6", "Título duplicado")
        continue
    seen.add(t)
    pool.setdefault(r["categoria"], []).append(r)

attempted = {}
for cat, need0 in QUOTAS.items():
    if not need0:
        continue
    q = list(pool.get(cat, []))
    got = 0
    for obs in OBSERVED[cat]:
        size = max(8, int((need0 - got) * 1.6))
        batch, q = q[:size], q[size:]
        for r in batch:
            attempted[r["openalex"]] = cat
        got = obs
sel0 = final_t.keys() | swap_t | off_t | group_t
SWAP2 = {"A044", "A045", "A041", "A040", "A050", "A013", "A011", "A028", "A024", "A033", "A014", "A070"}
GROUP = {"A009", "A012", "A026", "A065", "A067"}
LATE = {norm(x["title"]) for x in final if x["id"] in SWAP2 | GROUP | {"A053", "A061", "A062"}}
orig = [r for r in cands if r["openalex"] in attempted and norm(r["title"]) in sel0 and norm(r["title"]) not in LATE]
print("intentados", len(attempted), "seleccionados_originales", len(orig))

for cat, rows in pool.items():
    for r in rows:
        if r["openalex"] in attempted:
            status[r["openalex"]] = ("E8", "Descarga intentada: sin PDF válido o excedente de cupo (motivo individual no registrado)")
        else:
            status[r["openalex"]] = ("E7", "Elegible, no intentado por cupo temático")
for r in orig:
    status[r["openalex"]] = ("I0", "Seleccionado en la primera etapa")

rows, tally = [], Counter()
used_final = set()
for n, r in enumerate(cands, 1):
    t = norm(r["title"])
    k, why = status[r["openalex"]]
    fid = ""
    if k == "E6":
        dec = "Excluido"
    elif t in final_t:
        fid = final_t[t]["id"]
        used_final.add(t)
        if fid in GROUP:
            dec, why, k = "Incluido", "Lista del grupo; DOI verificado en Crossref", "I5"
        elif fid in SWAP2:
            dec, why, k = "Incluido", "Búsqueda complementaria dirigida: multiservidor, movimiento lateral y origen de datos", "I4"
        elif k == "I0":
            dec, why = "Incluido", "Cumple criterios; PDF válido"
            k = "I1"
        elif k in ("E7", "E8"):
            dec, why = "Incluido", "Incorporado al revisar el corpus (reemplazo de un documento retirado)"
            k = "I2"
        else:
            dec, why = "Incluido", f"Aportado por la lista del grupo; verificado por DOI ({why})"
            k = "I3"
    elif t in off_t:
        dec, k, why = "Excluido", "E9", "Seleccionado y retirado en revisión manual: ajeno a ciberseguridad"
    elif t in swap_t:
        dec, k, why = "Excluido", "E10", "Seleccionado y retirado: aporte limitado al tema multiservidor"
    elif t in group_t:
        dec, k, why = "Excluido", "E11", "Seleccionado y sustituido por un artículo de la lista del grupo"
    else:
        dec = "Excluido"
    tally[k] += 1
    rows.append({"N": n, "Decisión": dec, "Código": k, "Motivo": why, "ID final": fid, "Título": " ".join(r["title"].split()), "Año": r["year"], "Tipo": r["type"], "Fuente": r.get("venue") or "", "Consulta": r["categoria"], "DOI": r.get("doi") or "", "OpenAlex": r["openalex"]})
extra = [r for r in final if norm(r["title"]) not in used_final]
for r in sorted(extra, key=lambda x: x["id"]):
    k, why = ("I4", "Búsqueda complementaria dirigida: multiservidor, movimiento lateral y origen de datos") if r["id"] in SWAP2 else ("I5", "Lista del grupo; DOI verificado en Crossref")
    assert r["id"] in SWAP2 | GROUP, r["id"]
    tally[k] += 1
    rows.append({"N": len(rows) + 1, "Decisión": "Incluido", "Código": k, "Motivo": why, "ID final": r["id"], "Título": " ".join(r["title"].split()), "Año": r["year"], "Tipo": r["type"], "Fuente": r.get("venue") or "", "Consulta": r["categoria"], "DOI": r.get("doi") or "", "OpenAlex": r.get("openalex") or ""})

inc = sum(1 for r in rows if r["Decisión"] == "Incluido")
print(sorted(tally.items()))
print("filas", len(rows), "incluidos", inc, "ids", len({r["ID final"] for r in rows if r["ID final"]}))
assert inc == 80
assert sum(v for k, v in tally.items() if k not in ("I4", "I5")) + sum(1 for r in rows if r["Código"] in ("I4", "I5") and r["OpenAlex"] and r["N"] <= len(cands)) == len(cands)
out = os.path.join(B, "documento", "Anexo_A_Triaje_de_Candidatos.csv")
with open(out, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, list(rows[0].keys()), delimiter=";")
    w.writeheader(); w.writerows(rows)
json.dump({"tally": tally, "intentados": len(attempted), "orig": len(orig), "pool": sum(len(v) for v in pool.values())}, open(os.path.join(M, "triaje_resumen.json"), "w", encoding="utf-8"), indent=1)
print("pool", sum(len(v) for v in pool.values()))
